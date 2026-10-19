"""Claude Code hook adapter: journal and police Claude Code's own tool calls.

``aileron hook`` is registered as a PreToolUse, PostToolUse and
PostToolUseFailure command hook. Claude Code runs it once before and once
after each tool call, with one JSON payload on stdin. The hook builds a
``tool_call`` event from that payload, runs the policy engine on it, appends
it to the journal under a cross-process lock, and exits 0 or 2. Exit 2 on PreToolUse blocks the call in
every permission mode; exit 1 is a non-blocking error in Claude Code, so it is
never used. Nothing is ever written to stdout: a stray line there would be
read as a JSON decision, and the hook never emits a decision of its own.

Invariants:

- No executed call without a pre record. On PreToolUse the hook exits 0 only
  after its event is on disk. Every other outcome is exit 2.
- Policy sees full content, the file gets digests. ``decide()`` runs on the
  in-memory event with ``tool.arguments`` set to ``tool_input``, on post
  events ``result`` set to ``tool_response``, and on PostToolUseFailure
  ``meta.error`` set to the raw ``error``; ``ChainLog.append`` strips the
  first two and ``run_hook`` replaces the third with its digest just before
  the append, unless ``--capture-content`` is given.
- Parallel hooks cannot fork the chain. Claude Code runs hooks in parallel,
  so ``ChainLog`` construction (which replays the tip) and ``append`` happen
  inside ``chainlog.exclusive_lock``.
- Fail closed. Input that cannot be parsed, rules that cannot be loaded,
  hold nothing or fail while they run, and a journal that cannot be written
  all end in exit 2 with the reason on stderr.

Two events per call: the pre event is the enforcement record (``status`` is
the verdict, ``ok`` or ``blocked``) and the post event is the outcome
(``status`` is ``ok`` or ``error``). They are joined by ``session_id`` and
``meta.hook.tool_use_id``. Both carry ``arguments_digest``, so a sibling
hook's ``updatedInput`` shows up as a digest mismatch.

``run_hook`` never prints and never raises for an expected failure; the CLI
does all printing, so every path is testable without capturing output.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from .chainlog import ChainLog, exclusive_lock
from .events import digest, new_event
from .policy import Rule, decide, load_rules

TRANSPORT = "claude-code-hook"
MAX_INPUT_BYTES = 16 * 1024 * 1024
SUPPORTED_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
DEFAULT_AGENT_NAME = "claude-code"
DEFAULT_FRAMEWORK = "claude-code"
LOCK_TIMEOUT_S = 10.0
# Synthetic rule id recorded when the rules path cannot be loaded, next to
# the proxy's aileron-pending-limit.
RULE_CONFIG_REJECTED = "aileron-hook-config"
BLOCK_EXIT = 2
TOOL_NAME_MAX_CHARS = 256
# Same bound as cli.IDENTITY_MAX_CHARS, applied to the payload's session_id.
IDENTITY_MAX_CHARS = 128
# Deepest container nesting accepted anywhere in the payload. Whether a
# deeper document raises RecursionError in json.loads depends on the Python
# version, and canonical_json must be able to serialize everything that gets
# this far, so the bound is explicit and checked without recursion.
MAX_NESTING = 256
# meta is never stripped by capture_content, so nothing uncapped may enter it.
_META_CAPS = {"tool_use_id": 128, "cwd": 1024, "permission_mode": 32, "agent_id": 128, "agent_type": 128}
_MCP_CAPS = {"name": 256, "source": 32}


class HookInputError(ValueError):
    """The stdin payload was refused; the message is the one-line reason."""


@dataclass(frozen=True)
class HookOptions:
    """What the CLI resolved from flags and environment."""

    log_path: str
    rules_path: str | None
    capture_content: bool
    agent_name: str
    framework: str


@dataclass(frozen=True)
class HookOutcome:
    """What the CLI should do: exit with ``exit_code`` after printing ``message`` to stderr.

    ``exit_code`` is 0 or 2; ``message`` is empty exactly when ``exit_code`` is
    0; ``event`` is the stored event when one was appended.
    """

    exit_code: int
    message: str
    event: dict | None


def one_line(value: Any) -> str:
    """Collapse any text or exception to one whitespace-normalized line."""
    return " ".join(str(value).split())


def _reject_constant(token: str) -> Any:
    """json.loads hook: NaN and Infinity are not JSON and cannot be canonicalized."""
    raise HookInputError(f"non-JSON constant {token!r}")


def _finite_float(text: str) -> float:
    """json.loads hook: a literal such as 1e999 parses to inf, which canonical_json rejects."""
    value = float(text)
    if not math.isfinite(value):
        raise HookInputError(f"non-finite number {text[:64]!r}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """json.loads hook: two parsers disagreeing about which ``command`` ran is the 0.1.2 bug class."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise HookInputError(f"duplicate key {key[:64]!r}")
        seen.add(key)
    return dict(pairs)


def _too_deep(obj: Any, limit: int) -> bool:
    """True when containers nest more than ``limit`` levels; walks without recursion."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def _is_identity(value: Any) -> bool:
    """The CLI's identity rule: 1 to 128 printable characters, no surrounding whitespace."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= IDENTITY_MAX_CHARS
        and value == value.strip()
        and value.isprintable()
    )


def parse_payload(raw: bytes) -> dict:
    """Decode and check one hook payload, or raise HookInputError with the reason.

    Checks run in order: size, emptiness, UTF-8, JSON (no NaN or Infinity, no
    non-finite numbers, no duplicate keys, bounded nesting), object at the top
    level, then the fields the hook needs: ``hook_event_name``, ``session_id``,
    ``tool_name`` and the presence of ``tool_input``. Everything else is
    optional and handled by ``build_event``.
    """
    if len(raw) > MAX_INPUT_BYTES:
        raise HookInputError(f"input larger than {MAX_INPUT_BYTES} bytes")
    if not raw:
        raise HookInputError("empty stdin")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HookInputError("not UTF-8") from None
    try:
        payload = json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except HookInputError:
        raise
    except RecursionError:
        raise HookInputError("nesting too deep") from None
    except ValueError as exc:
        raise HookInputError(f"not JSON ({one_line(exc)})") from None
    if _too_deep(payload, MAX_NESTING):
        raise HookInputError("nesting too deep")
    if not isinstance(payload, dict):
        raise HookInputError("top level is not a JSON object")

    event_name = payload.get("hook_event_name")
    if not isinstance(event_name, str):
        raise HookInputError("hook_event_name missing or not a string")
    if event_name not in SUPPORTED_EVENTS:
        raise HookInputError(
            f"hook_event_name {event_name[:64]!r} is not one of {', '.join(SUPPORTED_EVENTS)}"
        )
    if not _is_identity(payload.get("session_id")):
        raise HookInputError(
            f"session_id must be 1 to {IDENTITY_MAX_CHARS} printable characters "
            "with no leading or trailing whitespace"
        )
    tool_name = payload.get("tool_name")
    if (
        not isinstance(tool_name, str)
        or not tool_name
        or len(tool_name) > TOOL_NAME_MAX_CHARS
        or not tool_name.isprintable()
    ):
        raise HookInputError(f"tool_name must be 1 to {TOOL_NAME_MAX_CHARS} printable characters")
    if "tool_input" not in payload:
        raise HookInputError("tool_input is missing")
    return payload


def _capped_str(value: Any, cap: int) -> bool:
    return isinstance(value, str) and len(value) <= cap


def _hook_meta(payload: dict) -> tuple[dict, list[str]]:
    """The ``meta.hook`` block and the names of payload fields it left out.

    ``event`` and ``tool_use_id`` are always present. The optional fields are
    copied only when they have the expected type and fit their cap; a field
    that is present but does not is named in ``dropped`` rather than refused,
    because none of them is an enforcement input.
    """
    meta: dict[str, Any] = {"event": payload["hook_event_name"]}
    dropped: list[str] = []
    tool_use_id = payload.get("tool_use_id")
    if _capped_str(tool_use_id, _META_CAPS["tool_use_id"]):
        meta["tool_use_id"] = tool_use_id
    else:
        meta["tool_use_id"] = None
        dropped.append("tool_use_id")
    for key in ("cwd", "permission_mode", "agent_id", "agent_type"):
        if key not in payload:
            continue
        if _capped_str(payload[key], _META_CAPS[key]):
            meta[key] = payload[key]
        else:
            dropped.append(key)
    if "mcp_server" in payload:
        server = payload["mcp_server"]
        if isinstance(server, dict) and all(_capped_str(server.get(k), cap) for k, cap in _MCP_CAPS.items()):
            meta["mcp_server"] = {k: server[k] for k in _MCP_CAPS}
        else:
            dropped.append("mcp_server")
    if payload["hook_event_name"] == "PostToolUseFailure" and "is_interrupt" in payload:
        if isinstance(payload["is_interrupt"], bool):
            meta["is_interrupt"] = payload["is_interrupt"]
        else:
            dropped.append("is_interrupt")
    return meta, dropped


def _latency(value: Any) -> int | float | None:
    """``duration_ms`` as ``latency_ms``: a finite, non-negative number or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if not math.isfinite(value) or value < 0:
            return None
    except OverflowError:
        # An int too large to convert to a float; no tool ran that long.
        return None
    return value


def build_event(payload: dict, options: HookOptions) -> dict:
    """The in-memory ``tool_call`` event for a parsed payload.

    ``tool.arguments`` holds the full ``tool_input``, on PostToolUse
    ``result`` holds the full ``tool_response`` and on PostToolUseFailure
    ``meta.error`` holds the raw ``error`` value, so rules see content.
    ``ChainLog.append`` strips the first two unless content capture is on;
    ``run_hook`` swaps the error for its digest before appending, because
    ``append`` never touches ``meta``. The digests are passed explicitly so a
    null input or response still gets one.
    """
    event_name = payload["hook_event_name"]
    tool_input = payload["tool_input"]
    hook_meta, dropped = _hook_meta(payload)
    meta: dict[str, Any] = {"transport": TRANSPORT, "hook": hook_meta}
    fields: dict[str, Any] = {
        "tool": {"name": payload["tool_name"], "arguments": tool_input, "arguments_digest": digest(tool_input)},
        "meta": meta,
    }
    if event_name == "PostToolUse":
        if "tool_response" in payload:
            fields["result"] = payload["tool_response"]
            fields["result_digest"] = digest(payload["tool_response"])
        else:
            dropped.append("tool_response")
        fields["latency_ms"] = _latency(payload.get("duration_ms"))
    elif event_name == "PostToolUseFailure":
        if "error" not in payload:
            dropped.append("error")
        meta["error"] = payload.get("error")
        fields["status"] = "error"
        fields["latency_ms"] = _latency(payload.get("duration_ms"))
    if dropped:
        hook_meta["dropped"] = dropped
    return new_event("tool_call", payload["session_id"], options.agent_name, options.framework, **fields)


def _title_for(rules: list[Rule] | None, rule_id: str) -> str:
    for rule in rules or []:
        if rule.id == rule_id:
            return one_line(rule.title)
    return ""


def _journal_message(options: HookOptions, pre: bool, tool_name: str, exc: BaseException) -> str:
    cause = f"{type(exc).__name__}: {one_line(exc)}"
    if pre:
        return (f"aileron: journal {options.log_path} could not be written ({cause}); "
                f"refusing to let {tool_name} run unrecorded")
    return (f"aileron: journal {options.log_path} could not be written ({cause}); "
            f"{tool_name} already ran and is not recorded, fix the journal before continuing")


def run_hook(raw: bytes, options: HookOptions) -> HookOutcome:
    """Journal and police one hook payload; never prints, never raises for an expected failure.

    Order: parse, load rules, build the event, decide in memory, append under
    the lock, then report. The append happens before the verdict is returned,
    so a blocked call is in the journal before Claude Code hears about it.

    Any failure of the rules configuration is journaled under
    ``aileron-hook-config`` with exit 2: a path that cannot be loaded, a path
    that yields no rules (``--rules`` is a request for enforcement, so an
    empty directory is a mistake, not a pass), and a rule that raises while
    it is evaluated.
    """
    try:
        payload = parse_payload(raw)
    except HookInputError as exc:
        return HookOutcome(BLOCK_EXIT, f"aileron: hook input rejected ({one_line(exc)}); refusing to continue", None)
    pre = payload["hook_event_name"] == "PreToolUse"
    tool_name = payload["tool_name"]

    rules: list[Rule] | None = None
    rules_error: str | None = None
    if options.rules_path is not None:
        try:
            rules = load_rules(options.rules_path)
        except Exception as exc:
            rules_error = one_line(exc)
        else:
            if not rules:
                rules_error = "no rules found"

    event = build_event(payload, options)
    if rules:
        try:
            decision = decide(event, rules)
        except Exception as exc:
            rules_error = f"rule evaluation failed: {type(exc).__name__}: {one_line(exc)}"
        else:
            if decision.action == "block":
                event["policy"] = {"rule_id": decision.rule_ids[0], "action": "block"}
                if pre:
                    event["status"] = "blocked"
            elif decision.action == "alert":
                event["policy"] = {"rule_id": decision.rule_ids[0], "action": "alert"}
    if rules_error is not None:
        event["policy"] = {"rule_id": RULE_CONFIG_REJECTED, "action": "block"}
        if pre:
            event["status"] = "blocked"
    # Policy has seen the raw error; the file gets its digest (ChainLog.append
    # strips arguments and result but never meta).
    if not options.capture_content and "error" in event["meta"]:
        event["meta"]["error"] = {"digest": digest(event["meta"]["error"])}

    try:
        with exclusive_lock(options.log_path, LOCK_TIMEOUT_S):
            stored = ChainLog(options.log_path, capture_content=options.capture_content).append(event)
    except Exception as exc:
        return HookOutcome(BLOCK_EXIT, _journal_message(options, pre, tool_name, exc), None)

    where = f"recorded as seq {stored['seq']} in {options.log_path}"
    if rules_error is not None:
        head = f"aileron: rules {options.rules_path} could not be loaded ({rules_error})"
        if pre:
            return HookOutcome(BLOCK_EXIT, f"{head}; refusing to let {tool_name} run unpoliced; {where}", stored)
        return HookOutcome(BLOCK_EXIT, f"{head}; {tool_name} already ran unpoliced; {where}", stored)
    policy = event.get("policy")
    if policy is not None and policy["action"] == "block":
        rule_id = policy["rule_id"]
        title = _title_for(rules, rule_id)
        if pre:
            return HookOutcome(BLOCK_EXIT, f"blocked by aileron rule {rule_id} ({title}); {where}", stored)
        return HookOutcome(
            BLOCK_EXIT,
            f"aileron: {tool_name} already ran but matches block rule {rule_id} ({title}); "
            f"the PreToolUse hook did not stop it; {where}",
            stored,
        )
    return HookOutcome(0, "", stored)
