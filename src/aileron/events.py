"""Aileron event schema: canonical JSON, hashing, and validation."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

EVENT_TYPES = {
    "tool_call",
    "llm_call",
    "agent_start",
    "agent_end",
    "policy_decision",
    "alert",
}

STATUSES = {"ok", "error", "blocked"}

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

EVENT_KEYS = {
    "id",
    "ts",
    "seq",
    "session_id",
    "agent",
    "type",
    "tool",
    "result",
    "result_digest",
    "status",
    "latency_ms",
    "policy",
    "meta",
    "prev_hash",
    "hash",
}


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, tight separators, ASCII-escaped.

    This is the single serializer the hash chain and signatures depend on;
    chainlog, policy, and signing all route through it so no copy can drift.

    ``ensure_ascii=True`` keeps the output pure ASCII, so lone surrogates and
    other non-encodable text become ``\\uXXXX`` escapes instead of raising at
    hash time (a peer-supplied surrogate must never be able to crash the
    integrity check). ``allow_nan=False`` rejects NaN/Infinity, which are not
    valid JSON and would otherwise be written into the journal.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(obj: Any) -> str:
    """Return the sha256 hex digest of the canonical JSON serialization of ``obj``."""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def canonical(event: dict) -> str:
    """Return the canonical JSON of ``event`` with the ``hash`` field removed."""
    return canonical_json({k: v for k, v in event.items() if k != "hash"})


def event_hash(event: dict) -> str:
    """Return the sha256 hex digest of ``canonical(event)``."""
    return hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()


def new_event(
    type: str,
    session_id: str,
    agent_name: str,
    framework: str,
    **fields: Any,
) -> dict:
    """Create a new event dict with all schema keys populated.

    Fills id (uuid4 hex), ts (RFC3339 UTC 'Z'), seq=0, status='ok',
    latency_ms=None, meta={}, and '0'*64 placeholders for prev_hash/hash.
    Any key may be overridden via ``**fields``. If a tool dict with arguments
    but no arguments_digest is given, the digest is computed automatically;
    likewise ``result_digest`` is derived from ``result`` when absent.
    """
    event: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "seq": 0,
        "session_id": session_id,
        "agent": {"name": agent_name, "framework": framework, "version": None},
        "type": type,
        "tool": None,
        "result": None,
        "result_digest": None,
        "status": "ok",
        "latency_ms": None,
        "policy": None,
        "meta": {},
        "prev_hash": "0" * 64,
        "hash": "0" * 64,
    }
    event.update(fields)
    # Normalize nested dict overrides (e.g. agent={"version": "1.0"}).
    if isinstance(fields.get("agent"), dict):
        agent = {"name": agent_name, "framework": framework, "version": None}
        agent.update(fields["agent"])
        event["agent"] = agent
    # Auto-fill content digests when content is present but digest is missing.
    tool = event.get("tool")
    if isinstance(tool, dict):
        if tool.get("arguments") is not None and not tool.get("arguments_digest"):
            tool["arguments_digest"] = digest(tool["arguments"])
        tool.setdefault("arguments", None)
        tool.setdefault("arguments_digest", None)
    if event.get("result") is not None and not event.get("result_digest"):
        event["result_digest"] = digest(event["result"])
    return event


# Field checks, one small function each.
#
# This used to be a single ninety-line run of if-statements, which made it hard
# to see that every field is really the same shape of question: given this
# value, what is wrong with it. Each check below is a pure function from a value
# to a list of complaints, and `_FIELD_CHECKS` lists them in the order their
# errors are reported. Adding a field is adding one entry, and the order of the
# output is visible in one place rather than implied by control flow.


def _hex_string(value: Any, length: int) -> bool:
    """True when value is a lowercase hex string of exactly ``length``."""
    return isinstance(value, str) and bool(re.fullmatch(f"[0-9a-f]{{{length}}}", value))


def _one_of(allowed: set, label: str):
    """Value must be a member of ``allowed``.

    The try/except is not decoration. A hostile or corrupt journal can carry a
    list or dict here, and ``x in some_set`` raises TypeError on an unhashable
    value. validate() promises a list of problems, so it has to answer
    "that is not one of the allowed values" rather than terminating by exception.
    """
    def check(value: Any) -> list[str]:
        try:
            ok = value in allowed
        except TypeError:
            ok = False
        return [] if ok else [f"{label} must be one of {sorted(allowed)}"]
    return check


def _check_id(value: Any) -> list[str]:
    if _hex_string(value, 32):
        return []
    return ["id must be a 32-char lowercase hex string (uuid4 hex)"]


def _check_ts(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.endswith("Z"):
        return ["ts must be an RFC3339 UTC string ending in 'Z'"]
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ["ts is not a valid RFC3339 timestamp"]
    return []


def _check_seq(value: Any) -> list[str]:
    if not isinstance(value, int) or isinstance(value, bool):
        return ["seq must be an int"]
    if value < 0:
        return ["seq must be >= 0"]
    return []


def _check_session_id(value: Any) -> list[str]:
    return [] if isinstance(value, str) else ["session_id must be a string"]


def _check_agent(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["agent must be a dict"]
    return [f"agent missing key: {key}"
            for key in ("name", "framework", "version") if key not in value]


def _check_latency(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ["latency_ms must be a number or None"]
    return []


def _check_tool(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["tool must be a dict or None"]
    errors = []
    if "name" not in value:
        errors.append("tool missing key: name")
    elif not isinstance(value["name"], str):
        errors.append("tool.name must be a string")
    arguments_digest = value.get("arguments_digest")
    if arguments_digest is not None and not _HASH_RE.match(str(arguments_digest)):
        errors.append("tool.arguments_digest must be a sha256 hex string")
    return errors


def _check_result_digest(value: Any) -> list[str]:
    if value is None or _HASH_RE.match(str(value)):
        return []
    return ["result_digest must be a sha256 hex string or None"]


def _check_policy(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["policy must be a dict or None"]
    return [f"policy missing key: {key}"
            for key in ("rule_id", "action") if key not in value]


def _check_meta(value: Any) -> list[str]:
    return [] if isinstance(value, dict) else ["meta must be a dict"]


def _chain_hash(label: str):
    """prev_hash and hash are the chain links; both are plain sha256 hex."""
    def check(value: Any) -> list[str]:
        if _hex_string(value, 64):
            return []
        return [f"{label} must be a 64-char lowercase hex string"]
    return check


# Order matters only because it is the order errors come back in, which some
# callers print. Keeping it explicit here is the point.
_FIELD_CHECKS: tuple[tuple[str, Any], ...] = (
    ("id", _check_id),
    ("ts", _check_ts),
    ("seq", _check_seq),
    ("session_id", _check_session_id),
    ("agent", _check_agent),
    ("type", _one_of(EVENT_TYPES, "type")),
    ("status", _one_of(STATUSES, "status")),
    ("latency_ms", _check_latency),
    ("tool", _check_tool),
    ("result_digest", _check_result_digest),
    ("policy", _check_policy),
    ("meta", _check_meta),
    ("prev_hash", _chain_hash("prev_hash")),
    ("hash", _chain_hash("hash")),
)


def validate(event: dict) -> list[str]:
    """Return a list of schema error strings for ``event``; ``[]`` if valid.

    Never raises. Events reach this function from journals, which can be
    corrupt or hostile, so every malformed value has to come back as a
    complaint rather than an exception.
    """
    if not isinstance(event, dict):
        return ["event is not a dict"]

    missing = [f"missing key: {key}" for key in sorted(EVENT_KEYS - set(event))]
    present = [error
               for key, check in _FIELD_CHECKS if key in event
               for error in check(event[key])]
    return missing + present
