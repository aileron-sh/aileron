"""Tests for aileron.hook: the Claude Code PreToolUse / PostToolUse / PostToolUseFailure command hook.

The hook's contract is small and every test here checks a piece of it: exit 0
or 2 and never 1, nothing on stdout, a message on stderr if and only if the
exit code is 2, a pre record on disk before a call is released, policy run on
full content while the file holds digests, and a chain that survives parallel
hook processes.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron import events, hook
from aileron.chainlog import ChainLog, exclusive_lock, verify
from aileron.cli import main
from aileron.events import digest
from aileron.hook import (
    DEFAULT_AGENT_NAME,
    DEFAULT_FRAMEWORK,
    HookInputError,
    HookOptions,
    build_event,
    parse_payload,
    run_hook,
)

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "claude-code.md"
SESSION = "00893aaf-19fa-41d2-8238-13269b9b3ca0"
HOOK_ENV = ("AILERON_AGENT", "AILERON_FRAMEWORK", "AILERON_SESSION_ID", "AILERON_LOG")

# Sentinels for _payload: OMIT removes a key, _DEFAULT keeps the helper's value.
OMIT = object()
_DEFAULT = object()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """The developer's shell must not leak an identity or a journal path into these tests."""
    for name in HOOK_ENV:
        monkeypatch.delenv(name, raising=False)


# ----------------------------------------------------------------- helpers


def _payload(event="PreToolUse", tool="Bash", tool_input=_DEFAULT, **extra) -> bytes:
    """One Claude Code hook payload as bytes. ``key=OMIT`` removes a key."""
    body: dict = {
        "session_id": SESSION,
        "transcript_path": "/home/me/.claude/projects/t.jsonl",
        "cwd": "/home/me/my-project",
        "permission_mode": "default",
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": {"command": "ls -la"},
        "tool_use_id": "toolu_01ABC123",
    }
    if event == "PostToolUse":
        body.update(tool_response={"stdout": "ok", "stderr": ""}, duration_ms=12)
    elif event == "PostToolUseFailure":
        body.update(error="command exited 1", is_interrupt=False, duration_ms=2301)
    overrides = {"tool_name": tool, **extra}
    if tool_input is not _DEFAULT:
        overrides["tool_input"] = tool_input
    for key, value in overrides.items():
        if value is OMIT:
            body.pop(key, None)
        else:
            body[key] = value
    return json.dumps(body).encode("utf-8")


def _with_input(raw_json: bytes) -> bytes:
    """The default payload with ``tool_input`` replaced by literal JSON bytes."""
    marker = b'"tool_input": {"command": "ls -la"}'
    base = _payload()
    assert marker in base
    return base.replace(marker, b'"tool_input": ' + raw_json)


def _log(tmp_path) -> str:
    return str(tmp_path / "hook.chain.jsonl")


def _options(tmp_path, rules=None, capture=False, **identity) -> HookOptions:
    return HookOptions(
        log_path=_log(tmp_path),
        rules_path=rules,
        capture_content=capture,
        agent_name=identity.get("agent_name", DEFAULT_AGENT_NAME),
        framework=identity.get("framework", DEFAULT_FRAMEWORK),
    )


def _run(tmp_path, raw, rules=None, capture=False, **identity):
    return run_hook(raw, _options(tmp_path, rules, capture, **identity))


def _rules(tmp_path, text, name="rule.yml") -> str:
    """Write one rule file under tmp_path/rules and return its path."""
    path = tmp_path / "rules" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def _main(monkeypatch, raw, argv) -> int:
    """Run ``aileron hook`` through main() with ``raw`` on stdin."""
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
    return main(["hook", *argv])


def _stored(tmp_path) -> list[dict]:
    return ChainLog.read(_log(tmp_path))


RM_RULE = """\
id: local-001
title: Block destructive shell commands from Claude Code
severity: high
match:
  type: tool_call
  tool.name_regex: '^(Bash|PowerShell)$'
  tool.arguments_contains:
    - "rm -rf"
    - "rm -fr"
action: block
"""

ALERT_RULE = """\
id: local-002
title: Alert on edits to the hook configuration
severity: medium
match:
  type: tool_call
  tool.arguments_contains:
    - ".claude/settings.json"
action: alert
"""

BROKEN_RULE = "id: [unclosed\n"


# --------------------------------------------------------------- recording


def test_pre_allowed_is_recorded(tmp_path):
    tool_input = {"file_path": "/home/me/my-project/README.md"}
    out = _run(tmp_path, _payload(tool="Read", tool_input=tool_input))
    assert (out.exit_code, out.message) == (0, "")
    (stored,) = _stored(tmp_path)
    assert stored == out.event
    assert stored["type"] == "tool_call"
    assert stored["tool"]["name"] == "Read"
    assert stored["tool"]["arguments_digest"] == digest(tool_input)
    assert stored["status"] == "ok"
    assert stored["policy"] is None
    assert stored["latency_ms"] is None
    assert stored["meta"]["transport"] == "claude-code-hook"
    assert stored["meta"]["hook"]["event"] == "PreToolUse"
    assert stored["meta"]["hook"]["tool_use_id"] == "toolu_01ABC123"
    assert stored["meta"]["hook"]["cwd"] == "/home/me/my-project"
    assert stored["meta"]["hook"]["permission_mode"] == "default"
    assert stored["session_id"] == SESSION
    # transcript_path points into the user's home directory and is never recorded.
    assert "transcript_path" not in json.dumps(stored)
    assert events.validate(stored) == []
    assert verify(_log(tmp_path)).ok


def test_pre_digest_only_by_default(tmp_path):
    tool_input = {"command": "cat /etc/hosts"}
    out = _run(tmp_path, _payload(tool_input=tool_input))
    assert out.event["tool"]["arguments"] is None
    assert out.event["tool"]["arguments_digest"] == digest(tool_input)
    (on_disk,) = _stored(tmp_path)
    assert on_disk["tool"]["arguments"] is None
    assert "/etc/hosts" not in Path(_log(tmp_path)).read_text(encoding="utf-8")


def test_capture_content_stores_content(tmp_path):
    tool_input = {"command": "cat /etc/hosts"}
    pre = _run(tmp_path, _payload(tool_input=tool_input), capture=True)
    post = _run(tmp_path, _payload("PostToolUse", tool_input=tool_input, tool_response={"stdout": "127.0.0.1"}),
                capture=True)
    fail = _run(tmp_path, _payload("PostToolUseFailure", tool_input=tool_input, error={"message": "boom"}),
                capture=True)
    assert pre.event["tool"]["arguments"] == tool_input
    assert post.event["result"] == {"stdout": "127.0.0.1"}
    assert post.event["result_digest"] == digest({"stdout": "127.0.0.1"})
    assert fail.event["meta"]["error"] == {"message": "boom"}
    on_disk = _stored(tmp_path)
    assert on_disk == [pre.event, post.event, fail.event]
    assert all(events.validate(e) == [] for e in on_disk)
    assert verify(_log(tmp_path)).ok


def test_post_records_result_digest_latency_status(tmp_path):
    response = {"stdout": "total 0\n", "stderr": "", "interrupted": False}
    out = _run(tmp_path, _payload("PostToolUse", tool_response=response, duration_ms=12))
    assert (out.exit_code, out.message) == (0, "")
    assert out.event["status"] == "ok"
    assert out.event["result"] is None
    assert out.event["result_digest"] == digest(response)
    assert out.event["latency_ms"] == 12
    assert out.event["meta"]["hook"]["event"] == "PostToolUse"
    assert "total 0" not in Path(_log(tmp_path)).read_text(encoding="utf-8")
    assert events.validate(out.event) == []


def test_pre_post_join_and_rewrite_detection(tmp_path):
    tool_input = {"command": "ls"}
    pre = _run(tmp_path, _payload(tool_input=tool_input, tool_use_id="toolu_01X"))
    post = _run(tmp_path, _payload("PostToolUse", tool_input=tool_input, tool_use_id="toolu_01X"))
    assert pre.event["session_id"] == post.event["session_id"] == SESSION
    assert pre.event["meta"]["hook"]["tool_use_id"] == post.event["meta"]["hook"]["tool_use_id"] == "toolu_01X"
    assert pre.event["tool"]["arguments_digest"] == post.event["tool"]["arguments_digest"]
    assert (pre.event["status"], post.event["status"]) == ("ok", "ok")
    # A sibling hook's updatedInput changed what ran: the post digest no longer matches.
    pre2 = _run(tmp_path, _payload(tool_input=tool_input, tool_use_id="toolu_01Y"))
    post2 = _run(tmp_path, _payload("PostToolUse", tool_input={"command": "ls -la /"}, tool_use_id="toolu_01Y"))
    assert pre2.event["tool"]["arguments_digest"] != post2.event["tool"]["arguments_digest"]
    assert [e["seq"] for e in _stored(tmp_path)] == [1, 2, 3, 4]
    assert verify(_log(tmp_path)).ok


def test_post_failure_recorded(tmp_path):
    out = _run(tmp_path, _payload("PostToolUseFailure", error="command exited 1", is_interrupt=True,
                                   duration_ms=2301))
    assert (out.exit_code, out.message) == (0, "")
    assert out.event["status"] == "error"
    assert out.event["meta"]["error"] == {"digest": digest("command exited 1")}
    assert out.event["meta"]["hook"]["is_interrupt"] is True
    assert out.event["meta"]["hook"]["event"] == "PostToolUseFailure"
    assert out.event["result"] is None
    assert out.event["result_digest"] is None
    assert out.event["latency_ms"] == 2301
    assert "command exited 1" not in Path(_log(tmp_path)).read_text(encoding="utf-8")
    assert events.validate(out.event) == []


def test_post_missing_optional_fields_recorded(tmp_path):
    post = _run(tmp_path, _payload("PostToolUse", tool_response=OMIT, duration_ms=OMIT))
    fail = _run(tmp_path, _payload("PostToolUseFailure", error=OMIT, is_interrupt=OMIT, duration_ms=OMIT))
    assert (post.exit_code, fail.exit_code) == (0, 0)
    assert post.event["result_digest"] is None
    assert post.event["latency_ms"] is None
    assert post.event["meta"]["hook"]["dropped"] == ["tool_response"]
    assert fail.event["status"] == "error"
    assert fail.event["meta"]["error"] == {"digest": digest(None)}
    assert fail.event["latency_ms"] is None
    assert "is_interrupt" not in fail.event["meta"]["hook"]
    assert fail.event["meta"]["hook"]["dropped"] == ["error"]
    assert all(events.validate(e) == [] for e in (post.event, fail.event))
    assert verify(_log(tmp_path)).ok


def test_bad_duration_ms_becomes_null(tmp_path):
    # 10**400 is a finite int that math.isfinite cannot even convert to a float.
    for bad in (True, "12", -1, 10**400):
        out = _run(tmp_path, _payload("PostToolUse", duration_ms=bad))
        assert out.exit_code == 0, bad
        assert out.event["latency_ms"] is None, bad
    # A non-finite number such as 1e999 is refused at parse time (see
    # test_nan_refused_before_canonical_json), so it can only reach build_event
    # directly; the event must still come out valid.
    payload = json.loads(_payload("PostToolUse"))
    for bad in (float("inf"), float("nan")):
        payload["duration_ms"] = bad
        event = build_event(payload, _options(tmp_path))
        assert event["latency_ms"] is None
        assert events.validate(event) == []


def test_meta_hook_only_carries_present_keys(tmp_path):
    plain = _run(tmp_path, _payload())
    sub = _run(tmp_path, _payload("PostToolUse", tool="mcp__filesystem__read_file", agent_id="agent_7Hq2",
                                   agent_type="Explore", permission_mode="acceptEdits",
                                   mcp_server={"name": "filesystem", "source": "project"}))
    assert set(plain.event["meta"]["hook"]) == {"event", "tool_use_id", "cwd", "permission_mode"}
    sub_hook = sub.event["meta"]["hook"]
    assert sub_hook["agent_id"] == "agent_7Hq2"
    assert sub_hook["agent_type"] == "Explore"
    assert sub_hook["mcp_server"] == {"name": "filesystem", "source": "project"}
    assert sub_hook["permission_mode"] == "acceptEdits"
    assert "dropped" not in sub_hook
    assert set(sub.event["meta"]) == {"transport", "hook"}


def test_oversized_meta_fields_dropped_not_refused(tmp_path):
    out = _run(tmp_path, _payload(cwd="/x" * 1000, permission_mode=7, agent_type="E" * 129,
                                   mcp_server={"name": "fs", "source": ["project"]}))
    assert (out.exit_code, out.message) == (0, "")
    hook_meta = out.event["meta"]["hook"]
    for key in ("cwd", "permission_mode", "agent_type", "mcp_server"):
        assert key not in hook_meta
    assert hook_meta["dropped"] == ["cwd", "permission_mode", "agent_type", "mcp_server"]
    # meta is never stripped by capture_content, so the 2000-char path must not be on disk.
    assert "/x/x/x" not in Path(_log(tmp_path)).read_text(encoding="utf-8")
    fail = _run(tmp_path, _payload("PostToolUseFailure", is_interrupt="yes"))
    assert fail.exit_code == 0
    assert "is_interrupt" not in fail.event["meta"]["hook"]
    assert fail.event["meta"]["hook"]["dropped"] == ["is_interrupt"]
    assert all(events.validate(e) == [] for e in _stored(tmp_path))


def test_missing_tool_use_id_recorded_as_null(tmp_path):
    missing = _run(tmp_path, _payload(tool_use_id=OMIT))
    too_long = _run(tmp_path, _payload(tool_use_id="t" * 129))
    for out in (missing, too_long):
        assert out.exit_code == 0
        assert out.event["meta"]["hook"]["tool_use_id"] is None
        assert out.event["meta"]["hook"]["dropped"] == ["tool_use_id"]


def test_non_object_tool_input_recorded_and_matched(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    for value in ([1, 2], 3, None, "ls"):
        out = _run(tmp_path, _payload(tool_input=value), rules=rules)
        assert out.exit_code == 0, value
        assert out.event["tool"]["arguments_digest"] == digest(value)
    blocked = _run(tmp_path, _payload(tool_input="rm -rf /tmp/x"), rules=rules)
    assert blocked.exit_code == 2
    assert blocked.event["status"] == "blocked"
    assert blocked.event["tool"]["arguments_digest"] == digest("rm -rf /tmp/x")
    assert verify(_log(tmp_path)).ok


def test_large_input_rule_fires_at_tail(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    command = "echo " + "x" * (8 * 1024 * 1024) + " && rm -rf /tmp/x"
    out = _run(tmp_path, _payload(tool_input={"command": command}), rules=rules)
    assert out.exit_code == 2
    assert out.message.startswith("blocked by aileron rule local-001")
    assert out.event["status"] == "blocked"
    assert out.event["tool"]["arguments"] is None
    assert os.path.getsize(_log(tmp_path)) < 4096


HOSTILE_NAMES = ["mcp__srv__(.*)+$|^[", "mcp__日本語__ツール", "n" * 256]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_hostile_tool_name_recorded_verbatim(tmp_path, name):
    out = _run(tmp_path, _payload(tool=name))
    assert out.exit_code == 0
    (stored,) = _stored(tmp_path)
    assert stored["tool"]["name"] == name
    assert events.validate(stored) == []
    assert verify(_log(tmp_path)).ok


def test_journal_verifies_after_mixed_session(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    kinds = ("PreToolUse", "PostToolUse", "PostToolUseFailure")
    for i in range(20):
        command = f"step {i}" + (" && rm -rf /tmp/x" if i % 7 == 0 else "")
        out = _run(tmp_path, _payload(kinds[i % 3], tool_input={"command": command}, tool_use_id=f"toolu_{i:03d}"),
                   rules=rules)
        assert out.exit_code in (0, 2)
    stored = _stored(tmp_path)
    assert [e["seq"] for e in stored] == list(range(1, 21))
    assert {e["status"] for e in stored} == {"ok", "blocked", "error"}
    assert all(events.validate(e) == [] for e in stored)
    assert verify(_log(tmp_path)).ok


# ---------------------------------------------------------------- blocking


def test_pre_block_exit_2_rule_id_on_stderr(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    out = _run(tmp_path, _payload(tool_input={"command": "rm -rf /tmp/aileron-smoke", "description": "clean up"}),
               rules=rules)
    assert out.exit_code == 2
    assert out.message == ("blocked by aileron rule local-001 (Block destructive shell commands from Claude Code); "
                           f"recorded as seq 1 in {_log(tmp_path)}")
    assert out.event["status"] == "blocked"
    assert out.event["policy"] == {"rule_id": "local-001", "action": "block"}
    assert events.validate(out.event) == []


def _docs_blocks(language: str) -> list[str]:
    """Fenced code blocks of one language from docs/claude-code.md."""
    assert DOCS.exists(), "docs/claude-code.md is part of the hook contract: the README links to its snippet and rule"
    return re.findall(rf"```{language}\n(.*?)```", DOCS.read_text(encoding="utf-8"), re.S)


def test_docs_rule_blocks_bash_rm_rf(tmp_path):
    blocks = [b for b in _docs_blocks("yaml") if "id: local-001" in b]
    assert blocks, "docs/claude-code.md must carry the paste-in rule"
    rules = _rules(tmp_path, blocks[0], name="claude-code-shell.yml")
    blocked = _run(tmp_path, _payload(tool="Bash", tool_input={"command": "rm -rf /tmp/x"}), rules=rules)
    allowed = _run(tmp_path, _payload(tool="Read", tool_input={"file_path": "/home/me/notes/rm -rf.md"}),
                   rules=rules)
    assert blocked.exit_code == 2 and blocked.event["status"] == "blocked"
    assert allowed.exit_code == 0 and allowed.event["status"] == "ok"


def test_digest_only_strips_but_rule_fires(tmp_path):
    """Invariant 2: capture_content gates persistence, not enforcement."""
    rules = _rules(tmp_path, RM_RULE)
    out = _run(tmp_path, _payload(tool_input={"command": "rm -rf /"}), rules=rules)
    assert out.exit_code == 2
    assert out.event["policy"]["rule_id"] == "local-001"
    (on_disk,) = _stored(tmp_path)
    assert on_disk["tool"]["arguments"] is None
    assert "rm -rf" not in Path(_log(tmp_path)).read_text(encoding="utf-8")


def test_digest_only_strips_error_but_rule_fires(tmp_path):
    """Invariant 2 for meta.error: a rule on the error text fires in digest mode and the file holds the digest."""
    rules = _rules(tmp_path, (
        "id: local-005\ntitle: Permission problems\nseverity: medium\n"
        "match:\n  meta.error_contains:\n    - permission denied\naction: alert\n"
    ))
    error = "command exited 1: permission denied"
    out = _run(tmp_path, _payload("PostToolUseFailure", error=error), rules=rules)
    assert (out.exit_code, out.message) == (0, "")
    assert out.event["policy"] == {"rule_id": "local-005", "action": "alert"}
    assert out.event["meta"]["error"] == {"digest": digest(error)}
    assert "permission denied" not in Path(_log(tmp_path)).read_text(encoding="utf-8")
    captured = _run(tmp_path, _payload("PostToolUseFailure", error=error), rules=rules, capture=True)
    assert captured.event["policy"] == {"rule_id": "local-005", "action": "alert"}
    assert captured.event["meta"]["error"] == error
    assert verify(_log(tmp_path)).ok


def test_blocked_event_is_appended_before_verdict(tmp_path):
    """The block outcome carries the stored event and cites its seq: the line is on disk first."""
    rules = _rules(tmp_path, RM_RULE)
    out = _run(tmp_path, _payload(tool_input={"command": "rm -rf /"}), rules=rules)
    assert out.exit_code == 2
    assert out.event is not None
    assert _stored(tmp_path) == [out.event]
    assert out.message.endswith(f"recorded as seq {out.event['seq']} in {_log(tmp_path)}")


def test_alert_recorded_exit_0(tmp_path):
    rules = _rules(tmp_path, ALERT_RULE)
    out = _run(tmp_path, _payload(tool="Edit", tool_input={"file_path": "/home/me/.claude/settings.json"}),
               rules=rules)
    assert (out.exit_code, out.message) == (0, "")
    assert out.event["status"] == "ok"
    assert out.event["policy"] == {"rule_id": "local-002", "action": "alert"}


def test_post_block_verdict_exit_2_status_kept(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    out = _run(tmp_path, _payload("PostToolUse", tool_input={"command": "rm -rf /tmp/x"}), rules=rules)
    assert out.exit_code == 2
    assert out.event["status"] == "ok"
    assert out.event["policy"] == {"rule_id": "local-001", "action": "block"}
    assert out.message == ("aileron: Bash already ran but matches block rule local-001 "
                           "(Block destructive shell commands from Claude Code); "
                           "the PreToolUse hook did not stop it; "
                           f"recorded as seq 1 in {_log(tmp_path)}")


def test_post_failure_never_blocks(tmp_path):
    rules = _rules(tmp_path, RM_RULE)
    out = _run(tmp_path, _payload("PostToolUseFailure", tool_input={"command": "rm -rf /tmp/x"}), rules=rules)
    assert out.exit_code == 2
    assert out.event["status"] == "error"
    assert out.event["policy"] == {"rule_id": "local-001", "action": "block"}
    assert "Bash already ran but matches block rule local-001" in out.message


def test_rule_on_meta_hook_agent_type_matches_subagent(tmp_path):
    rules = _rules(tmp_path, (
        "id: local-003\ntitle: Explore subagents may not run shell commands\nseverity: high\n"
        "match:\n  type: tool_call\n  tool.name: Bash\n  meta.hook.agent_type: Explore\naction: block\n"
    ))
    sub = _run(tmp_path, _payload(agent_id="agent_7Hq2", agent_type="Explore"), rules=rules)
    top = _run(tmp_path, _payload(), rules=rules)
    assert sub.exit_code == 2 and sub.event["status"] == "blocked"
    assert top.exit_code == 0 and top.event["status"] == "ok"


def test_rule_on_transport_matches(tmp_path):
    rules = _rules(tmp_path, (
        "id: local-004\ntitle: Every Claude Code call\nseverity: low\n"
        "match:\n  meta.transport: claude-code-hook\naction: alert\n"
    ))
    out = _run(tmp_path, _payload(), rules=rules)
    assert out.exit_code == 0
    assert out.event["policy"] == {"rule_id": "local-004", "action": "alert"}


def test_never_emits_permission_allow(tmp_path, monkeypatch, capsys):
    """Exit 0 with empty stdout is "no opinion"; the hook never widens what Claude Code would permit."""
    rules = _rules(tmp_path, RM_RULE)
    log = _log(tmp_path)
    for raw in (_payload(), _payload(tool_input={"command": "rm -rf /"}), b"{", _payload("PostToolUse")):
        assert _main(monkeypatch, raw, ["--log", log, "--rules", rules]) in (0, 2)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "permissionDecision" not in captured.err
    assert "hookSpecificOutput" not in captured.err


# ------------------------------------------------------------- fail closed


def _refused(tmp_path, raw, reason: str):
    """Assert ``raw`` is refused with ``reason`` and nothing was created on disk."""
    out = _run(tmp_path, raw)
    assert out.exit_code == 2
    assert out.event is None
    assert out.message.startswith("aileron: hook input rejected (")
    assert out.message.endswith("); refusing to continue")
    assert reason in out.message, out.message
    assert not Path(_log(tmp_path)).exists()
    assert not Path(_log(tmp_path) + ".lock").exists()
    return out


def test_empty_stdin_refused(tmp_path):
    _refused(tmp_path, b"", "empty stdin")


def test_invalid_utf8_refused(tmp_path):
    _refused(tmp_path, b'{"session_id":"\xff\xfe"}', "not UTF-8")


@pytest.mark.parametrize("raw", [b"not json", b'{"session_id": "s"', _payload() + _payload(), b"\xef\xbb\xbf{}"])
def test_malformed_json_refused(tmp_path, raw):
    _refused(tmp_path, raw, "not JSON")


@pytest.mark.parametrize("raw", [b"[]", b'"x"', b"null", b"1"])
def test_non_object_payload_refused(tmp_path, raw):
    _refused(tmp_path, raw, "top level is not a JSON object")


def test_duplicate_key_refused(tmp_path):
    nested = _with_input(b'{"command":"ls","command":"rm -rf /"}')
    top = b'{"tool_name":"Read","tool_name":"Bash",' + _payload()[1:]
    _refused(tmp_path, nested, "duplicate key 'command'")
    _refused(tmp_path, top, "duplicate key 'tool_name'")


@pytest.mark.parametrize(("literal", "reason"), [
    ("NaN", "non-JSON constant 'NaN'"),
    ("Infinity", "non-JSON constant 'Infinity'"),
    ("-Infinity", "non-JSON constant '-Infinity'"),
    ("1e999", "non-finite number '1e999'"),
])
def test_nan_refused_before_canonical_json(tmp_path, literal, reason):
    _refused(tmp_path, _with_input(b'{"n": ' + literal.encode() + b"}"), reason)


def test_deep_nesting_refused(tmp_path):
    # Past the explicit bound: refused on every Python version, whether or not
    # json.loads itself raised RecursionError.
    _refused(tmp_path, _with_input(b"[" * 300 + b"]" * 300), "nesting too deep")
    _refused(tmp_path, _with_input(b"[" * 100_000 + b"]" * 100_000), "nesting too deep")
    _refused(tmp_path, _with_input(b'{"a":' * 300 + b"1" + b"}" * 300), "nesting too deep")
    # Inside the bound: recorded, and the journal still verifies.
    ok = _run(tmp_path, _with_input(b"[" * 250 + b"]" * 250))
    assert ok.exit_code == 0
    assert verify(_log(tmp_path)).ok


@pytest.mark.parametrize("event", [OMIT, "Stop", "Notification", "SessionStart", "pretooluse", 5, ""])
def test_unsupported_event_refused(tmp_path, event):
    _refused(tmp_path, _payload(hook_event_name=event), "hook_event_name")


BAD_SESSION_IDS = [OMIT, None, 123, "", " x", "x ", "a\nb", "a​b", "\x1b[31mred", "s" * 129]


@pytest.mark.parametrize("session_id", BAD_SESSION_IDS)
def test_bad_session_id_refused(tmp_path, session_id):
    _refused(tmp_path, _payload(session_id=session_id), "session_id must be 1 to 128 printable characters")


BAD_TOOL_NAMES = [OMIT, None, 7, "", "n" * 257, "Ba\x01sh", "Bash\n", "a​b"]


@pytest.mark.parametrize("name", BAD_TOOL_NAMES)
def test_bad_tool_name_refused(tmp_path, name):
    _refused(tmp_path, _payload(tool=name), "tool_name must be 1 to 256 printable characters")


def test_missing_tool_input_refused(tmp_path):
    _refused(tmp_path, _payload(tool_input=OMIT), "tool_input is missing")
    # Present but null is a value, not an omission.
    assert _run(tmp_path, _payload(tool_input=None)).exit_code == 0


def test_oversize_input_refused_before_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "MAX_INPUT_BYTES", 1024)
    # The bound is "more than", so 1024 bytes get as far as the parser.
    with pytest.raises(HookInputError, match="input larger than 1024 bytes"):
        parse_payload(b"x" * 1025)
    with pytest.raises(HookInputError, match="not JSON"):
        parse_payload(b"x" * 1024)

    def never(*args, **kwargs):
        raise AssertionError("json.loads ran on an oversized payload")

    monkeypatch.setattr(hook.json, "loads", never)
    raw = _payload(tool_input={"command": "x" * 1024})
    assert len(raw) > 1024
    _refused(tmp_path, raw, "input larger than 1024 bytes")


def test_bad_rules_block_pre_and_are_journaled(tmp_path):
    for rules in (str(tmp_path / "no-such-rules"), _rules(tmp_path, BROKEN_RULE, name="broken.yml")):
        out = _run(tmp_path, _payload(tool="Read", tool_input={"file_path": "/x"}), rules=rules)
        assert out.exit_code == 2
        assert out.event["status"] == "blocked"
        assert out.event["policy"] == {"rule_id": "aileron-hook-config", "action": "block"}
        assert out.message.startswith(f"aileron: rules {rules} could not be loaded (")
        assert f"refusing to let Read run unpoliced; recorded as seq {out.event['seq']} in" in out.message
        assert events.validate(out.event) == []
    assert [e["seq"] for e in _stored(tmp_path)] == [1, 2]
    assert verify(_log(tmp_path)).ok


def test_bad_rules_on_post_exit_2_status_kept(tmp_path):
    rules = str(tmp_path / "no-such-rules")
    post = _run(tmp_path, _payload("PostToolUse", tool="Read"), rules=rules)
    fail = _run(tmp_path, _payload("PostToolUseFailure", tool="Read"), rules=rules)
    assert post.exit_code == 2 and post.event["status"] == "ok"
    assert fail.exit_code == 2 and fail.event["status"] == "error"
    for out in (post, fail):
        assert out.event["policy"] == {"rule_id": "aileron-hook-config", "action": "block"}
        assert out.message.startswith(f"aileron: rules {rules} could not be loaded (")
        assert "Read already ran unpoliced; recorded as seq" in out.message


@pytest.mark.parametrize(("text", "reason"), [
    # Loads (match keys are not validated) and crashes _matcher_for in decide().
    ("id: k-1\nmatch:\n  1: x\naction: block\n", "rule evaluation failed: AttributeError:"),
    # Raises RecursionError, not ValueError, inside yaml.safe_load.
    ("id: d-1\nmatch:\n  x: " + "[" * 5000 + "]" * 5000 + "\naction: block\n", "maximum recursion depth exceeded"),
])
def test_rules_that_load_but_cannot_run_are_journaled_as_config_error(tmp_path, text, reason):
    """A rules failure of any kind is a recorded aileron-hook-config block, not an escaped exception."""
    rules = _rules(tmp_path, text, name="odd.yml")
    pre = _run(tmp_path, _payload(), rules=rules)
    post = _run(tmp_path, _payload("PostToolUse"), rules=rules)
    assert pre.exit_code == 2 and pre.event["status"] == "blocked"
    assert post.exit_code == 2 and post.event["status"] == "ok"
    for out in (pre, post):
        assert out.event["policy"] == {"rule_id": "aileron-hook-config", "action": "block"}
        assert out.message.startswith(f"aileron: rules {rules} could not be loaded (")
        assert reason in out.message, out.message
    assert "refusing to let Bash run unpoliced; recorded as seq 1 in" in pre.message
    assert "Bash already ran unpoliced; recorded as seq 2 in" in post.message
    assert verify(_log(tmp_path)).ok


def test_rules_path_without_rules_is_refused(tmp_path):
    """--rules asks for enforcement; a path that yields no rules is a configuration error, not a quiet pass."""
    empty = tmp_path / "empty-rules"
    empty.mkdir()
    nested = tmp_path / "nested-rules" / "sub"
    nested.mkdir(parents=True)
    (nested / "block.yml").write_text(RM_RULE, encoding="utf-8")
    for rules in (str(empty), str(nested.parent)):
        out = _run(tmp_path, _payload(tool_input={"command": "rm -rf /"}), rules=rules)
        assert out.exit_code == 2
        assert out.event["status"] == "blocked"
        assert out.event["policy"] == {"rule_id": "aileron-hook-config", "action": "block"}
        assert out.message.startswith(
            f"aileron: rules {rules} could not be loaded (no rules found); refusing to let Bash run unpoliced"
        )
    assert [e["seq"] for e in _stored(tmp_path)] == [1, 2]
    assert verify(_log(tmp_path)).ok


def _options_at(log_path: str) -> HookOptions:
    return HookOptions(log_path=log_path, rules_path=None, capture_content=False,
                       agent_name=DEFAULT_AGENT_NAME, framework=DEFAULT_FRAMEWORK)


def test_unwritable_journal_blocks_pre(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    log_path = str(blocker / "hook.chain.jsonl")
    out = run_hook(_payload(), _options_at(log_path))
    assert out.exit_code == 2
    assert out.event is None
    assert out.message.startswith(f"aileron: journal {log_path} could not be written (")
    assert out.message.endswith("); refusing to let Bash run unrecorded")
    assert blocker.read_text(encoding="utf-8") == "x"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root ignores directory permissions")
def test_unwritable_journal_post_exits_2(tmp_path):
    read_only = tmp_path / "ro"
    read_only.mkdir()
    read_only.chmod(0o500)
    log_path = str(read_only / "hook.chain.jsonl")
    try:
        out = run_hook(_payload("PostToolUse"), _options_at(log_path))
    finally:
        read_only.chmod(0o700)
    assert out.exit_code == 2
    assert out.event is None
    assert out.message.startswith(f"aileron: journal {log_path} could not be written (PermissionError:")
    assert out.message.endswith("); Bash already ran and is not recorded, fix the journal before continuing")
    assert list(read_only.iterdir()) == []


def test_journal_path_is_directory_blocks(tmp_path):
    Path(_log(tmp_path)).mkdir()
    out = _run(tmp_path, _payload())
    assert out.exit_code == 2
    assert out.event is None
    assert "could not be written (IsADirectoryError:" in out.message
    assert out.message.endswith("refusing to let Bash run unrecorded")


def test_append_failure_after_allow_still_blocks(tmp_path, monkeypatch):
    """Regression guard for "allowed but unrecorded": a failed append after an allow verdict is exit 2."""

    def broken_append(self, event):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ChainLog, "append", broken_append)
    pre = _run(tmp_path, _payload())
    post = _run(tmp_path, _payload("PostToolUse"))
    assert pre.exit_code == 2 and pre.event is None
    assert "(OSError: [Errno 28] No space left on device)" in pre.message
    assert pre.message.endswith("refusing to let Bash run unrecorded")
    assert post.exit_code == 2 and post.event is None
    assert post.message.endswith("Bash already ran and is not recorded, fix the journal before continuing")
    assert _stored(tmp_path) == []


def test_lock_timeout_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(hook, "LOCK_TIMEOUT_S", 0.2)
    log = _log(tmp_path)
    with exclusive_lock(log, 5.0):
        out = _run(tmp_path, _payload())
    assert out.exit_code == 2
    assert out.event is None
    assert f"(TimeoutError: lock {log}.lock held by another writer for 0.2s)" in out.message
    assert out.message.endswith("refusing to let Bash run unrecorded")
    assert not Path(log).exists()
    # Once the holder lets go the same call goes through.
    assert _run(tmp_path, _payload()).exit_code == 0


def test_parallel_processes_keep_chain_valid(tmp_path):
    """Eight real hook processes queue on the cross-process lock and leave one unforked chain.

    The parent holds the lock while the children start, so all eight are
    blocked on it at the same moment instead of relying on interpreter
    start-up jitter to make them collide. A lock that is missing or only
    process-local lets a child finish during the hold, which the poll() check
    catches on every run.
    """
    log = _log(tmp_path)
    env = {k: v for k, v in os.environ.items() if k not in HOOK_ENV}
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(ROOT / "src"), env.get("PYTHONPATH")) if p)
    with exclusive_lock(log, 5.0):
        procs = [
            subprocess.Popen([sys.executable, "-m", "aileron.cli", "hook", "--log", log],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            for _ in range(8)
        ]
        for i, proc in enumerate(procs):
            proc.stdin.write(_payload(tool_input={"command": f"echo {i}"}, tool_use_id=f"toolu_{i}"))
            proc.stdin.close()
        # Time for the children to start and reach the lock. None may finish while it is held;
        # the hook's own lock timeout is 10 s, far past this.
        time.sleep(1.0)
        finished = {i: (proc.returncode, proc.stderr.read())
                    for i, proc in enumerate(procs) if proc.poll() is not None}
        assert not finished, finished
    # stdin is already closed, so collect without communicate(), which flushes it first
    # (ValueError on Python 3.10 to 3.13). Output is asserted empty, so reading after wait() cannot block.
    results = []
    for proc in procs:
        code = proc.wait(timeout=120)
        with proc.stdout, proc.stderr:
            results.append((code, proc.stdout.read(), proc.stderr.read()))
    assert [code for code, _, _ in results] == [0] * 8, results
    assert all(out == b"" and err == b"" for _, out, err in results), results
    stored = ChainLog.read(log)
    assert [e["seq"] for e in stored] == list(range(1, 9))
    assert sorted(e["meta"]["hook"]["tool_use_id"] for e in stored) == sorted(f"toolu_{i}" for i in range(8))
    assert verify(log).ok


def test_parallel_threads_keep_chain_valid(tmp_path):
    log = _log(tmp_path)
    failures: list = []

    def worker(n: int) -> None:
        for i in range(5):
            out = _run(tmp_path, _payload(tool_input={"command": f"echo {n}-{i}"}, tool_use_id=f"toolu_{n}_{i}"))
            if out.exit_code != 0:
                failures.append(out)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert failures == []
    stored = ChainLog.read(log)
    assert [e["seq"] for e in stored] == list(range(1, 41))
    assert verify(log).ok


# ---------------------------------------------------------------- identity


def test_identity_defaults(tmp_path):
    out = _run(tmp_path, _payload())
    assert out.event["agent"] == {"name": "claude-code", "framework": "claude-code", "version": None}
    assert out.event["session_id"] == SESSION


def test_identity_flags_and_env(tmp_path, monkeypatch):
    log = _log(tmp_path)
    assert _main(monkeypatch, _payload(), ["--log", log, "--agent", "reviewer", "--framework", "claude-code-ci"]) == 0
    monkeypatch.setenv("AILERON_AGENT", "env-agent")
    monkeypatch.setenv("AILERON_FRAMEWORK", "env-framework")
    monkeypatch.setenv("AILERON_SESSION_ID", "env-session-must-be-ignored")
    assert _main(monkeypatch, _payload(), ["--log", log]) == 0
    assert _main(monkeypatch, _payload(), ["--log", log, "--agent", "flag-agent"]) == 0
    flag, env, mixed = _stored(tmp_path)
    assert (flag["agent"]["name"], flag["agent"]["framework"]) == ("reviewer", "claude-code-ci")
    assert (env["agent"]["name"], env["agent"]["framework"]) == ("env-agent", "env-framework")
    assert (mixed["agent"]["name"], mixed["agent"]["framework"]) == ("flag-agent", "env-framework")
    # The session id is the join key to Claude Code's own transcript; the variable is ignored here.
    assert {e["session_id"] for e in (flag, env, mixed)} == {SESSION}


def test_agent_type_not_used_as_agent_name(tmp_path):
    out = _run(tmp_path, _payload(agent_id="agent_7Hq2", agent_type="Explore"))
    assert out.event["agent"]["name"] == "claude-code"
    assert out.event["meta"]["hook"]["agent_type"] == "Explore"
    assert out.event["meta"]["hook"]["agent_id"] == "agent_7Hq2"


# -------------------------------------------------------------------- docs


def test_docs_snippet_is_valid_json_and_names_hook():
    blocks = _docs_blocks("json")
    assert blocks, "docs/claude-code.md must carry the settings.json snippet"
    hooks = json.loads(blocks[0])["hooks"]
    assert set(hooks) == {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    for event, groups in hooks.items():
        entries = [entry for group in groups for entry in group["hooks"]]
        assert entries, event
        for entry in entries:
            assert entry["type"] == "command"
            assert entry["command"] == "aileron"
            assert entry["args"][0] == "hook"
            assert "--log" in entry["args"]
            assert ("onFailure" in entry) == (event == "PreToolUse")
            if event == "PreToolUse":
                assert entry["onFailure"] == "block"


# ------------------------------------------------- the whole matrix via main


MATRIX = [
    "allowed", "alert", "blocked", "post-block", "post-failure", "empty", "not-json", "unsupported-event",
    "bad-session", "broken-rules", "missing-rules", "unwritable-journal", "no-log-path", "bad-identity",
]


def _case(name: str, tmp_path) -> tuple[list[str], bytes, int]:
    """argv, stdin and the expected exit code for one row of the failure matrix."""
    log = _log(tmp_path)
    rules = _rules(tmp_path, RM_RULE)
    alert = _rules(tmp_path, ALERT_RULE, name="alert.yml")
    broken = _rules(tmp_path, BROKEN_RULE, name="broken.yml")
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    cases = {
        "allowed": (["--log", log, "--rules", rules], _payload(), 0),
        "alert": (["--log", log, "--rules", alert],
                  _payload(tool="Edit", tool_input={"file_path": "/home/me/.claude/settings.json"}), 0),
        "blocked": (["--log", log, "--rules", rules], _payload(tool_input={"command": "rm -rf /"}), 2),
        "post-block": (["--log", log, "--rules", rules],
                       _payload("PostToolUse", tool_input={"command": "rm -rf /"}), 2),
        "post-failure": (["--log", log, "--rules", rules], _payload("PostToolUseFailure"), 0),
        "empty": (["--log", log], b"", 2),
        "not-json": (["--log", log], b"{not json", 2),
        "unsupported-event": (["--log", log], _payload(hook_event_name="Stop"), 2),
        "bad-session": (["--log", log], _payload(session_id=""), 2),
        "broken-rules": (["--log", log, "--rules", broken], _payload(), 2),
        "missing-rules": (["--log", log, "--rules", str(tmp_path / "missing")], _payload("PostToolUse"), 2),
        "unwritable-journal": (["--log", str(blocker / "j.jsonl")], _payload(), 2),
        "no-log-path": ([], _payload(), 2),
        "bad-identity": (["--log", log, "--agent", " x"], _payload(), 2),
    }
    return cases[name]


@pytest.mark.parametrize("case", MATRIX)
def test_stdout_always_empty(tmp_path, monkeypatch, capsys, case):
    argv, raw, expected = _case(case, tmp_path)
    code = _main(monkeypatch, raw, argv)
    captured = capsys.readouterr()
    assert captured.out == ""
    # A message on stderr if and only if the exit code is 2.
    assert (captured.err != "") == (code == 2), captured.err
    assert code == expected
    if captured.err:
        assert captured.err.count("\n") == 1 and captured.err.endswith("\n")
    # The operator-facing lines Claude Code shows must carry the rule id, title and seq.
    if case == "blocked":
        assert captured.err == ("blocked by aileron rule local-001 "
                                "(Block destructive shell commands from Claude Code); "
                                f"recorded as seq 1 in {_log(tmp_path)}\n")
    elif case == "post-block":
        assert captured.err.startswith("aileron: Bash already ran but matches block rule local-001 "
                                       "(Block destructive shell commands from Claude Code); ")
        assert captured.err.endswith(f"recorded as seq 1 in {_log(tmp_path)}\n")
    elif case == "broken-rules":
        assert captured.err.startswith("aileron: rules ") and "could not be loaded (" in captured.err
        assert "aileron-hook-config" not in captured.err


@pytest.mark.parametrize("case", MATRIX)
def test_never_exits_1(tmp_path, monkeypatch, case):
    argv, raw, expected = _case(case, tmp_path)
    code = _main(monkeypatch, raw, argv)
    assert code in (0, 2)
    assert code == expected
