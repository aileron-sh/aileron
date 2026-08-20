"""Tests for the read-only journal MCP server.

Most of these are containment tests. The whole point of the module is that it
exposes journals to an agent without becoming a file reader, so the interesting
cases are the ones that try to walk out of the served directory.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog  # noqa: E402
from aileron.events import new_event  # noqa: E402
from aileron.mcpserver import Denied, _resolve, serve  # noqa: E402


def _journal(root: Path, name="run.chain.jsonl", tools=("read_file", "shell")):
    log = ChainLog(str(root / name))
    for tool in tools:
        log.append(new_event("tool_call", "s", "agent", "mcp", tool={"name": tool}))
    return root / name


def _drive(root: Path, requests: list[dict]) -> list[dict]:
    """Run the server over a canned request list and collect the replies."""
    payload = b"".join(json.dumps(r).encode() + b"\n" for r in requests)
    out = io.BytesIO()
    serve(str(root), stdin=io.BytesIO(payload), stdout=out)
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def _call(root: Path, tool: str, arguments: dict, req_id: int = 1) -> dict:
    replies = _drive(root, [{"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                             "params": {"name": tool, "arguments": arguments}}])
    assert replies, "server returned nothing"
    return replies[0]


def _payload(reply: dict) -> dict:
    return json.loads(reply["result"]["content"][0]["text"])


# ------------------------------------------------------------ protocol basics


def test_handshake_and_tool_list(tmp_path):
    replies = _drive(tmp_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ])
    assert replies[0]["result"]["serverInfo"]["name"] == "aileron"
    names = {t["name"] for t in replies[1]["result"]["tools"]}
    assert names == {"verify_journal", "query_events", "explain_rule"}
    # A notification must not produce a reply.
    assert len(replies) == 2


def test_unknown_tool_and_method_are_refused(tmp_path):
    reply = _call(tmp_path, "delete_journal", {"journal": "x.jsonl"})
    assert reply["error"]["code"] == -32601
    replies = _drive(tmp_path, [{"jsonrpc": "2.0", "id": 9, "method": "sneaky/thing"}])
    assert replies[0]["error"]["code"] == -32601


# ----------------------------------------------------------------- the tools


def test_verify_journal_reports_intact_and_tampered(tmp_path):
    path = _journal(tmp_path)
    payload = _payload(_call(tmp_path, "verify_journal", {"journal": path.name}))
    assert payload["intact"] is True and payload["events"] == 2

    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[0])
    event["status"] = "blocked"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    payload = _payload(_call(tmp_path, "verify_journal", {"journal": path.name}))
    assert payload["intact"] is False


def test_query_events_filters(tmp_path):
    path = _journal(tmp_path, tools=("read_file", "shell", "shell"))
    payload = _payload(_call(tmp_path, "query_events",
                             {"journal": path.name, "tool_name": "shell"}))
    assert payload["returned"] == 2
    assert {e["tool"] for e in payload["events"]} == {"shell"}


def test_query_events_limit_is_capped(tmp_path):
    path = _journal(tmp_path, tools=tuple("shell" for _ in range(30)))
    payload = _payload(_call(tmp_path, "query_events",
                             {"journal": path.name, "limit": 100000}))
    assert payload["returned"] <= 200


def test_explain_rule_lists_and_finds(tmp_path):
    payload = _payload(_call(tmp_path, "explain_rule", {}))
    assert len(payload["rules"]) >= 30
    payload = _payload(_call(tmp_path, "explain_rule", {"rule_id": "aileron-001"}))
    assert payload["rules"][0]["action"] == "block"


# -------------------------------------------------------------- containment
# These are the ones that matter. The server must not become a file reader.


@pytest.mark.parametrize("escape", [
    "../outside.jsonl",
    "../../etc/passwd",
    "sub/../../outside.jsonl",
    "/etc/passwd",
    "/tmp/anything.jsonl",
])
def test_paths_outside_the_root_are_refused(tmp_path, escape):
    root = tmp_path / "journals"
    root.mkdir()
    # A real journal sitting just outside the served root.
    _journal(tmp_path, name="outside.jsonl")
    with pytest.raises(Denied):
        _resolve(root, escape)


def test_non_jsonl_files_are_refused(tmp_path):
    (tmp_path / "aileron_ed25519.key").write_text("-----BEGIN PRIVATE KEY-----\n")
    with pytest.raises(Denied, match="only .jsonl"):
        _resolve(tmp_path, "aileron_ed25519.key")


def test_signing_keys_cannot_be_read_even_when_renamed(tmp_path):
    """A key renamed to look like a journal still must not be served as one."""
    (tmp_path / "sneaky.jsonl").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n", encoding="utf-8")
    payload = _payload(_call(tmp_path, "verify_journal", {"journal": "sneaky.jsonl"}))
    # It is read as a journal and reported as broken. What must never happen is
    # the file's contents coming back to the caller.
    assert payload["intact"] is False
    blob = json.dumps(payload)
    assert "PRIVATE KEY" not in blob and "b3BlbnNzaC1rZXktdjEA" not in blob


def test_errors_do_not_echo_file_contents(tmp_path):
    (tmp_path / "junk.jsonl").write_text("SECRET_TOKEN_abc123 not json\n", encoding="utf-8")
    reply = _call(tmp_path, "query_events", {"journal": "junk.jsonl"})
    assert "SECRET_TOKEN_abc123" not in json.dumps(reply)


def test_missing_journal_is_a_clean_refusal(tmp_path):
    reply = _call(tmp_path, "verify_journal", {"journal": "nope.jsonl"})
    assert reply["result"]["isError"] is True
    assert "no such journal" in reply["result"]["content"][0]["text"]


def test_bad_argument_types_do_not_crash(tmp_path):
    for bad in [{"journal": 42}, {"journal": None}, {"journal": ""}, {}]:
        reply = _call(tmp_path, "verify_journal", bad)
        assert reply["result"]["isError"] is True


def test_there_are_no_mutating_tools():
    """A write tool here would hand the recorded agent its own evidence locker."""
    from aileron.mcpserver import HANDLERS, TOOLS

    forbidden = ("write", "delete", "remove", "rotate", "sign", "edit", "truncate")
    for name in list(HANDLERS) + [t["name"] for t in TOOLS]:
        assert not any(word in name.lower() for word in forbidden), (
            f"{name} looks like it mutates state; this server must stay read only"
        )
