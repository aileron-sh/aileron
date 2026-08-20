"""Run the proxy against a real MCP server, not a hand-written stub.

Every other proxy test uses a fake server written for the test. Those prove
the logic but not the claim the README actually makes, which is that Aileron
works in front of a real MCP server. This test closes that gap.

It is skipped unless node is installed and AILERON_LIVE_MCP=1 is set, because
it downloads a package from npm and needs network. CI does not run it by
default; run it before a release:

    AILERON_LIVE_MCP=1 python -m pytest tests/test_real_mcp_server.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog, verify  # noqa: E402

SERVER = ["npx", "-y", "@modelcontextprotocol/server-filesystem"]

pytestmark = [
    pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed"),
    pytest.mark.skipif(
        os.environ.get("AILERON_LIVE_MCP") != "1",
        reason="set AILERON_LIVE_MCP=1 to run against a real MCP server (needs network)",
    ),
]


def _send(proc, obj):
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()


def _reply(proc, want_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg
    return None


def test_proxy_in_front_of_the_real_filesystem_server(tmp_path):
    """Handshake, list tools, read a real file, and block a real write."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "note.txt").write_text("hello from a real file\n", encoding="utf-8")

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "block.yml").write_text(
        "id: aileron-100\n"
        "title: Block destructive writes\n"
        "severity: high\n"
        "match:\n"
        "  type: tool_call\n"
        "  tool.name: write_file\n"
        '  tool.arguments_contains:\n    - "rm -rf"\n'
        "action: block\n",
        encoding="utf-8",
    )
    log = tmp_path / "run.chain.jsonl"

    proc = subprocess.Popen(
        [sys.executable, "-m", "aileron.cli", "proxy", "--log", str(log),
         "--rules", str(rules), "--", *SERVER, str(sandbox)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "aileron-test", "version": "1.0"}}})
        init = _reply(proc, 1)
        assert init is not None, "real server did not answer initialize through the proxy"
        assert "result" in init

        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        listed = _reply(proc, 2)
        assert listed and listed["result"]["tools"], "no tools listed through the proxy"

        # A real read must succeed and reach the client unchanged.
        _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "read_text_file",
            "arguments": {"path": str(sandbox / "note.txt")}}})
        read = _reply(proc, 3)
        assert read and "result" in read, f"real read failed: {read}"
        assert "hello from a real file" in json.dumps(read["result"])

        # A blocked write must never reach the server.
        _send(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "write_file",
            "arguments": {"path": str(sandbox / "pwned.txt"),
                          "content": "rm -rf / --no-preserve-root"}}})
        blocked = _reply(proc, 4)
        assert blocked and "error" in blocked, f"write was not blocked: {blocked}"
        assert blocked["error"]["code"] == -32000
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # The server must not have written the blocked file.
    assert not (sandbox / "pwned.txt").exists(), "blocked write still reached the server"

    events = ChainLog.read(str(log))
    names = [(e.get("tool") or {}).get("name") for e in events]
    statuses = [e["status"] for e in events]
    assert "read_text_file" in names and "write_file" in names
    assert "blocked" in statuses
    assert verify(str(log)).ok, "journal from a real session does not verify"

    # Digest-only by default: real file contents must not be on disk.
    assert "hello from a real file" not in log.read_text(encoding="utf-8")
