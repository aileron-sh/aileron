"""Tests for aileron.proxy: MCP stdio proxy (ndjson + Content-Length framing, policy block)."""
from __future__ import annotations

import io
import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


from aileron import events  # noqa: E402
from aileron.chainlog import ChainLog, verify  # noqa: E402
from aileron.policy import Rule  # noqa: E402
from aileron.proxy import run_proxy  # noqa: E402

CHILD_NDJSON = (
    "import sys, json\n"
    "for line in sys.stdin:\n"
    "    line = line.strip()\n"
    "    if not line:\n"
    "        continue\n"
    "    req = json.loads(line)\n"
    "    if req.get('method') == 'tools/call':\n"
    "        resp = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'echo': req.get('params')}}\n"
    "    elif 'id' in req:\n"
    "        resp = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': {}}\n"
    "    else:\n"
    "        continue\n"
    "    sys.stdout.write(json.dumps(resp) + '\\n')\n"
    "    sys.stdout.flush()\n"
)

CHILD_FRAMED = (
    "import sys, json\n"
    "def read_msg():\n"
    "    length = None\n"
    "    while True:\n"
    "        line = sys.stdin.buffer.readline()\n"
    "        if not line:\n"
    "            return None\n"
    "        if line in (b'\\r\\n', b'\\n'):\n"
    "            break\n"
    "        if line.lower().startswith(b'content-length:'):\n"
    "            length = int(line.split(b':')[1].strip())\n"
    "    return sys.stdin.buffer.read(length)\n"
    "while True:\n"
    "    body = read_msg()\n"
    "    if body is None:\n"
    "        break\n"
    "    req = json.loads(body)\n"
    "    resp = json.dumps({'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'echo': req.get('params')}}).encode()\n"
    "    sys.stdout.buffer.write(b'Content-Length: %d\\r\\n\\r\\n' % len(resp) + resp)\n"
    "    sys.stdout.buffer.flush()\n"
)


class _ProxySession:
    """Runs run_proxy in a thread with pipe-backed fake stdin/stdout."""

    def __init__(self, monkeypatch, tmp_path, child_argv, rules=None, capture_content=False):
        self.log = ChainLog(str(tmp_path / "proxy.chain.jsonl"), capture_content=capture_content)
        c2p_r, c2p_w = os.pipe()
        p2c_r, p2c_w = os.pipe()
        stdin_buf = io.BufferedReader(io.FileIO(c2p_r, "rb"))
        stdout_buf = io.BufferedWriter(io.FileIO(p2c_w, "wb"))
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(stdin_buf))
        monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(stdout_buf))
        self.client_w = os.fdopen(c2p_w, "wb")
        self.client_r = os.fdopen(p2c_r, "rb")
        self._rc: dict = {}
        self._thread = threading.Thread(
            target=lambda: self._rc.setdefault("rc", run_proxy(child_argv, self.log, rules)),
            daemon=True,
        )
        self._thread.start()

    def send(self, payload: bytes) -> None:
        self.client_w.write(payload + b"\n")
        self.client_w.flush()

    def send_framed(self, payload: bytes) -> None:
        self.client_w.write(b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        self.client_w.flush()

    def recv_line(self) -> dict:
        line = self.client_r.readline()
        assert line, "EOF waiting for proxy response"
        return json.loads(line.decode())

    def recv_framed(self) -> dict:
        length = None
        while True:
            line = self.client_r.readline()
            assert line, "EOF waiting for framed proxy response"
            if line in (b"\r\n", b"\n"):
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1].strip())
        assert length is not None
        return json.loads(self.client_r.read(length).decode())

    def close(self) -> int:
        self.client_w.close()  # EOF to proxy stdin -> proxy closes child stdin
        self._thread.join(timeout=15)
        assert not self._thread.is_alive(), "run_proxy did not terminate"
        return self._rc["rc"]


def test_proxy_ndjson_tools_call_logged(monkeypatch, tmp_path):
    args = {"path": "/tmp/x"}
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON])
    sess.send(json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}).encode())
    init_resp = sess.recv_line()
    assert init_resp["id"] == 0 and "result" in init_resp
    sess.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": args},
            }
        ).encode()
    )
    resp = sess.recv_line()
    assert resp["id"] == 1
    assert resp["result"]["echo"]["name"] == "read_file"
    assert resp["result"]["echo"]["arguments"] == args
    assert sess.close() == 0
    recs = list(sess.log)
    tool_events = [r for r in recs if r["type"] == "tool_call"]
    assert len(tool_events) == 1, "initialize must pass through without a tool_call event"
    ev = tool_events[0]
    assert ev["tool"]["name"] == "read_file"
    assert ev["tool"]["arguments_digest"] == events.digest(args)
    assert ev["status"] == "ok"
    assert ev["latency_ms"] is not None and ev["latency_ms"] >= 0
    assert ev["result_digest"]
    res = verify(sess.log.path)
    assert res.ok, res.errors


def test_proxy_block_rule(monkeypatch, tmp_path):
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={"type": "tool_call", "tool.name": "shell"},
            action="block",
        )
    ]
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON], rules=rules)
    sess.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "shell", "arguments": {"cmd": "rm -rf /"}},
            }
        ).encode()
    )
    resp = sess.recv_line()
    assert resp["id"] == 1
    assert resp["error"]["code"] == -32000
    assert resp["error"]["message"] == "blocked by aileron rule aileron-001"
    # Child was NOT invoked but is still alive for allowed calls.
    sess.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}},
            }
        ).encode()
    )
    ok = sess.recv_line()
    assert ok["id"] == 2 and "result" in ok
    assert sess.close() == 0
    recs = list(sess.log)
    assert [r["type"] for r in recs] == ["tool_call", "tool_call"]
    blocked = recs[0]
    assert blocked["tool"]["name"] == "shell"
    assert blocked["status"] == "blocked"
    assert blocked["policy"] == {"rule_id": "aileron-001", "action": "block"}
    assert recs[1]["status"] == "ok"
    res = verify(sess.log.path)
    assert res.ok, res.errors


def test_proxy_content_length_framing(monkeypatch, tmp_path):
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_FRAMED])
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "y"}},
        }
    ).encode()
    sess.send_framed(req)
    resp = sess.recv_framed()
    assert resp["id"] == 1
    assert resp["result"]["echo"]["name"] == "read_file"
    assert sess.close() == 0
    recs = [r for r in sess.log if r["type"] == "tool_call"]
    assert len(recs) == 1
    assert recs[0]["status"] == "ok"
    res = verify(sess.log.path)
    assert res.ok, res.errors


def test_proxy_block_content_rule_default_digest_mode(monkeypatch, tmp_path):
    """Content rules must fire on the proxy path with digest-only logging.

    Regression test: policy decisions see the full in-memory arguments even
    when capture_content is False; only digests reach the journal.
    """
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={
                "type": "tool_call",
                "tool.name": "shell",
                "tool.arguments_contains": ["rm -rf"],
            },
            action="block",
        )
    ]
    sess = _ProxySession(
        monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON], rules=rules
    )
    sess.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "shell", "arguments": {"cmd": "rm -rf /tmp/x"}},
            }
        ).encode()
    )
    resp = sess.recv_line()
    assert resp["error"]["code"] == -32000
    assert sess.close() == 0
    recs = list(sess.log)
    assert len(recs) == 1
    assert recs[0]["status"] == "blocked"
    assert recs[0]["policy"]["rule_id"] == "aileron-001"
    # Privacy posture intact: only the digest was persisted.
    assert recs[0]["tool"]["arguments"] is None
    assert recs[0]["tool"]["arguments_digest"]
    assert "rm -rf" not in open(sess.log.path, encoding="utf-8").read()
    res = verify(sess.log.path)
    assert res.ok, res.errors


CHILD_SILENT = (
    "import sys\n"
    "sys.stdin.readline()\n"  # swallow one request, respond to nothing, exit
)


def test_proxy_journals_inflight_call_when_child_never_responds(monkeypatch, tmp_path):
    """A crash mid-call must still leave the attempt in the journal."""
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_SILENT])
    sess.send(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
            }
        ).encode()
    )
    sess.close()
    recs = list(sess.log)
    assert len(recs) == 1
    assert recs[0]["type"] == "tool_call"
    assert recs[0]["tool"]["name"] == "read_file"
    assert recs[0]["status"] == "error"
    assert "no response" in recs[0]["meta"]["error"]
    res = verify(sess.log.path)
    assert res.ok, res.errors


def test_read_message_rejects_duplicate_content_length():
    import io as _io

    from aileron.proxy import _read_message

    # Two Content-Length headers = ambiguous framing; must fail closed.
    wire = b"Content-Length: 2\r\nContent-Length: 9\r\n\r\n{}"
    with pytest.raises(ValueError):
        _read_message(_io.BytesIO(wire))

    # Non-numeric length also rejected.
    with pytest.raises(ValueError):
        _read_message(_io.BytesIO(b"Content-Length: abc\r\n\r\n{}"))

    # A single well-formed framed message still parses.
    payload = b'{"jsonrpc":"2.0"}'
    good = b"Content-Length: %d\r\n\r\n%s" % (len(payload), payload)
    body, _wire = _read_message(_io.BytesIO(good))
    assert json.loads(body) == {"jsonrpc": "2.0"}


def _blocking_rule():
    return [Rule(id="aileron-001", title="Block destructive shell", severity="high",
                 match={"type": "tool_call", "tool.name": "shell",
                        "tool.arguments_contains": ["rm -rf"]},
                 action="block")]


def test_batch_array_cannot_bypass_block(monkeypatch, tmp_path):
    """A JSON-RPC batch must be policed, not forwarded verbatim."""
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON],
                         rules=_blocking_rule())
    sess.send(json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "shell", "arguments": {"cmd": "rm -rf /"}}}]).encode())
    resp = sess.recv_line()
    assert resp["error"]["code"] == -32000
    sess.close()
    recs = list(sess.log)
    assert [r["status"] for r in recs] == ["blocked"]


def test_id_less_tools_call_cannot_bypass_block(monkeypatch, tmp_path):
    """No id still means the child would execute it, so policy must run."""
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON],
                         rules=_blocking_rule())
    sess.send(json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                          "params": {"name": "shell", "arguments": {"cmd": "rm -rf /"}}}).encode())
    sess.close()
    recs = list(sess.log)
    assert len(recs) == 1 and recs[0]["status"] == "blocked"


def test_unparseable_message_is_rejected_not_forwarded(monkeypatch, tmp_path):
    """If we cannot parse it we cannot police it: never pass it through."""
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON],
                         rules=_blocking_rule())
    sess.client_w.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","s":"\xff\xfe"}\n')
    sess.client_w.flush()
    resp = sess.recv_line()
    assert resp["error"]["code"] == -32700
    sess.close()


def test_duplicate_jsonrpc_id_does_not_erase_a_record(monkeypatch, tmp_path):
    """A reused in-flight id must not silently drop the earlier audit event."""
    sess = _ProxySession(monkeypatch, tmp_path, [sys.executable, "-c", CHILD_NDJSON])
    for name in ("sensitive", "cover"):
        sess.send(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                              "params": {"name": name, "arguments": {}}}).encode())
    sess.close()
    names = [r["tool"]["name"] for r in sess.log if r["type"] == "tool_call"]
    assert "sensitive" in names and "cover" in names
    assert verify(sess.log.path).ok


def test_content_length_is_bounded():
    import io as _io

    from aileron.proxy import MAX_MESSAGE_BYTES, _read_message

    huge = str(MAX_MESSAGE_BYTES + 1).encode()
    with pytest.raises(ValueError, match="too large"):
        _read_message(_io.BytesIO(b"Content-Length: " + huge + b"\r\n\r\n{}"))
