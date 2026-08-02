"""Aileron MCP stdio proxy.

Speaks JSON-RPC 2.0 over stdin/stdout (both newline-delimited JSON and
Content-Length framed messages). Spawns a child MCP server, forwards
client<->child traffic, logs every ``tools/call`` request/response as a
hash-chained ``tool_call`` event, and enforces policy rules: a ``block``
decision returns JSON-RPC error -32000 to the client without invoking the
child and records the event with ``status='blocked'``.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, BinaryIO

from aileron import events
from aileron.policy import decide


def _read_message(stream: BinaryIO) -> tuple[bytes, bytes] | None:
    """Read one JSON-RPC message from stream.

    Returns ``(payload, wire)`` where ``payload`` is the JSON body and ``wire``
    is the exact byte sequence to forward (re-framed identically to how the
    message was received). Returns None on clean EOF.
    """
    first = stream.read(1)
    while first and first.strip() == b"":
        first = stream.read(1)
    if not first:
        return None
    if first in (b"{", b"["):
        # Newline-delimited JSON. readline() reads the remainder of the line in
        # one buffered call; a byte-at-a-time loop here costs one syscall per
        # byte and dominates latency on large tool arguments.
        rest = stream.readline()
        if rest.endswith(b"\n"):
            rest = rest[:-1]  # drop the delimiter, keep any \r (as before)
        payload = bytes(first + rest)
        return payload, payload + b"\n"
    # Content-Length (or similar header) framed message. Headers are
    # line-oriented, so read them a line at a time rather than a byte at a time.
    headers = bytearray(first)
    while True:
        line = stream.readline()
        if not line:
            return None
        headers += line
        if headers.endswith(b"\r\n\r\n") or headers.endswith(b"\n\n"):
            break
    # Reject ambiguous framing: a duplicate or non-numeric Content-Length lets
    # a peer desync the proxy's policy-checked message boundary from the
    # child's (request-smuggling). Fail closed instead — the caller tears the
    # proxy down, which favors enforcement integrity over availability.
    length: int | None = None
    for line in headers.decode("latin-1").replace("\r\n", "\n").split("\n"):
        if line.lower().startswith("content-length:"):
            if length is not None:
                raise ValueError("framed message has multiple Content-Length headers")
            raw = line.split(":", 1)[1].strip()
            if not raw.isdigit():
                raise ValueError(f"invalid Content-Length: {raw!r}")
            length = int(raw)
    if length is None:
        raise ValueError("framed message missing Content-Length header")
    body = bytearray()
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            return None
        body += chunk
    return bytes(body), bytes(headers) + bytes(body)


def _frame(payload: bytes, wire: bytes) -> bytes:
    """Re-frame a locally generated payload the same way ``wire`` was framed."""
    if wire.lstrip()[:1] in (b"{", b"["):
        return payload + b"\n"
    return b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload


def run_proxy(child_argv: list[str], log: Any, rules: list | None = None) -> int:
    """Run the MCP stdio proxy. Returns the child's exit code.

    ``log`` is a ChainLog; ``rules`` is an optional list of policy Rules.
    """
    child = subprocess.Popen(
        child_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    assert child.stdin is not None and child.stdout is not None
    client_in = sys.stdin.buffer
    client_out = sys.stdout.buffer
    session_id = uuid.uuid4().hex
    agent_name = "mcp-proxy"
    framework = "mcp"
    lock = threading.Lock()
    pending: dict[Any, dict[str, Any]] = {}

    def append(ev: dict) -> None:
        with lock:
            log.append(ev)

    def child_to_client() -> None:
        try:
            while True:
                try:
                    got = _read_message(child.stdout)
                except (ValueError, OSError):
                    break
                if got is None:
                    break
                payload, wire = got
                try:
                    msg = json.loads(payload)
                except ValueError:
                    msg = None
                if (
                    isinstance(msg, dict)
                    and msg.get("id") is not None
                    and ("result" in msg or "error" in msg)
                ):
                    with lock:
                        info = pending.pop(msg.get("id"), None)
                    if info is not None:
                        ev = info["event"]
                        ev["latency_ms"] = (
                            time.perf_counter() - info["started"]
                        ) * 1000.0
                        if "error" in msg:
                            ev["status"] = "error"
                            err = msg["error"]
                            # A JSON-RPC error's free-form `data` can echo
                            # result content; honor the digest-only promise
                            # unless content capture is on.
                            if getattr(log, "capture_content", False):
                                recorded = err
                            elif isinstance(err, dict):
                                recorded = {
                                    "code": err.get("code"),
                                    "digest": events.digest(err),
                                }
                            else:
                                recorded = {"digest": events.digest(err)}
                            ev["meta"] = {**ev.get("meta", {}), "error": recorded}
                        else:
                            ev["status"] = "ok"
                            result = msg.get("result")
                            ev["result_digest"] = events.digest(result)
                            if getattr(log, "capture_content", False):
                                ev["result"] = result
                        append(ev)
                try:
                    client_out.write(wire)
                    client_out.flush()
                except (BrokenPipeError, OSError):
                    break
        finally:
            try:
                client_out.flush()
            except OSError:
                pass

    reader = threading.Thread(target=child_to_client, daemon=True)
    reader.start()
    try:
        while True:
            try:
                got = _read_message(client_in)
            except (ValueError, OSError):
                break
            if got is None:
                break
            payload, wire = got
            try:
                msg = json.loads(payload)
            except ValueError:
                msg = None
            if (
                isinstance(msg, dict)
                and msg.get("method") == "tools/call"
                and "id" in msg
            ):
                params = msg.get("params") or {}
                arguments = params.get("arguments")
                # Arguments are always attached in memory so policy rules can
                # match on content; ChainLog.append strips them at persist
                # time unless the log was opened with capture_content=True.
                ev = events.new_event(
                    "tool_call",
                    session_id,
                    agent_name,
                    framework,
                    tool={
                        "name": params.get("name"),
                        "arguments": arguments,
                        "arguments_digest": events.digest(arguments),
                    },
                    meta={"transport": "mcp-stdio"},
                )
                if rules:
                    decision = decide(ev, rules)
                    if decision.action == "block":
                        rule_id = decision.rule_ids[0]
                        ev["status"] = "blocked"
                        ev["policy"] = {"rule_id": rule_id, "action": "block"}
                        append(ev)
                        err = json.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": msg["id"],
                                "error": {
                                    "code": -32000,
                                    "message": f"blocked by aileron rule {rule_id}",
                                },
                            }
                        ).encode()
                        try:
                            client_out.write(_frame(err, wire))
                            client_out.flush()
                        except (BrokenPipeError, OSError):
                            break
                        continue  # child NOT invoked
                    if decision.rule_ids:
                        ev["policy"] = {
                            "rule_id": decision.rule_ids[0],
                            "action": decision.action,
                        }
                with lock:
                    pending[msg["id"]] = {"event": ev, "started": time.perf_counter()}
            try:
                child.stdin.write(wire)
                child.stdin.flush()
            except (BrokenPipeError, OSError):
                break
    finally:
        try:
            child.stdin.close()
        except OSError:
            pass
        returncode = child.wait()
        reader.join(timeout=5.0)
        if reader.is_alive():
            child.kill()
            child.wait()
        # Flight-recorder guarantee: journal in-flight calls that never got a
        # response (child crashed or exited mid-call) instead of dropping them.
        with lock:
            orphaned = list(pending.values())
            pending.clear()
        for info in orphaned:
            ev = info["event"]
            ev["status"] = "error"
            ev["latency_ms"] = (time.perf_counter() - info["started"]) * 1000.0
            ev["meta"] = {
                **ev.get("meta", {}),
                "error": "no response from MCP server before proxy shutdown",
            }
            append(ev)  # lock-guarded: reader thread may still be writing
    return returncode
