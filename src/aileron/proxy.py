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
import re
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, BinaryIO

# RFC 7230 field-name followed by a colon. Header lines must look like headers.
_HEADER_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+:")

from aileron import events
from aileron.policy import decide

# Refuse absurd frames rather than allocating for them: the proxy is the
# enforcement point, so exhausting it is a way to stop mediation.
MAX_MESSAGE_BYTES = 64 * 1024 * 1024

# Cap on in-flight calls awaiting a response. Far above any real client's
# window; prevents a peer that never reads responses from growing `pending`
# without bound.
MAX_PENDING = 4096

# How long to wait for the child to exit before killing it, so the shutdown
# drain that journals in-flight calls always runs.
CHILD_EXIT_TIMEOUT = 5.0

# Sentinel: the message could not be parsed, so it must not be forwarded.
_UNPARSEABLE = object()


def _canonical_wire(msg: Any) -> bytes:
    """Re-serialize a parsed JSON-RPC message to compact, newline-free bytes.

    Compact separators mean no insignificant whitespace, and json.dumps escapes
    any newline inside a string, so the result can never be re-split into more
    messages than the one that was policed.
    """
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _respond_raw(client_out: BinaryIO, wire: bytes, obj: Any) -> None:
    """Send a locally generated JSON-RPC reply (object or batch), framed like
    the request."""
    try:
        client_out.write(_frame(_canonical_wire(obj), wire))
        client_out.flush()
    except (BrokenPipeError, OSError):
        pass


def _respond(client_out: BinaryIO, wire: bytes, obj: dict) -> None:
    """Send a locally generated JSON-RPC reply, framed like the request."""
    _respond_raw(client_out, wire, obj)


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
        # byte and dominates latency on large tool arguments. The cap is the
        # same one the framed path enforces — neither peer may drive us to
        # buffer without bound.
        rest = stream.readline(MAX_MESSAGE_BYTES)
        if not rest.endswith(b"\n") and len(rest) >= MAX_MESSAGE_BYTES - 1:
            raise ValueError("newline-delimited message too large")
        if rest.endswith(b"\n"):
            rest = rest[:-1]  # drop the delimiter, keep any \r (as before)
        payload = bytes(first + rest)
        return payload, payload + b"\n"
    # Content-Length (or similar header) framed message. Headers are
    # line-oriented, so read them a line at a time rather than a byte at a time.
    headers = bytearray(first)
    while True:
        line = stream.readline(MAX_MESSAGE_BYTES)
        if not line:
            return None
        headers += line
        if len(headers) > MAX_MESSAGE_BYTES:
            raise ValueError("header block too large")
        # Only genuine headers may appear here. Anything else is an attempt to
        # park extra JSON-RPC traffic in the header block, where it would be
        # invisible to policy but still reach a newline-delimited child.
        if line not in (b"\r\n", b"\n") and not _HEADER_RE.match(line):
            raise ValueError(f"malformed header line: {bytes(line[:40])!r}")
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
    if length > MAX_MESSAGE_BYTES:
        raise ValueError(f"Content-Length too large: {length}")
    body = bytearray()
    while len(body) < length:
        # Read in bounded chunks so a large declared length cannot be
        # pre-allocated in one shot.
        chunk = stream.read(min(65536, length - len(body)))
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
    # Set when recording breaks: a flight recorder that cannot record must
    # stop mediating rather than let calls through unlogged.
    record_failed = threading.Event()

    def append(ev: dict) -> None:
        with lock:
            log.append(ev)

    def child_to_client() -> None:
        try:
            while True:
                try:
                    got = _read_message(child.stdout)
                except (ValueError, OSError) as exc:
                    # A framing error from the child ends response recording.
                    # Say so and stop mediating rather than exiting quietly.
                    print(f"aileron: child framing error, recording stopped: {exc}",
                          file=sys.stderr, flush=True)
                    record_failed.set()
                    break
                if got is None:
                    break
                payload, wire = got
                try:
                    msg = json.loads(payload)
                except Exception:
                    msg = None
                # A response id must be usable as a dict key; an untrusted
                # child could send a list/dict here and take the thread down.
                if (
                    isinstance(msg, dict)
                    and isinstance(msg.get("id"), (str, int, float))
                    and not isinstance(msg.get("id"), bool)
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
                        try:
                            append(ev)
                        except Exception as exc:
                            # A journal write that fails must not silently kill
                            # this thread and leave the child executing calls
                            # unrecorded. Surface it and stop mediating.
                            print(f"aileron: journal write failed: {exc}",
                                  file=sys.stderr, flush=True)
                            record_failed.set()
                            break
                try:
                    # Re-serialize the child's response too: a malicious server
                    # must not be able to smuggle extra frames past us to the
                    # client any more than the client can to it.
                    out = _canonical_wire(msg) if msg is not None else payload
                    client_out.write(_frame(out, wire))
                    client_out.flush()
                except (BrokenPipeError, OSError):
                    break
        except Exception as exc:  # never die silently: this thread records evidence
            print(f"aileron: reader thread aborted: {exc}", file=sys.stderr, flush=True)
            record_failed.set()
        finally:
            try:
                client_out.flush()
            except OSError:
                pass

    reader = threading.Thread(target=child_to_client, daemon=True)
    reader.start()
    try:
        while True:
            if record_failed.is_set():
                break  # recording is broken; stop forwarding tool calls
            try:
                got = _read_message(client_in)
            except (ValueError, OSError):
                break
            if got is None:
                break
            payload, wire = got
            try:
                msg = json.loads(payload)
            except Exception:
                # Fail closed. If we cannot parse it we cannot police it, and
                # the child's parser may well accept what ours rejected — that
                # difference alone would be a policy bypass. Never forward.
                msg = _UNPARSEABLE
            if msg is _UNPARSEABLE:
                _respond(
                    client_out, wire,
                    {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "parse error (rejected by aileron)"}},
                )
                continue

            # A message may carry one call (dict) or several (JSON-RPC batch
            # array). Police every tools/call in it, whether or not it has an
            # id: the child dispatches on `method`, so an id-less call executes
            # just the same.
            calls = [m for m in (msg if isinstance(msg, list) else [msg])
                     if isinstance(m, dict) and m.get("method") == "tools/call"]

            blocked_rule: str | None = None
            blocked_id: Any = None
            staged: list[tuple[Any, dict]] = []
            for call in calls:
                # params may legally be an array (positional) or, from a hostile
                # client, any JSON type. Never assume it is a mapping.
                raw_params = call.get("params")
                params = raw_params if isinstance(raw_params, dict) else {}
                arguments = params.get("arguments")
                if arguments is None and raw_params is not None and not isinstance(
                    raw_params, dict
                ):
                    arguments = raw_params  # keep it auditable and policy-visible
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
                        blocked_rule = decision.rule_ids[0]
                        blocked_id = call.get("id")
                        ev["status"] = "blocked"
                        ev["policy"] = {"rule_id": blocked_rule, "action": "block"}
                        append(ev)
                        break  # whole message is refused; see below
                    if decision.rule_ids:
                        ev["policy"] = {
                            "rule_id": decision.rule_ids[0],
                            "action": decision.action,
                        }
                staged.append((call.get("id"), ev))

            if blocked_rule is not None:
                # Refuse the entire message rather than forwarding a partial
                # batch: the child must not see any of it. Attribute the denial
                # to the call that actually matched, and answer the others so no
                # request in a batch is left hanging.
                denial = {"jsonrpc": "2.0", "id": blocked_id,
                          "error": {"code": -32000,
                                    "message": f"blocked by aileron rule {blocked_rule}"}}
                if isinstance(msg, list):
                    others = [
                        {"jsonrpc": "2.0", "id": c.get("id"),
                         "error": {"code": -32000,
                                   "message": "refused: batch contained a blocked call"}}
                        for c in calls if c.get("id") != blocked_id
                    ]
                    _respond_raw(client_out, wire, [denial] + others)
                else:
                    _respond(client_out, wire, denial)
                continue  # child NOT invoked

            for call_id, ev in staged:
                if call_id is None:
                    # No id means no response will come back to complete this
                    # event, so journal it now rather than losing it.
                    ev["meta"] = {**ev.get("meta", {}), "notification": True}
                    append(ev)
                    continue
                with lock:
                    if len(pending) >= MAX_PENDING and call_id not in pending:
                        # Fail closed: refuse rather than grow without bound.
                        ev["status"] = "blocked"
                        ev["policy"] = {"rule_id": "aileron-pending-limit",
                                        "action": "block"}
                        log.append(ev)
                        continue
                    prior = pending.get(call_id)
                    if prior is not None:
                        # A reused in-flight id would silently displace the
                        # earlier record; journal it before it is overwritten.
                        displaced = prior["event"]
                        displaced["status"] = "error"
                        displaced["meta"] = {
                            **displaced.get("meta", {}),
                            "error": "superseded by duplicate JSON-RPC id",
                        }
                        log.append(displaced)
                    pending[call_id] = {"event": ev, "started": time.perf_counter()}
            if record_failed.is_set():
                # Recording broke while we were policing this call. Refuse it
                # rather than let it through unrecorded.
                _respond(client_out, wire,
                         {"jsonrpc": "2.0", "id": calls[0].get("id") if calls else None,
                          "error": {"code": -32000,
                                    "message": "aileron: recording unavailable, call refused"}})
                break
            try:
                # Forward a re-serialization of exactly what policy saw, never
                # the peer's raw bytes. Verbatim forwarding lets the child
                # re-split the stream differently than we parsed it (extra
                # JSON-RPC parked in a header block, or raw newlines inside a
                # Content-Length body), executing calls policy never inspected.
                child.stdin.write(_frame(_canonical_wire(msg), wire))
                child.stdin.flush()
            except (BrokenPipeError, OSError):
                break
    finally:
        try:
            child.stdin.close()
        except OSError:
            pass
        # Bound the wait: a child that never exits must not strand the in-flight
        # calls that the drain below is responsible for journaling.
        try:
            returncode = child.wait(timeout=CHILD_EXIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            child.kill()
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
