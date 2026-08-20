"""A read-only MCP server that answers questions about Aileron journals.

Aileron normally sits in front of an MCP server. This is the other direction:
it exposes the recorded journal *as* an MCP server, so an assistant can be
asked "what did the agent touch yesterday?" and read the answer out of the
tamper-evident record instead of a human scrolling an HTML timeline.

READ ONLY, AND DELIBERATELY SO
------------------------------
The agent being recorded is the untrusted party. Handing it a tool that can
edit or delete the journal is handing the suspect the evidence locker. So:

- there is no write, delete, rotate, or sign tool, and there never should be
- every path is resolved and must sit inside the configured root, so an agent
  cannot walk out with ../.. or an absolute path
- only files ending .jsonl can be opened, so this is not a general file reader
- signing keys are never read, listed, or referenced
- errors never echo file contents, so a failed parse cannot be used to read a
  file one message at a time

Run it:

    aileron serve --root ./journals
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, BinaryIO

from aileron import __version__

PROTOCOL_VERSION = "2024-11-05"
MAX_RESULTS = 200

TOOLS = [
    {
        "name": "verify_journal",
        "description": (
            "Check whether an Aileron journal is intact. Returns whether the hash "
            "chain verifies, how many events it holds, and the sequence number of "
            "the first bad event if it was tampered with."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "journal": {"type": "string",
                            "description": "Journal filename, relative to the served root."}
            },
            "required": ["journal"],
        },
    },
    {
        "name": "query_events",
        "description": (
            "Search a journal for recorded tool calls. Filter by tool name, status "
            "(ok, error, blocked), or a time range. Returns the matching events. "
            "Tool arguments appear as digests unless the journal was recorded with "
            "content capture enabled."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "journal": {"type": "string",
                            "description": "Journal filename, relative to the served root."},
                "tool_name": {"type": "string", "description": "Exact tool name to match."},
                "status": {"type": "string", "enum": ["ok", "error", "blocked"]},
                "since": {"type": "string", "description": "RFC3339 lower bound, inclusive."},
                "until": {"type": "string", "description": "RFC3339 upper bound, inclusive."},
                "limit": {"type": "integer",
                          "description": f"Maximum events to return (default 50, max {MAX_RESULTS})."},
            },
            "required": ["journal"],
        },
    },
    {
        "name": "explain_rule",
        "description": (
            "Describe the bundled detection rules: what each one matches, its "
            "severity, and whether it blocks or only alerts. Omit rule_id to list "
            "all of them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "For example aileron-130."}
            },
        },
    },
]


class Denied(Exception):
    """A request that must not be served. The message is safe to return."""


def _resolve(root: Path, name: Any) -> Path:
    """Map a caller-supplied journal name to a real path inside root.

    This is the security boundary of the whole module. Without it,
    verify_journal is an arbitrary file read.
    """
    if not isinstance(name, str) or not name:
        raise Denied("journal must be a non-empty string")
    candidate = (root / name).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        raise Denied("journal must be inside the served root") from None
    if candidate.suffix != ".jsonl":
        raise Denied("only .jsonl journals can be read")
    if not candidate.is_file():
        raise Denied("no such journal")
    return candidate


def _verify_journal(root: Path, args: dict) -> dict:
    from aileron.chainlog import verify

    path = _resolve(root, args.get("journal"))
    result = verify(str(path))
    return {
        "journal": path.name,
        "intact": result.ok,
        "events": result.count,
        "first_bad_seq": result.first_bad_seq,
        "errors": result.errors[:10],
    }


def _query_events(root: Path, args: dict) -> dict:
    from aileron.chainlog import ChainLog

    path = _resolve(root, args.get("journal"))
    limit = args.get("limit", 50)
    if not isinstance(limit, int) or limit < 1:
        limit = 50
    limit = min(limit, MAX_RESULTS)

    tool_name = args.get("tool_name")
    status = args.get("status")
    since, until = args.get("since"), args.get("until")

    matched = []
    for event in ChainLog.read(str(path)):
        if tool_name and (event.get("tool") or {}).get("name") != tool_name:
            continue
        if status and event.get("status") != status:
            continue
        ts = event.get("ts") or ""
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        matched.append({
            "seq": event.get("seq"),
            "ts": ts,
            "type": event.get("type"),
            "tool": (event.get("tool") or {}).get("name"),
            "status": event.get("status"),
            "policy": event.get("policy"),
            "flags": (event.get("meta") or {}).get("flags"),
            "arguments_digest": (event.get("tool") or {}).get("arguments_digest"),
        })
        if len(matched) >= limit:
            break

    return {"journal": path.name, "returned": len(matched),
            "truncated": len(matched) >= limit, "events": matched}


def _explain_rule(_root: Path, args: dict) -> dict:
    from aileron import bundled_rules_dir
    from aileron.policy import load_rules

    rules = load_rules(bundled_rules_dir())
    wanted = args.get("rule_id")
    if wanted:
        rules = [r for r in rules if r.id == wanted]
        if not rules:
            raise Denied(f"no bundled rule with id {wanted}")
    return {
        "rules": [
            {"id": r.id, "title": r.title, "severity": r.severity,
             "action": r.action, "match": r.match}
            for r in rules
        ]
    }


HANDLERS = {
    "verify_journal": _verify_journal,
    "query_events": _query_events,
    "explain_rule": _explain_rule,
}


def _write(out: BinaryIO, message: dict) -> None:
    out.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
    out.flush()


def _handle(root: Path, message: dict) -> dict | None:
    """Return the reply for one request, or None for a notification."""
    method = message.get("method")
    msg_id = message.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "aileron", "version": __version__},
        }}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"no such tool: {name}"}}
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            payload = handler(root, arguments)
        except Denied as exc:
            return {"jsonrpc": "2.0", "id": msg_id, "result": {
                "isError": True,
                "content": [{"type": "text", "text": str(exc)}],
            }}
        except Exception:
            # Never surface the underlying error: a parse or OS error can leak
            # file contents or layout back to a caller that should not have it.
            return {"jsonrpc": "2.0", "id": msg_id, "result": {
                "isError": True,
                "content": [{"type": "text", "text": "the request could not be served"}],
            }}
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        }}

    if msg_id is None:
        return None  # a notification, nothing to answer

    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": f"no such method: {method}"}}


def serve(root: str, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    """Run the read-only journal server over stdio until the client closes."""
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            _write(stdout, {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}})
            continue
        if not isinstance(message, dict):
            continue
        reply = _handle(root_path, message)
        if reply is not None:
            _write(stdout, reply)
    return 0
