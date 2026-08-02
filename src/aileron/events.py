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


def validate(event: dict) -> list[str]:
    """Return a list of schema error strings for ``event``; ``[]`` if valid."""
    errors: list[str] = []
    if not isinstance(event, dict):
        return ["event is not a dict"]

    missing = EVENT_KEYS - set(event)
    for key in sorted(missing):
        errors.append(f"missing key: {key}")

    if "id" in event:
        if not isinstance(event["id"], str) or not re.fullmatch(
            r"[0-9a-f]{32}", event["id"]
        ):
            errors.append("id must be a 32-char lowercase hex string (uuid4 hex)")

    if "ts" in event:
        ts = event["ts"]
        if not isinstance(ts, str) or not ts.endswith("Z"):
            errors.append("ts must be an RFC3339 UTC string ending in 'Z'")
        else:
            try:
                datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                errors.append("ts is not a valid RFC3339 timestamp")

    if "seq" in event:
        if not isinstance(event["seq"], int) or isinstance(event["seq"], bool):
            errors.append("seq must be an int")
        elif event["seq"] < 0:
            errors.append("seq must be >= 0")

    if "session_id" in event and not isinstance(event["session_id"], str):
        errors.append("session_id must be a string")

    if "agent" in event:
        agent = event["agent"]
        if not isinstance(agent, dict):
            errors.append("agent must be a dict")
        else:
            for key in ("name", "framework", "version"):
                if key not in agent:
                    errors.append(f"agent missing key: {key}")

    if "type" in event and event["type"] not in EVENT_TYPES:
        errors.append(f"type must be one of {sorted(EVENT_TYPES)}")

    if "status" in event and event["status"] not in STATUSES:
        errors.append(f"status must be one of {sorted(STATUSES)}")

    if "latency_ms" in event:
        lat = event["latency_ms"]
        if lat is not None and (
            not isinstance(lat, (int, float)) or isinstance(lat, bool)
        ):
            errors.append("latency_ms must be a number or None")

    if "tool" in event:
        tool = event["tool"]
        if tool is not None:
            if not isinstance(tool, dict):
                errors.append("tool must be a dict or None")
            else:
                if "name" not in tool:
                    errors.append("tool missing key: name")
                elif not isinstance(tool["name"], str):
                    errors.append("tool.name must be a string")
                if "arguments_digest" in tool and tool["arguments_digest"] is not None:
                    if not _HASH_RE.match(str(tool["arguments_digest"])):
                        errors.append("tool.arguments_digest must be a sha256 hex string")

    if "result_digest" in event and event["result_digest"] is not None:
        if not _HASH_RE.match(str(event["result_digest"])):
            errors.append("result_digest must be a sha256 hex string or None")

    if "policy" in event:
        policy = event["policy"]
        if policy is not None:
            if not isinstance(policy, dict):
                errors.append("policy must be a dict or None")
            else:
                for key in ("rule_id", "action"):
                    if key not in policy:
                        errors.append(f"policy missing key: {key}")

    if "meta" in event and not isinstance(event["meta"], dict):
        errors.append("meta must be a dict")

    for key in ("prev_hash", "hash"):
        if key in event:
            if not isinstance(event[key], str) or not _HASH_RE.match(event[key]):
                errors.append(f"{key} must be a 64-char lowercase hex string")

    return errors
