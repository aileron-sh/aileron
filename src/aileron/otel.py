"""OpenTelemetry GenAI-aligned span export for aileron events.

Maps aileron audit events to OTel-style span dicts following the GenAI
semantic conventions (``gen_ai.operation.name``, ``gen_ai.tool.name``,
``gen_ai.agent.name``) plus ``aileron.*`` provenance attributes.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# OTLP proto enum: SPAN_KIND_INTERNAL
_OTLP_KIND_INTERNAL = 1

# aileron event type -> OTel GenAI operation name
_OPERATION = {
    "tool_call": "execute_tool",
    "agent_start": "invoke_agent",
    "agent_end": "invoke_agent",
    "llm_call": "chat",
}


def _ts_to_ns(ts: str | None) -> int:
    """Convert an RFC3339 UTC timestamp to nanoseconds since the epoch.

    Returns 0 on a malformed timestamp so that exporting a tampered log
    degrades gracefully rather than aborting the whole export.
    """
    if not ts:
        return 0
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _EPOCH
    return (
        (delta.days * 86400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000
    )


def _span_name(event: dict) -> str:
    """Span name: 'execute_tool {tool}', 'invoke_agent {agent}', or the event type."""
    etype = event.get("type", "")
    agent = (event.get("agent") or {}).get("name") or "unknown"
    if etype == "tool_call":
        tool = (event.get("tool") or {}).get("name") or "unknown"
        return f"execute_tool {tool}"
    if etype in ("agent_start", "agent_end"):
        return f"invoke_agent {agent}"
    if etype == "llm_call":
        return f"chat {agent}"
    return etype or "event"


def to_otel_spans(events: list[dict]) -> list[dict]:
    """Convert aileron events to OTel-style span dicts.

    One span per event: INTERNAL kind, ``gen_ai.*`` semantic attributes,
    ``aileron.*`` provenance attributes, and start/end times in nanoseconds
    derived from ``ts`` and ``latency_ms``.
    """
    spans: list[dict] = []
    for event in events:
        etype = event.get("type", "")
        agent = (event.get("agent") or {}).get("name")
        tool = (event.get("tool") or {}).get("name")
        policy = event.get("policy") or {}
        meta = event.get("meta") or {}

        attributes: dict[str, Any] = {
            "gen_ai.operation.name": _OPERATION.get(etype, etype),
            "gen_ai.agent.name": agent,
            "aileron.event.id": event.get("id"),
            "aileron.event.type": etype,
            "aileron.event.seq": event.get("seq"),
            "aileron.event.hash": event.get("hash"),
            "aileron.event.prev_hash": event.get("prev_hash"),
            "aileron.session_id": event.get("session_id"),
            "aileron.status": event.get("status"),
        }
        if tool is not None:
            attributes["gen_ai.tool.name"] = tool
        if event.get("latency_ms") is not None:
            attributes["aileron.latency_ms"] = event.get("latency_ms")
        if policy.get("rule_id"):
            attributes["aileron.policy.rule_id"] = policy["rule_id"]
            attributes["aileron.policy.action"] = policy.get("action")
        if meta.get("flags"):
            attributes["aileron.flags"] = list(meta["flags"])

        start_ns = _ts_to_ns(event.get("ts"))
        latency_ms = event.get("latency_ms")
        if isinstance(latency_ms, (int, float)) and math.isfinite(latency_ms) and latency_ms:
            end_ns = start_ns + int(latency_ms * 1_000_000)
        else:
            end_ns = start_ns

        spans.append(
            {
                "name": _span_name(event),
                "kind": "INTERNAL",
                "attributes": attributes,
                "start_time": start_ns,
                "end_time": end_ns,
            }
        )
    return spans


def _any_value(value: Any) -> dict | None:
    """Map a Python value to an OTLP ``AnyValue``; None means 'skip'."""
    if value is None:
        return None
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}  # proto3 JSON: int64 as string
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, (list, tuple)):
        values = [v for v in (_any_value(item) for item in value) if v is not None]
        return {"arrayValue": {"values": values}}
    return {"stringValue": str(value)}


def _kv_list(attributes: dict[str, Any]) -> list[dict]:
    """OTLP ``KeyValue`` list from a plain attribute dict (None values dropped)."""
    out = []
    for key, value in attributes.items():
        any_value = _any_value(value)
        if any_value is not None:
            out.append({"key": key, "value": any_value})
    return out


def _hex_id(seed: str, nbytes: int) -> str:
    """Deterministic OTLP id (hex) derived from a seed string."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[: nbytes * 2]


def to_otlp_spans(events: list[dict]) -> list[dict]:
    """Convert aileron events to OTLP/JSON spans (proto3 JSON mapping).

    ``traceId`` is derived deterministically from the session_id and
    ``spanId`` from the event id, so re-exports are stable and one agent
    session groups into one trace.
    """
    spans = []
    for event, span in zip(events, to_otel_spans(events)):
        spans.append(
            {
                "traceId": _hex_id(f"aileron.session:{event.get('session_id')}", 16),
                "spanId": _hex_id(f"aileron.event:{event.get('id')}", 8),
                "name": span["name"],
                "kind": _OTLP_KIND_INTERNAL,
                "startTimeUnixNano": str(span["start_time"]),
                "endTimeUnixNano": str(span["end_time"]),
                "attributes": _kv_list(span["attributes"]),
                "status": {},
            }
        )
    return spans


def export_json(events: list[dict], out_path: str) -> None:
    """Write events as an OTLP/JSON document to ``out_path``.

    The output is a ``resourceSpans`` envelope in the OTLP proto3 JSON
    mapping (KeyValue attribute lists, hex trace/span ids, nanosecond
    timestamps as strings), suitable for OTLP/HTTP JSON ingestion.
    """
    document = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": _kv_list(
                        {
                            "service.name": "aileron",
                            "telemetry.sdk.name": "aileron",
                        }
                    )
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "aileron.otel", "version": __version__},
                        "spans": to_otlp_spans(events),
                    }
                ],
            }
        ]
    }
    Path(out_path).write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
