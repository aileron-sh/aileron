"""Tests for aileron.otel span conversion and JSON export."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.otel import export_json, to_otel_spans


def _event(**overrides):
    event = {
        "id": "evt-1",
        "ts": "2024-01-01T00:00:00.500Z",
        "seq": 1,
        "session_id": "sess-1",
        "agent": {"name": "researcher", "framework": "demo", "version": "1"},
        "type": "tool_call",
        "tool": {"name": "shell", "arguments_digest": "d" * 64},
        "status": "ok",
        "latency_ms": 250.0,
        "policy": None,
        "meta": {},
        "prev_hash": "0" * 64,
        "hash": "a" * 64,
    }
    event.update(overrides)
    return event


def test_tool_call_span_shape():
    spans = to_otel_spans([_event()])
    assert len(spans) == 1
    span = spans[0]
    assert span["name"] == "execute_tool shell"
    assert span["kind"] == "INTERNAL"
    attrs = span["attributes"]
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["gen_ai.tool.name"] == "shell"
    assert attrs["gen_ai.agent.name"] == "researcher"
    assert attrs["aileron.event.hash"] == "a" * 64
    assert attrs["aileron.status"] == "ok"


def test_agent_spans_use_invoke_agent():
    for etype in ("agent_start", "agent_end"):
        spans = to_otel_spans([_event(type=etype, tool=None, latency_ms=None)])
        assert spans[0]["name"] == "invoke_agent researcher"
        assert spans[0]["attributes"]["gen_ai.operation.name"] == "invoke_agent"
        assert "gen_ai.tool.name" not in spans[0]["attributes"]


def test_timestamps_are_nanoseconds_from_ts_and_latency():
    span = to_otel_spans([_event()])[0]
    # 2024-01-01T00:00:00.500Z == 1704067200.5s
    assert span["start_time"] == 1704067200_500_000_000
    assert span["end_time"] == span["start_time"] + 250_000_000
    # no latency -> end == start
    span2 = to_otel_spans([_event(latency_ms=None)])[0]
    assert span2["end_time"] == span2["start_time"]


def test_policy_and_flags_attributes():
    event = _event(
        status="blocked",
        policy={"rule_id": "aileron-001", "action": "block"},
        meta={"flags": ["first_seen_tool:shell"]},
    )
    attrs = to_otel_spans([event])[0]["attributes"]
    assert attrs["aileron.policy.rule_id"] == "aileron-001"
    assert attrs["aileron.policy.action"] == "block"
    assert attrs["aileron.flags"] == ["first_seen_tool:shell"]
    assert attrs["aileron.status"] == "blocked"


def test_export_json_writes_otlp_document(tmp_path):
    out = tmp_path / "spans.json"
    events = [_event(), _event(id="evt-2", type="agent_end", tool=None,
                               latency_ms=None, seq=2)]
    export_json(events, str(out))
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 2
    assert spans[0]["name"] == "execute_tool shell"
    assert spans[1]["name"] == "invoke_agent researcher"
    # OTLP proto3 JSON mapping: numeric enum, hex ids, nano strings, KeyValue lists.
    assert all(s["kind"] == 1 for s in spans)  # SPAN_KIND_INTERNAL
    for span in spans:
        assert len(span["traceId"]) == 32
        assert len(span["spanId"]) == 16
        assert isinstance(span["startTimeUnixNano"], str)
        assert isinstance(span["attributes"], list)
    # Same session -> same trace; distinct events -> distinct spans.
    assert spans[0]["traceId"] == spans[1]["traceId"]
    assert spans[0]["spanId"] != spans[1]["spanId"]
    attrs = {kv["key"]: kv["value"] for kv in spans[0]["attributes"]}
    assert attrs["gen_ai.tool.name"] == {"stringValue": "shell"}
    assert attrs["aileron.event.seq"] == {"intValue": "1"}
    resource_attrs = {kv["key"]: kv["value"]
                      for kv in doc["resourceSpans"][0]["resource"]["attributes"]}
    assert resource_attrs["service.name"] == {"stringValue": "aileron"}


def test_export_survives_tampered_timestamp_and_nonfinite_latency():
    # Malformed ts degrades to epoch 0 instead of raising.
    bad_ts = _event(ts="not-a-timestamp", latency_ms=None)
    span = to_otel_spans([bad_ts])[0]
    assert span["start_time"] == 0 and span["end_time"] == 0

    # Non-finite latency does not blow up the int() cast.
    inf_lat = _event(latency_ms=float("inf"))
    span2 = to_otel_spans([inf_lat])[0]
    assert span2["end_time"] == span2["start_time"]

    nan_lat = _event(latency_ms=float("nan"))
    span3 = to_otel_spans([nan_lat])[0]
    assert span3["end_time"] == span3["start_time"]
