"""Tests for aileron.report HTML rendering."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog  # noqa: E402
from aileron.events import new_event  # noqa: E402
from aileron.report import render_html  # noqa: E402


@dataclass
class FakeVerifyResult:
    ok: bool
    count: int
    first_bad_seq: int | None = None
    errors: list[str] = field(default_factory=list)


def _events():
    return [
        {
            "id": "e1",
            "ts": "2024-01-01T00:00:00Z",
            "seq": 1,
            "session_id": "s",
            "agent": {"name": "researcher", "framework": "demo", "version": "1"},
            "type": "agent_start",
            "status": "ok",
            "latency_ms": None,
            "policy": None,
            "meta": {},
            "prev_hash": "0" * 64,
            "hash": "ab" * 32,
        },
        {
            "id": "e2",
            "ts": "2024-01-01T00:00:01Z",
            "seq": 2,
            "session_id": "s",
            "agent": {"name": "researcher", "framework": "demo", "version": "1"},
            "type": "tool_call",
            "tool": {"name": "shell"},
            "status": "blocked",
            "latency_ms": 3.0,
            "policy": {"rule_id": "aileron-001", "action": "block"},
            "meta": {"flags": ["first_seen_tool:shell"]},
            "prev_hash": "ab" * 32,
            "hash": "cd" * 32,
        },
    ]


def test_report_file_exists_with_verified_badge(tmp_path):
    out = tmp_path / "report.html"
    render_html(_events(), FakeVerifyResult(ok=True, count=2), str(out))
    assert out.exists()
    doc = out.read_text(encoding="utf-8")
    assert "VERIFIED 2 events" in doc
    assert "Aileron Incident Report" in doc


def test_report_tampered_badge_shows_seq(tmp_path):
    out = tmp_path / "report.html"
    result = FakeVerifyResult(ok=False, count=2, first_bad_seq=2,
                              errors=["hash mismatch at seq 2"])
    render_html(_events(), result, str(out))
    doc = out.read_text(encoding="utf-8")
    assert "TAMPERED at seq 2" in doc
    assert "VERIFIED" not in doc.split("TAMPERED")[0] or "TAMPERED" in doc
    assert "hash mismatch at seq 2" in doc


def test_report_timeline_columns_and_filter(tmp_path):
    out = tmp_path / "report.html"
    render_html(_events(), FakeVerifyResult(ok=True, count=2), str(out))
    doc = out.read_text(encoding="utf-8")
    for header in ("<th>ts</th>", "<th>seq</th>", "<th>type</th>",
                   "<th>tool</th>", "<th>status</th>", "<th>rule</th>",
                   "<th>hash</th>", "<th>flags</th>"):
        assert header in doc
    # row content
    assert "shell" in doc
    assert "aileron-001" in doc
    assert "cdcdcdcdcdcd" in doc  # hash prefix (12 chars)
    assert "first_seen_tool:shell" in doc
    # client-side vanilla-JS filter, inline CSS, no external assets
    assert "filterRows" in doc
    assert "<style>" in doc
    assert "http://" not in doc and "https://" not in doc
    assert "<script src" not in doc and "link rel" not in doc


def test_report_escapes_html(tmp_path):
    events = _events()
    events[1]["tool"]["name"] = "<b>evil</b>"
    out = tmp_path / "report.html"
    render_html(events, FakeVerifyResult(ok=True, count=2), str(out))
    doc = out.read_text(encoding="utf-8")
    assert "<b>evil</b>" not in doc
    assert "&lt;b&gt;evil&lt;/b&gt;" in doc


def test_report_from_chainlog_roundtrip(tmp_path):
    """Build a small chain via the chainlog API and report on it."""
    log_path = tmp_path / "chain.jsonl"
    log = ChainLog(str(log_path))
    log.append(new_event("agent_start", "s", "researcher", "demo"))
    log.append(new_event("tool_call", "s", "researcher", "demo",
                         tool={"name": "read_file"}, latency_ms=5.0))
    log.append(new_event("agent_end", "s", "researcher", "demo"))
    events = list(log)
    out = tmp_path / "report.html"
    render_html(events, FakeVerifyResult(ok=True, count=len(events)), str(out),
                title="Custom Title")
    doc = out.read_text(encoding="utf-8")
    assert "Custom Title" in doc
    assert f"VERIFIED {len(events)} events" in doc
    assert "read_file" in doc


def test_badge_escapes_verify_result_fields(tmp_path):
    """first_bad_seq/count reach the badge from a tampered journal."""
    class VR:
        ok = False
        count = 0
        first_bad_seq = '<img src=x onerror=alert(1)>'
        errors = []

    out = tmp_path / "r.html"
    render_html([], VR(), str(out))
    doc = out.read_text(encoding="utf-8")
    assert "<img src=x" not in doc
    assert "&lt;img" in doc
