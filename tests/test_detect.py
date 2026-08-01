"""Tests for aileron.detect.Baseline: flag types, flag-before-observe,
JSON persistence roundtrip, and tolerance of missing files."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.detect import Baseline  # noqa: E402


def ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def event(tool: str, t: float, session: str = "s1") -> dict:
    return {
        "type": "tool_call",
        "ts": ts(t),
        "session_id": session,
        "tool": {"name": tool},
    }


# -- first_seen_tool ------------------------------------------------------------


def test_first_seen_tool_flagged_once():
    b = Baseline()
    e = event("shell", 1000)
    assert b.flag(e) == ["first_seen_tool:shell"]
    b.observe(e)
    assert b.flag(event("shell", 1001)) == []


def test_flag_does_not_mutate_state():
    b = Baseline()
    b.flag(event("shell", 1000))
    b.flag(event("shell", 1000))
    # still unseen because observe() was never called
    assert b.flag(event("shell", 1000)) == ["first_seen_tool:shell"]


def test_non_tool_call_events_ignored():
    b = Baseline()
    e = {"type": "llm_call", "ts": ts(1000), "session_id": "s1"}
    assert b.flag(e) == []
    b.observe(e)
    assert b.seen_tools == set()
    assert b.tool_counts == {}


# -- rate_spike -----------------------------------------------------------------


def test_rate_spike_after_min_observations():
    b = Baseline()
    # 5 prior observations spread far apart -> very low baseline rate.
    for t in (0, 1000, 2000, 3000, 4000):
        b.observe(event("shell", t))
    # a burst call now is far above the learned average rate
    assert b.flag(event("shell", 5000)) == ["rate_spike:shell"]


def test_rate_spike_needs_min_observations():
    b = Baseline()
    for t in (0, 1000, 2000, 3000):  # only 4 priors
        b.observe(event("shell", t))
    flags = b.flag(event("shell", 4000))
    assert not any(f.startswith("rate_spike:") for f in flags)


def test_no_spike_at_steady_rate():
    b = Baseline()
    for t in (0, 60, 120, 180, 240):
        b.observe(event("shell", t))
    flags = b.flag(event("shell", 300))
    assert not any(f.startswith("rate_spike:") for f in flags)


def test_rate_spike_is_per_tool():
    b = Baseline()
    for t in (0, 1000, 2000, 3000, 4000):
        b.observe(event("shell", t))
    # other tool has no baseline history -> no rate flag for it
    flags = b.flag(event("browser", 5000))
    assert not any(f.startswith("rate_spike:") for f in flags)


# -- novel_sequence -------------------------------------------------------------


def test_novel_sequence_flagged_then_learned():
    b = Baseline()
    b.observe(event("a", 1000))
    e_b = event("b", 1001)
    b.observe(e_b)  # transition a->b learned
    flags = b.flag(event("c", 1002))
    assert "novel_sequence:b->c" in flags
    b.observe(event("c", 1002))
    # b->c now known, no longer novel
    assert "novel_sequence:b->c" not in b.flag(event("c", 1003))


def test_sequence_is_per_session_and_repeat_not_novel():
    b = Baseline()
    b.observe(event("a", 1000, session="s1"))
    # same tool repeated is not a novel transition
    flags = b.flag(event("a", 1001, session="s1"))
    assert not any(f.startswith("novel_sequence:") for f in flags)
    # different session has no history -> first transition there is not novel
    b.observe(event("x", 1002, session="s2"))
    flags2 = b.flag(event("y", 1003, session="s2"))
    assert "novel_sequence:x->y" in flags2


# -- persistence ------------------------------------------------------------------


def test_persistence_roundtrip(tmp_path):
    path = str(tmp_path / "baseline.json")
    b = Baseline()
    b.observe(event("a", 1000))
    b.observe(event("b", 1001))
    b.observe(event("a", 1002))
    b.path = path
    b.save()

    b2 = Baseline(path)
    assert b2.seen_tools == {"a", "b"}
    assert b2.tool_counts == {"s1": {"a": 2, "b": 1}}
    assert b2.tool_ts["a"] == [1000.0, 1002.0]
    assert b2.last_tool == {"s1": "a"}
    assert b2.transitions == {"a->b", "b->a"}
    # flags behave identically after reload
    assert b2.flag(event("a", 1003)) == []
    assert "novel_sequence:a->c" in b2.flag(event("c", 1003))


def test_load_missing_file_tolerated(tmp_path):
    b = Baseline(str(tmp_path / "does-not-exist.json"))
    assert b.seen_tools == set()
    b.load()  # explicit load also fine


def test_load_corrupt_file_tolerated(tmp_path):
    p = tmp_path / "baseline.json"
    p.write_text("{not json", encoding="utf-8")
    b = Baseline(str(p))
    assert b.seen_tools == set()


def test_save_without_path_is_noop():
    Baseline().save()
