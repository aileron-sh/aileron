import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.events import EVENT_TYPES, canonical, digest, event_hash, new_event, validate


def test_event_types_exact():
    assert EVENT_TYPES == {
        "tool_call",
        "llm_call",
        "agent_start",
        "agent_end",
        "policy_decision",
        "alert",
    }


def test_new_event_defaults():
    ev = new_event("tool_call", "sess-1", "bot", "langchain")
    assert ev["seq"] == 0
    assert ev["status"] == "ok"
    assert ev["latency_ms"] is None
    assert ev["session_id"] == "sess-1"
    assert ev["agent"] == {"name": "bot", "framework": "langchain", "version": None}
    assert ev["type"] == "tool_call"
    assert ev["tool"] is None
    assert ev["result"] is None
    assert ev["result_digest"] is None
    assert ev["policy"] is None
    assert ev["meta"] == {}
    assert ev["prev_hash"] == "0" * 64
    assert ev["hash"] == "0" * 64
    assert len(ev["id"]) == 32
    assert ev["ts"].endswith("Z")
    assert validate(ev) == []


def test_new_event_field_overrides_and_digest_autofill():
    ev = new_event(
        "tool_call",
        "s",
        "bot",
        "fw",
        tool={"name": "shell", "arguments": {"cmd": "ls"}},
        result={"out": "ok"},
        status="error",
        latency_ms=12.5,
    )
    assert ev["tool"]["arguments_digest"] == digest({"cmd": "ls"})
    assert ev["result_digest"] == digest({"out": "ok"})
    assert ev["status"] == "error"
    assert ev["latency_ms"] == 12.5
    assert validate(ev) == []


def test_canonical_excludes_hash_and_is_sorted():
    ev = new_event("alert", "s", "bot", "fw")
    canon = canonical(ev)
    assert "hash" not in json.loads(canon)
    obj = json.loads(canon)
    keys = list(obj.keys())
    assert keys == sorted(keys)
    assert canon == json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    # hash value must not affect canonical form
    ev2 = dict(ev, hash="f" * 64)
    assert canonical(ev2) == canon


def test_event_hash_determinism():
    ev = new_event("agent_start", "s", "bot", "fw", meta={"x": [1, 2, {"y": "z"}]})
    assert event_hash(ev) == event_hash(dict(ev))
    expected = hashlib.sha256(canonical(ev).encode("utf-8")).hexdigest()
    assert event_hash(ev) == expected
    # non-ASCII is not escaped
    ev["meta"]["x"] = "héllo"
    assert "héllo" in canonical(ev)


def test_digest_is_canonical():
    assert digest({"b": 1, "a": 2}) == digest({"a": 2, "b": 1})
    assert digest({}) == hashlib.sha256(b"{}").hexdigest()


def test_validate_catches_errors():
    ev = new_event("tool_call", "s", "bot", "fw")
    assert validate(ev) == []

    bad = dict(ev, type="nope")
    assert any("type" in e for e in validate(bad))

    bad = dict(ev, status="weird")
    assert any("status" in e for e in validate(bad))

    bad = dict(ev, seq=-1)
    assert any("seq" in e for e in validate(bad))

    bad = dict(ev, prev_hash="zz")
    assert any("prev_hash" in e for e in validate(bad))

    bad = dict(ev, latency_ms="soon")
    assert any("latency_ms" in e for e in validate(bad))

    bad = dict(ev, agent={"name": "bot"})
    assert any("agent" in e for e in validate(bad))

    bad = {k: v for k, v in ev.items() if k != "session_id"}
    assert any("session_id" in e for e in validate(bad))

    assert validate("not a dict") == ["event is not a dict"]
