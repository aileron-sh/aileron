"""Tests for aileron.policy: matchers, AND semantics, decide, load_rules."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.policy import (  # noqa: E402
    SEVERITY_ORDER,
    Decision,
    Rule,
    decide,
    load_rules,
    matches,
)


def make_event(**overrides) -> dict:
    event = {
        "id": "0" * 32,
        "ts": "2025-01-01T00:00:00Z",
        "seq": 1,
        "session_id": "s1",
        "agent": {"name": "agent", "framework": "test", "version": "0.1"},
        "type": "tool_call",
        "tool": {"name": "shell", "arguments": {"cmd": "rm -rf /tmp/x"}},
        "status": "ok",
        "latency_ms": 12,
        "meta": {},
    }
    for key, value in overrides.items():
        if "." in key:
            top, sub = key.split(".", 1)
            event.setdefault(top, {})[sub] = value
        else:
            event[key] = value
    return event


def rule(match: dict, action: str = "block", severity: str = "high", rid: str = "r1") -> Rule:
    return Rule(id=rid, title="t", severity=severity, match=match, action=action)


# -- matchers ---------------------------------------------------------------


def test_dotted_key_equality_matches_nested():
    r = rule({"type": "tool_call", "tool.name": "shell"})
    assert matches(r, make_event())


def test_dotted_key_equality_mismatch():
    r = rule({"tool.name": "browser"})
    assert not matches(r, make_event())


def test_missing_key_means_no_match():
    r = rule({"tool.arguments.cmd.sub": "x"})
    assert not matches(r, make_event())
    r2 = rule({"nonexistent.key": "x"})
    assert not matches(r2, make_event())


def test_contains_case_insensitive_substring():
    r = rule({"tool.arguments_contains": ["RM -RF"]})
    assert matches(r, make_event())


def test_contains_against_canonical_serialized_dict():
    # 'rm -rf' is found inside the canonical JSON of the arguments dict.
    r = rule({"tool.arguments_contains": ['"cmd":"rm -rf /tmp/x"']})
    assert matches(r, make_event())


def test_contains_any_of_list_and_no_match():
    r = rule({"tool.arguments_contains": ["DROP TABLE", "rm -rf"]})
    assert matches(r, make_event())
    r2 = rule({"tool.arguments_contains": ["DROP TABLE", "mkfs"]})
    assert not matches(r2, make_event())


def test_regex_matcher():
    r = rule({"tool.arguments_regex": r"rm\s+-[rf]+\s+/"})
    assert matches(r, make_event())
    r2 = rule({"tool.arguments_regex": r"^curl"})
    assert not matches(r2, make_event())


def test_regex_on_string_field_directly():
    r = rule({"tool.name_regex": r"^sh"})
    assert matches(r, make_event())


def test_severity_gte():
    r = rule({"severity_gte": "high"})
    assert matches(r, make_event(severity="critical"))
    assert matches(r, make_event(severity="high"))
    assert not matches(r, make_event(severity="low"))
    # missing severity key -> clause does not match
    assert not matches(r, make_event())


def test_severity_order_constant():
    assert SEVERITY_ORDER == ["low", "medium", "high", "critical"]


# -- AND semantics ------------------------------------------------------------


def test_all_clauses_anded():
    r = rule({"type": "tool_call", "tool.name": "shell", "tool.arguments_contains": ["rm -rf"]})
    assert matches(r, make_event())
    # one failing clause kills the match
    r_fail = rule(
        {"type": "tool_call", "tool.name": "shell", "tool.arguments_contains": ["DROP TABLE"]}
    )
    assert not matches(r_fail, make_event())
    r_fail2 = rule({"type": "llm_call", "tool.name": "shell"})
    assert not matches(r_fail2, make_event())


# -- decide -------------------------------------------------------------------


def test_decide_first_block_wins():
    rules = [
        rule({"tool.name": "shell"}, action="alert", rid="a1"),
        rule({"tool.name": "shell"}, action="block", rid="b1"),
        rule({"tool.name": "shell"}, action="block", rid="b2"),
    ]
    d = decide(make_event(), rules)
    assert d == Decision(action="block", rule_ids=["b1"])


def test_decide_alert_beats_allow_and_collects_ids():
    rules = [
        rule({"tool.name": "nomatch"}, action="alert", rid="a0"),
        rule({"tool.name": "shell"}, action="alert", rid="a1"),
        rule({"tool.name": "shell"}, action="alert", rid="a2"),
        rule({"tool.name": "shell"}, action="allow", rid="ok"),
    ]
    d = decide(make_event(), rules)
    assert d.action == "alert"
    assert d.rule_ids == ["a1", "a2"]


def test_decide_default_allow():
    d = decide(make_event(), [rule({"tool.name": "browser"}, action="block")])
    assert d == Decision(action="allow", rule_ids=[])
    assert decide(make_event(), []).action == "allow"


# -- load_rules ---------------------------------------------------------------


def test_load_rules_single_file(tmp_path):
    f = tmp_path / "r.yml"
    f.write_text(
        "id: x\ntitle: t\nseverity: low\nmatch:\n  type: tool_call\naction: alert\n",
        encoding="utf-8",
    )
    rules = load_rules(f)
    assert len(rules) == 1
    assert rules[0].id == "x"
    assert rules[0].severity == "low"
    assert rules[0].match == {"type": "tool_call"}
    assert rules[0].action == "alert"


def test_load_rules_directory_skips_non_yaml(tmp_path):
    (tmp_path / "b.yml").write_text(
        "id: b\nseverity: high\nmatch:\n  type: tool_call\naction: block\n", encoding="utf-8"
    )
    (tmp_path / "a.yaml").write_text(
        "id: a\nseverity: low\nmatch:\n  type: llm_call\naction: alert\n", encoding="utf-8"
    )
    (tmp_path / "note.md").write_text("not a rule", encoding="utf-8")
    rules = load_rules(tmp_path)
    assert [r.id for r in rules] == ["a", "b"]  # sorted by filename


@pytest.mark.parametrize(
    "body,msg",
    [
        ("title: t\nseverity: high\nmatch:\n  type: x\naction: block\n", "id"),
        ("id: x\nseverity: high\naction: block\n", "match"),
        ("id: x\nseverity: high\nmatch:\n  type: x\n", "action"),
        ("id: x\nseverity: extreme\nmatch:\n  type: x\naction: block\n", "severity"),
        ("id: x\nseverity: high\nmatch:\n  type: x\naction: deny\n", "action"),
        ("- just\n- a\n- list\n", "mapping"),
    ],
)
def test_load_rules_error_cases(tmp_path, body, msg):
    f = tmp_path / "bad.yml"
    f.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match=msg):
        load_rules(f)


def test_load_rules_missing_path(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        load_rules(tmp_path / "nope")


def test_load_rules_invalid_yaml(tmp_path):
    f = tmp_path / "bad.yml"
    f.write_text("id: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML"):
        load_rules(f)


# -- bundled example rules ----------------------------------------------------


def test_example_rules_are_wellformed_and_functional():
    from aileron import bundled_rules_dir

    rules = load_rules(bundled_rules_dir())
    # The pack grows over time; these two are the originals and must stay.
    # tests/test_rule_pack.py checks each rule against its own examples.
    assert {"aileron-001", "aileron-002"} <= {r.id for r in rules}

    destructive = make_event(**{"tool.arguments": {"cmd": "rm -rf / --no-preserve-root"}})
    d = decide(destructive, rules)
    assert d.action == "block"
    assert "aileron-001" in d.rule_ids

    exfil = make_event(**{"tool.name": "read_file", "tool.arguments": {"path": "~/.ssh/id_rsa"}})
    d2 = decide(exfil, rules)
    assert d2.action == "alert"
    assert "aileron-002" in d2.rule_ids

    benign = make_event(**{"tool.arguments": {"cmd": "ls -la"}})
    assert decide(benign, rules).action == "allow"
