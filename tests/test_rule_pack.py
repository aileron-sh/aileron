"""Keep the bundled rule pack honest.

Every shipped rule carries a set of examples in tests/rule_examples.json: tool
calls it must catch, and ordinary work it must ignore. This runs all of them
through the real policy engine.

The second half is the part that matters. A rule that fires on normal work
gets the whole pack switched off by the first user who trips it, so a false
positive is treated as a failure here, not a nuisance.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron import bundled_rules_dir  # noqa: E402
from aileron.events import digest, new_event  # noqa: E402
from aileron.policy import decide, load_rules  # noqa: E402

EXAMPLES = json.loads((Path(__file__).parent / "rule_examples.json").read_text())

# Nested quantifiers can take exponential time on crafted input. Rules run on
# the enforcement path, so a slow rule is a denial of service.
NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*]\)[+*]")


def _event(tool_name, args):
    return new_event(
        "tool_call", "s", "mcp-proxy", "mcp",
        tool={"name": tool_name, "arguments": args, "arguments_digest": digest(args)},
        meta={"transport": "mcp-stdio"},
    )


def _rule_by_id(rule_id):
    for rule in load_rules(bundled_rules_dir()):
        if rule.id == rule_id:
            return rule
    raise AssertionError(f"rule {rule_id} is not in the bundled pack")


def test_the_whole_pack_loads():
    rules = load_rules(bundled_rules_dir())
    assert len(rules) >= 30
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"


@pytest.mark.parametrize("case", EXAMPLES, ids=[c["id"] for c in EXAMPLES])
def test_rule_catches_what_it_should(case):
    rule = _rule_by_id(case["id"])
    for tool_name, args in case["positive"]:
        action = decide(_event(tool_name, args), [rule]).action
        assert action != "allow", (
            f"{case['id']} missed {tool_name} {json.dumps(args)[:90]}"
        )


@pytest.mark.parametrize("case", EXAMPLES, ids=[c["id"] for c in EXAMPLES])
def test_rule_ignores_ordinary_work(case):
    rule = _rule_by_id(case["id"])
    for tool_name, args in case["negative"]:
        action = decide(_event(tool_name, args), [rule]).action
        assert action == "allow", (
            f"{case['id']} fired on ordinary work: {tool_name} {json.dumps(args)[:90]}"
        )


def test_no_rule_uses_a_matcher_that_never_fires():
    """severity_gte reads a field real events do not carry."""
    for rule in load_rules(bundled_rules_dir()):
        assert "severity_gte" not in rule.match, (
            f"{rule.id} uses severity_gte, which silently never matches"
        )


def test_regexes_cannot_backtrack_badly():
    for rule in load_rules(bundled_rules_dir()):
        for key, value in rule.match.items():
            if key.endswith("_regex") and isinstance(value, str):
                assert not NESTED_QUANTIFIER.search(value), (
                    f"{rule.id} has a regex that may backtrack exponentially: {value!r}"
                )
                re.compile(value)  # must be valid


def test_blocking_rules_are_rare_and_deliberate():
    """A wrong block breaks someone's agent, so blocks must stay exceptional."""
    rules = load_rules(bundled_rules_dir())
    blocking = [r.id for r in rules if r.action == "block"]
    assert len(blocking) <= 5, (
        f"too many rules block by default: {blocking}. Prefer alert unless the "
        f"action is almost never legitimate."
    )
