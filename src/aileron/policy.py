"""Sigma-like policy rules for Aileron: load, match, and decide.

Rules are YAML documents with keys: id, title, severity, match (dict of
match clauses), action ('allow' | 'alert' | 'block'). All match clauses are
AND-ed. Supported clause forms:

- ``dotted.key: value``            -- exact equality after dotted lookup
- ``dotted.key_contains: [strs]``  -- case-insensitive substring, any of
- ``dotted.key_regex: pattern``    -- regex search
- ``severity_gte: high``           -- event top-level 'severity' >= level

Dotted lookup traverses nested dicts; a missing key means the clause does
not match. Substring/regex clauses match against the field value itself when
it is a string, otherwise against its canonical JSON serialization.

Note: ``severity_gte`` consults an optional top-level ``severity`` field on
the event. Built-in event producers do not set one, so it is only useful for
custom pipelines that annotate events with their own severity.

Security note: ``key_regex`` patterns are executed with ``re`` and can
backtrack pathologically. Rules are trusted configuration - vet imported
community rules as you would Sigma or Semgrep rules before running them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .events import canonical_json

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

ACTIONS = ("allow", "alert", "block")

_CONTAINS_SUFFIX = "_contains"
_REGEX_SUFFIX = "_regex"
_SEVERITY_GTE = "severity_gte"


@dataclass
class Rule:
    """A single policy rule loaded from YAML."""

    id: str
    title: str
    severity: str
    match: dict
    action: str


@dataclass
class Decision:
    """Outcome of evaluating an event against a rule set."""

    action: str
    rule_ids: list[str] = field(default_factory=list)


def _lookup(event: dict, dotted_key: str) -> tuple[bool, object]:
    """Resolve a dotted key against nested dicts.

    Returns (found, value); found is False when any path segment is missing
    or a non-dict is encountered mid-path.
    """
    current: object = event
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _haystack(value: object) -> str:
    """Text to run substring/regex clauses against."""
    if isinstance(value, str):
        return value
    return canonical_json(value)


def _clause_matches(key: str, clause_value: object, event: dict) -> bool:
    """Evaluate one match clause against the event."""
    if key == _SEVERITY_GTE:
        found, value = _lookup(event, "severity")
        if not found or not isinstance(value, str):
            return False
        if value not in SEVERITY_ORDER or clause_value not in SEVERITY_ORDER:
            return False
        return SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(clause_value)

    if key.endswith(_CONTAINS_SUFFIX):
        found, value = _lookup(event, key[: -len(_CONTAINS_SUFFIX)])
        if not found or value is None:
            return False
        needles = clause_value if isinstance(clause_value, list) else [clause_value]
        hay = _haystack(value).lower()
        return any(isinstance(n, str) and n.lower() in hay for n in needles)

    if key.endswith(_REGEX_SUFFIX):
        found, value = _lookup(event, key[: -len(_REGEX_SUFFIX)])
        if not found or value is None or not isinstance(clause_value, str):
            return False
        try:
            return re.search(clause_value, _haystack(value)) is not None
        except re.error:
            return False

    found, value = _lookup(event, key)
    if not found:
        return False
    return value == clause_value


def matches(rule: Rule, event: dict) -> bool:
    """Return True when every clause of the rule matches the event (AND)."""
    if not rule.match:
        return False
    return all(_clause_matches(key, value, event) for key, value in rule.match.items())


def decide(event: dict, rules: list[Rule]) -> Decision:
    """Evaluate an event against rules.

    The first matching rule with action 'block' wins immediately. Otherwise
    the ids of all matching 'alert' rules are collected (action 'alert' if
    any). Default is 'allow'.
    """
    alert_ids: list[str] = []
    for rule in rules:
        if not matches(rule, event):
            continue
        if rule.action == "block":
            return Decision(action="block", rule_ids=[rule.id])
        if rule.action == "alert":
            alert_ids.append(rule.id)
    if alert_ids:
        return Decision(action="alert", rule_ids=alert_ids)
    return Decision(action="allow", rule_ids=[])


def _validate_rule(data: object, source: Path) -> Rule:
    """Validate a parsed YAML document and build a Rule, or raise ValueError."""
    where = str(source)
    if not isinstance(data, dict):
        raise ValueError(f"rule {where}: top level must be a mapping")
    for required in ("id", "match", "action"):
        if required not in data or data[required] is None:
            raise ValueError(f"rule {where}: missing required key '{required}'")
    if not isinstance(data["id"], str) or not data["id"]:
        raise ValueError(f"rule {where}: 'id' must be a non-empty string")
    if not isinstance(data["match"], dict) or not data["match"]:
        raise ValueError(f"rule {where}: 'match' must be a non-empty mapping")
    severity = data.get("severity", "medium")
    if severity not in SEVERITY_ORDER:
        raise ValueError(
            f"rule {where}: bad severity {severity!r} "
            f"(expected one of {', '.join(SEVERITY_ORDER)})"
        )
    action = data["action"]
    if action not in ACTIONS:
        raise ValueError(
            f"rule {where}: bad action {action!r} (expected one of {', '.join(ACTIONS)})"
        )
    title = data.get("title", "")
    if not isinstance(title, str):
        raise ValueError(f"rule {where}: 'title' must be a string")
    return Rule(
        id=data["id"],
        title=title,
        severity=severity,
        match=dict(data["match"]),
        action=action,
    )


def _load_rule_file(path: Path) -> Rule:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"rule {path}: invalid YAML: {exc}") from exc
    return _validate_rule(data, path)


def load_rules(path: str | Path) -> list[Rule]:
    """Load rules from a single YAML file or a directory of .yml/.yaml files.

    Raises ValueError with a clear message when the path does not exist, a
    file cannot be parsed, or a rule is missing id/match/action or has a bad
    severity/action.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"rules path does not exist: {p}")
    if p.is_dir():
        files = sorted(
            f for f in p.iterdir() if f.suffix.lower() in (".yml", ".yaml") and f.is_file()
        )
        return [_load_rule_file(f) for f in files]
    return [_load_rule_file(p)]
