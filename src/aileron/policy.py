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

from . import prefilter
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


def _haystack(
    event: dict,
    path: str,
    cache: dict | None,
    *,
    form: str = "raw",
) -> tuple[bool, str]:
    """Resolve a dotted path and render it as searchable text, memoized.

    Returns (found, text); found is False when the path is missing or None,
    in which case the text is empty and no clause should match.

    The cache is why this takes an event and a path rather than a value. A
    rule pack asks the same few paths over and over - 41 clauses across the
    32 bundled rules match on tool arguments - and rendering an arguments
    dict to canonical JSON is proportional to its size. Doing that once per
    rule made proxy overhead scale with rule count times payload size: 24 ms
    on a 32 KB call, against 0.6 ms when only two rules shipped. Rendering
    once per distinct path drops the rule count out of the cost entirely.

    The cache is created per decide() call and never outlives the event it
    describes, so it cannot serve one event's text for another. Callers may
    pass None, which simply computes every time.
    """
    key = (path, form)
    if cache is not None:
        hit = cache.get(key)
        if hit is not None:
            return hit

    if form == "lower":
        found, text = _haystack(event, path, cache)
        entry = (found, text.lower())
    elif form == "fold":
        # Only used to decide whether a regex can be skipped; see prefilter.
        found, text = _haystack(event, path, cache)
        entry = (found, prefilter.fold(text))
    else:
        found, value = _lookup(event, path)
        if not found or value is None:
            entry = (False, "")
        elif isinstance(value, str):
            entry = (True, value)
        else:
            entry = (True, canonical_json(value))

    if cache is not None:
        cache[key] = entry
    return entry


# One matcher per kind of clause.
#
# A rule clause is a key and a value, and the key's suffix decides how to
# compare them: `tool.name` is equality, `tool.arguments_contains` is substring,
# `tool.arguments_regex` is a pattern, `severity_gte` is an ordering. That used
# to be one function with four branches sharing local state. Splitting it means
# each comparison can be read, and tested, on its own.
#
# Every matcher has the same shape: given the resolved path, the value written
# in the rule, the event, and the per-event memo, does this clause hold. None of
# them raise: a clause that cannot be evaluated is a clause that does not match,
# because a rule engine that throws on a malformed rule stops the proxy.


def _memo(cache: dict | None, kind: str, path: str) -> dict | None:
    """Per-event scratch space for "did we already look for this text".

    Rules share needles and literals, and scanning a large payload is not free,
    so each distinct string is looked for once per event rather than once per
    rule. Returns None when there is no cache, which simply means look every
    time.
    """
    if cache is None:
        return None
    return cache.setdefault((kind, path), {})


def _match_severity_gte(_path: str, clause_value: object, event: dict,
                        _cache: dict | None) -> bool:
    """Event severity is at least the level the rule names."""
    found, value = _lookup(event, "severity")
    if not found or not isinstance(value, str):
        return False
    if value not in SEVERITY_ORDER or clause_value not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(clause_value)


def _match_contains(path: str, clause_value: object, event: dict,
                    cache: dict | None) -> bool:
    """Any one of the rule's needles appears in the text at ``path``."""
    found, hay = _haystack(event, path, cache, form="lower")
    if not found:
        return False
    needles = clause_value if isinstance(clause_value, list) else [clause_value]
    seen = _memo(cache, "needles", path)
    for needle in needles:
        if not isinstance(needle, str):
            continue
        if seen is None:
            if needle.lower() in hay:
                return True
            continue
        hit = seen.get(needle)
        if hit is None:
            hit = needle.lower() in hay
            seen[needle] = hit
        if hit:
            return True
    return False


def _match_regex(path: str, clause_value: object, event: dict,
                 cache: dict | None) -> bool:
    """The rule's pattern matches the text at ``path``."""
    if not isinstance(clause_value, str):
        return False
    found, hay = _haystack(event, path, cache)
    if not found:
        return False

    # Most calls cannot possibly match most rules. Asking the cheap question
    # first turns roughly twenty full scans of the payload into a handful of
    # substring searches. can_skip only says yes when it has proven the pattern
    # cannot match, so this changes speed, not verdicts.
    _, folded = _haystack(event, path, cache, form="fold")
    if prefilter.can_skip(clause_value, folded, _memo(cache, "literals", path)):
        return False

    try:
        return re.search(clause_value, hay) is not None
    except re.error:
        # A rule that does not compile matches nothing rather than taking the
        # enforcement path down with it.
        return False


def _match_equals(path: str, clause_value: object, event: dict,
                  _cache: dict | None) -> bool:
    """The value at ``path`` equals what the rule says."""
    found, value = _lookup(event, path)
    return found and value == clause_value


def _matcher_for(key: str):
    """Pick the comparison for a clause key, and the path it reads.

    Suffixes are checked before falling back to equality, so `foo_contains`
    is a substring clause on `foo` rather than an equality clause on a field
    literally named `foo_contains`.
    """
    if key == _SEVERITY_GTE:
        return _match_severity_gte, "severity"
    if key.endswith(_CONTAINS_SUFFIX):
        return _match_contains, key[: -len(_CONTAINS_SUFFIX)]
    if key.endswith(_REGEX_SUFFIX):
        return _match_regex, key[: -len(_REGEX_SUFFIX)]
    return _match_equals, key


def _clause_matches(
    key: str,
    clause_value: object,
    event: dict,
    cache: dict | None = None,
) -> bool:
    """Evaluate one match clause against the event."""
    matcher, path = _matcher_for(key)
    return matcher(path, clause_value, event, cache)


def matches(rule: Rule, event: dict, cache: dict | None = None) -> bool:
    """Return True when every clause of the rule matches the event (AND).

    ``cache`` is an optional per-event memo shared across rules; see
    ``_haystack``. It is purely an optimization and never changes a verdict.
    """
    if not rule.match:
        return False
    return all(
        _clause_matches(key, value, event, cache) for key, value in rule.match.items()
    )


def decide(event: dict, rules: list[Rule]) -> Decision:
    """Evaluate an event against rules.

    The first matching rule with action 'block' wins immediately. Otherwise
    the ids of all matching 'alert' rules are collected (action 'alert' if
    any). Default is 'allow'.
    """
    alert_ids: list[str] = []
    # Shared across every rule in this call, discarded when it returns. Without
    # it, each rule re-renders the same arguments to text.
    cache: dict = {}
    for rule in rules:
        if not matches(rule, event, cache):
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
