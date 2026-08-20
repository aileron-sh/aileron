"""Prove the regex prefilter can never hide a detection.

The prefilter skips a rule's regex when the payload cannot contain anything the
pattern needs. That is a pure speed change, so the only thing worth testing is
that it is a pure speed change. A prefilter that wrongly skips is a rule that
silently stops firing, and nothing else in the suite would notice.

Three layers here:

1. The case folding is proven over every Unicode codepoint, because two obvious
   choices for it are both quietly wrong.
2. Extraction is checked against the real rule pack: every example the pack says
   a rule must catch has to survive the prefilter.
3. A differential fuzz requires identical verdicts with the prefilter on and off.
"""

from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron import bundled_rules_dir  # noqa: E402
from aileron.events import digest, new_event  # noqa: E402
from aileron.policy import decide, load_rules  # noqa: E402
from aileron.prefilter import (  # noqa: E402
    can_skip,
    fold,
    required_literals,
)

EXAMPLES = json.loads((Path(__file__).parent / "rule_examples.json").read_text())
ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz0123456789"


def _event(tool_name, args):
    return new_event(
        "tool_call", "s", "mcp-proxy", "mcp",
        tool={"name": tool_name, "arguments": args, "arguments_digest": digest(args)},
        meta={"transport": "mcp-stdio"},
    )


def _regex_patterns():
    return [v for rule in load_rules(bundled_rules_dir())
            for k, v in rule.match.items() if k.endswith("_regex")]


# --- 1. the folding, proven over all of Unicode ----------------------------


def test_fold_is_sound_over_every_codepoint():
    """Anything re.IGNORECASE calls equal to an ASCII letter must fold to it.

    Folding to *exactly* that one character is the strong form, and it is the
    form we need: it keeps a multi-character literal contiguous. A fold that
    merely contained the character would let U+0130 split "is" apart, because
    it casefolds to "i" plus a combining dot.

    Narrow to candidates with one character class first, otherwise this is a
    hundred million regex calls.
    """
    equivalent_to_ascii = re.compile("[" + re.escape(ASCII_LOWER) + "]", re.IGNORECASE)
    per_char = {c: re.compile(re.escape(c), re.IGNORECASE) for c in ASCII_LOWER}

    violations = []
    for code in range(0x110000):
        char = chr(code)
        if not equivalent_to_ascii.fullmatch(char):
            continue
        for ascii_char in ASCII_LOWER:
            if per_char[ascii_char].fullmatch(char) and fold(char) != ascii_char:
                violations.append((hex(code), ascii_char, fold(char)))

    assert not violations, f"fold() is unsound for: {violations}"


@pytest.mark.parametrize("char, target", [
    ("ı", "i"),  # dotless i, casefold leaves it alone
    ("İ", "i"),  # dotted capital I, casefold expands it to two characters
    ("ſ", "s"),  # long s
    ("K", "k"),  # Kelvin sign
])
def test_the_four_folding_traps(char, target):
    """These are the only non-ASCII codepoints re.IGNORECASE ties to ASCII.

    Named individually so a future change to fold() fails with an obvious
    message rather than only tripping the exhaustive test.
    """
    assert re.search(target, char, re.IGNORECASE), "premise changed"
    assert target in fold(char)


def test_dotted_capital_i_does_not_split_a_literal():
    """The bug that a casefold-only implementation would have shipped."""
    assert re.search("is", "İs", re.IGNORECASE)
    assert "is" not in "İs".casefold()  # why casefold alone is not enough
    assert "is" in fold("İs")


# --- 2. extraction against the real rule pack ------------------------------


def test_every_must_catch_example_survives_the_prefilter():
    """The true-positive check. A skip here is a rule that stopped working."""
    from aileron.events import canonical_json
    from aileron.policy import _lookup

    rules = {r.id: r for r in load_rules(bundled_rules_dir())}
    failures = []
    for case in EXAMPLES:
        rule = rules[case["id"]]
        for tool_name, args in case["positive"]:
            event = _event(tool_name, args)
            for key, pattern in rule.match.items():
                if not key.endswith("_regex"):
                    continue
                # Each clause matches its own path. Feeding a tool.name_regex
                # the arguments text would test nothing real.
                found, value = _lookup(event, key[: -len("_regex")])
                if not found or value is None:
                    continue
                text = value if isinstance(value, str) else canonical_json(value)
                if can_skip(pattern, fold(text)):
                    failures.append((case["id"], key, tool_name, pattern[:50]))
    assert not failures, f"prefilter would skip a rule that must fire: {failures}"


def test_extraction_is_sound_on_the_bundled_patterns():
    """If a pattern matches a string, a required literal must be in it."""
    rng = random.Random(11)
    pieces = ["cat /etc/shadow", "auditctl -D", "history -c", "rm -rf /",
              "ssh -i ~/.ssh/id_rsa host", "curl http://169.254.169.254/",
              "aileron_log=/dev/null", "DROP TABLE users", "shred -u a.log",
              "İ", "ı", "ſ", "K", "ß", "x" * 40, ""]
    for pattern in _regex_patterns():
        literals = required_literals(pattern)
        if literals is None:
            continue
        for _ in range(200):
            text = " ".join(rng.choice(pieces) for _ in range(rng.randint(1, 4)))
            if re.search(pattern, text):
                folded = fold(text)
                assert any(lit in folded for lit in literals), (
                    f"pattern {pattern[:60]!r} matched {text[:60]!r} "
                    f"but none of {sorted(literals)[:6]} are in it")


def test_the_prefilter_actually_does_something():
    """Guard against it quietly degrading into a no-op.

    If a refactor made required_literals always return None the suite would
    still be green and the tool would still be correct, just slow again, which
    is exactly the regression nobody notices.
    """
    patterns = _regex_patterns()
    covered = [p for p in patterns if required_literals(p) is not None]
    assert len(covered) >= 20, (
        f"only {len(covered)} of {len(patterns)} patterns get a prefilter")

    benign = fold(json.dumps({"path": "x" * 4096}))
    skipped = sum(1 for p in covered if can_skip(p, benign))
    assert skipped >= 15, f"only {skipped} patterns skipped on a benign payload"


# --- 3. robustness and differential ---------------------------------------


@pytest.mark.parametrize("bad", [
    "", "(", "[", "(?P<", "*", "(?", "\\", "((((((((((a))))))))))",
    "(a+)+$", "(?i)(?:a|b|", "a" * 5000, "(?(1)a|b)", "\\1(a)",
    None, 42, b"bytes", [], {},
])
def test_never_raises_on_anything(bad):
    """A crash on the enforcement path is worse than a slow one."""
    assert required_literals(bad) is None or isinstance(required_literals(bad), frozenset)
    assert can_skip(bad, "haystack") in (True, False)


def test_soundness_over_generated_patterns():
    """The core property, on patterns nobody wrote by hand.

    For any pattern and any string: if the pattern matches, at least one
    required literal must be in the folded string. The bundled pack only
    exercises the shapes we happened to write, so build patterns out of the
    constructs most likely to break the reasoning, especially the ones that can
    match nothing at all.
    """
    rng = random.Random(99)
    atoms = ["abc", "de", "xyz_1", "(?:foo)?", "bar{0,3}", "(?!no)", "(?=yes)",
             "[a-c]", ".", "\\b", "^", "$", "(alpha|beta)", "(gamma|)",
             "q+", "z*", "(?:pq){2,}", "(?i:MiXeD)", "needle", "(a)(b)\\1"]
    words = ["abc", "de", "xyz_1", "foo", "bar", "alpha", "beta", "gamma",
             "needle", "pqpq", "mixed", "yes", "no", "q", "z", "ab", " ", ""]

    generated = matched = 0
    for _ in range(3000):
        pattern = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 4)))
        if rng.random() < 0.5:
            pattern = "(?i)" + pattern
        literals = required_literals(pattern)
        if literals is None:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        generated += 1
        # Build strings out of the same vocabulary, otherwise almost nothing
        # matches and the test proves nothing.
        for _ in range(30):
            text = "".join(rng.choice(words) for _ in range(rng.randint(1, 6)))
            if rng.random() < 0.25:
                trap = rng.choice(["\u0130", "\u0131", "\u017f", "\u212a"])
                cut = rng.randrange(len(text) + 1)
                text = text[:cut] + trap + text[cut:]
            if compiled.search(text):
                matched += 1
                folded = fold(text)
                assert any(lit in folded for lit in literals), (
                    f"UNSOUND: {pattern!r} matched {text!r} "
                    f"but none of {sorted(literals)} are in {folded!r}")

    assert generated > 200, f"only {generated} patterns got a prefilter"
    assert matched > 200, f"only {matched} matching strings exercised"


def test_prefilter_never_changes_a_verdict():
    """Same events, prefilter on and off, identical decisions."""
    import aileron.prefilter as prefilter_module

    rules = load_rules(bundled_rules_dir())
    real = prefilter_module.can_skip
    rng = random.Random(2026)
    traps = ["İ", "ı", "ſ", "K", "ß"]
    pieces = ["cat /etc/shadow", "auditctl -D", "history -c", "rm -rf /tmp/x",
              "ssh -i ~/.ssh/id_rsa h", "curl http://169.254.169.254/latest/",
              "kubectl get pods", "aileron_log=/dev/null", "git push", ""]

    try:
        for _ in range(500):
            text = " ".join(rng.choice(pieces) for _ in range(rng.randint(1, 3)))
            if rng.random() < 0.4:
                trap = rng.choice(traps)
                cut = rng.randrange(len(text) + 1)
                text = text[:cut] + trap + text[cut:]
            event = _event(rng.choice(["shell", "read_file", "http_request"]),
                           {"command": text, "path": text[::-1]})

            with_pf = decide(event, rules)
            prefilter_module.can_skip = lambda *a, **k: False
            without_pf = decide(event, rules)
            prefilter_module.can_skip = real

            assert with_pf.action == without_pf.action, text
            assert sorted(with_pf.rule_ids) == sorted(without_pf.rule_ids), text
    finally:
        prefilter_module.can_skip = real


def test_the_prefilter_can_be_turned_off(monkeypatch):
    """An operator must be able to rule it out without patching the package."""
    import importlib

    import aileron.prefilter as prefilter_module

    monkeypatch.setenv("AILERON_NO_PREFILTER", "1")
    reloaded = importlib.reload(prefilter_module)
    try:
        assert reloaded.DISABLED is True
        pattern = next(p for p in _regex_patterns()
                       if reloaded.required_literals(p) is not None)
        assert reloaded.can_skip(pattern, "nothing relevant here") is False
    finally:
        monkeypatch.delenv("AILERON_NO_PREFILTER", raising=False)
        importlib.reload(prefilter_module)
        import aileron.policy
        importlib.reload(aileron.policy)


def test_mutation_fuzz_from_known_matching_inputs():
    """The strongest soundness evidence we can get cheaply.

    Random strings almost never match a real detection pattern, so a plain
    fuzz proves little. Start from inputs the pack says DO match, mutate them,
    and check the invariant every time the mutant still matches. That keeps the
    hit rate high and walks the boundary where a pattern stops matching, which
    is exactly where a wrong "required" literal would show up.
    """
    from aileron.events import canonical_json
    from aileron.policy import _lookup

    rules = {r.id: r for r in load_rules(bundled_rules_dir())}
    rng = random.Random(31)
    traps = ["İ", "ı", "ſ", "K", "ß"]
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 -_/.\\|;&"

    def mutate(text):
        if not text:
            return text
        cut = rng.randrange(len(text))
        choice = rng.randrange(6)
        if choice == 0:
            return text[:cut] + rng.choice(alphabet) + text[cut:]
        if choice == 1:
            return text[:cut] + text[cut + 1:]
        if choice == 2:
            return text[:cut] + rng.choice(alphabet) + text[cut + 1:]
        if choice == 3:
            return text[:cut] + rng.choice(traps) + text[cut:]
        if choice == 4:
            return text[:cut] + text[cut].swapcase() + text[cut + 1:]
        return text[:cut] + text[cut].upper() + text[cut:]

    seeds = []
    for case in EXAMPLES:
        rule = rules[case["id"]]
        for tool_name, args in case["positive"]:
            event = _event(tool_name, args)
            for key, pattern in rule.match.items():
                if not key.endswith("_regex"):
                    continue
                found, value = _lookup(event, key[: -len("_regex")])
                if not found or value is None:
                    continue
                text = value if isinstance(value, str) else canonical_json(value)
                seeds.append((pattern, text))

    assert len(seeds) > 100, f"only {len(seeds)} seeds"

    still_matching = 0
    for pattern, text in seeds:
        literals = required_literals(pattern)
        if literals is None:
            continue
        compiled = re.compile(pattern)
        current = text
        for _ in range(60):
            current = mutate(current) if rng.random() < 0.8 else text
            if len(current) > 4000:
                current = text
            if compiled.search(current):
                still_matching += 1
                folded = fold(current)
                assert any(lit in folded for lit in literals), (
                    f"UNSOUND: {pattern[:60]!r} matched {current[:60]!r} "
                    f"but none of {sorted(literals)[:5]} are present")

    assert still_matching > 1000, f"only {still_matching} mutants matched"
