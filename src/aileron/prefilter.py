"""Skip a rule's regex when the payload cannot possibly match it.

Content rules are matched against the whole tool payload. With the bundled
pack that meant roughly twenty regexes scanning every byte of every call, and
23 ms of it on a 32 KB argument. Almost all of that work is wasted: a rule
looking for ``auditctl`` cannot match a payload that does not contain the text
``auditctl`` anywhere.

So before running a pattern we ask a cheaper question. Every pattern is read
once and reduced to a set of literal strings with this property: **if the
pattern can match a string at all, at least one of those literals appears in
it.** A substring search is far cheaper than a backtracking regex scan, so
when none of the literals are present we skip the regex entirely.

The whole module is one safety argument, so it is worth being blunt about it.

**Skipping a regex that would have matched is a missed detection.** That is
the worst bug this project can ship, and it would be invisible: the rule
simply never fires and the journal looks clean. Running a regex that could not
have matched only costs time. So every decision here is deliberately lopsided.
Anything not understood returns ``None``, which means "no prefilter, run the
regex". A pattern this module cannot read is a pattern that keeps its old
behaviour exactly.

See ``tests/test_prefilter.py``, which proves the case folding below over the
whole Unicode range and cross-checks the extractor against every example in
the bundled rule pack.
"""

from __future__ import annotations

import os
import re

try:  # pragma: no cover - the fallback is for Python 3.10
    import re._parser as _sre_parse
except ImportError:  # pragma: no cover
    import sre_parse as _sre_parse  # type: ignore[no-redef]

__all__ = ["fold", "required_literals"]

# Literals shorter than this are not worth a prefilter. "rm" appears in
# ordinary text constantly, so a rule reduced to it would run its regex almost
# every time and we would have paid for the substring search on top. This only
# affects speed. A pattern whose literals are all too short returns None and
# behaves exactly as it did before.
MIN_LITERAL = 3

# Bounded so a pathological rule file cannot grow this without limit. Rules
# come from the operator rather than from the agent being recorded, so this is
# hygiene rather than a defence.
_MAX_CACHED = 4096
_CACHE: dict[str, frozenset[str] | None] = {}

# Case folding, and why str.lower() and str.casefold() are both wrong here.
#
# The prefilter tests `literal in fold(payload)`, and the literals are ASCII
# lowercase, so fold() has to agree with what re.IGNORECASE considers equal.
# Neither built-in does:
#
#     re.search("s", "ſ", re.I) matches, but "ſ".lower() is unchanged,
#     so a .lower() prefilter would skip a rule that matches.
#
#     re.search("i", "ı", re.I) matches, but "ı".casefold() is
#     unchanged too, so casefold has the same hole.
#
# Exactly four codepoints in all of Unicode are case-equal to an ASCII
# character: U+0130, U+0131, U+017F and U+212A. casefold already handles the
# last two. U+0131 it leaves alone, and U+0130 it expands to two codepoints,
# "i" followed by a combining dot. That expansion is the subtler bug: it splits
# a multi-character literal apart, so "is" would no longer be found inside a
# folded "İs" even though (?i)is matches it.
#
# Mapping both to a single "i" before casefolding fixes both. The property the
# test proves, over all 1,114,112 codepoints, is that any character re.IGNORECASE
# treats as equal to an ASCII letter folds to exactly that one character, which
# is what keeps literals contiguous.
_FOLD_REPAIRS = {
    0x130: "i",  # LATIN CAPITAL LETTER I WITH DOT ABOVE, casefolds to two chars
    0x131: "i",  # LATIN SMALL LETTER DOTLESS I, casefold leaves it alone
}


def fold(text: str) -> str:
    """Normalize text so an ASCII lowercase literal can be searched for in it.

    Being more permissive than ``re.IGNORECASE`` is safe here: it can only
    cause a regex to run that was never going to match. Being less permissive
    is the dangerous direction, and that is what the exhaustive test rules out.
    """
    return text.translate(_FOLD_REPAIRS).casefold()


def _most_selective(options: list[frozenset[str]]) -> frozenset[str] | None:
    """Pick one requirement to use out of several that all hold.

    In a sequence every part has to match, so any part's requirement is a valid
    requirement for the whole. They are all correct, so take the one that will
    reject the most payloads, which is the one whose weakest literal is longest.
    """
    usable = [option for option in options if option]
    if not usable:
        return None
    return max(usable, key=lambda option: min(len(literal) for literal in option))


def _required(node, depth: int = 0) -> frozenset[str] | None:
    """Literals that any string matching this parsed fragment must contain.

    Returns None for "nothing can be required here", which is the safe answer
    and the one every unrecognised construct gets.
    """
    if depth > 20:  # deeply nested rule, not worth reasoning about
        return None

    found: list[frozenset[str]] = []
    run: list[str] = []

    def flush_run() -> None:
        """Turn a run of adjacent plain characters into one required literal."""
        if not run:
            return
        literal = "".join(run)
        run.clear()
        # Non-ASCII literals would need their own folding argument, and no
        # bundled rule uses one, so they are simply not prefiltered.
        if literal.isascii() and len(literal) >= MIN_LITERAL:
            found.append(frozenset({fold(literal)}))

    for op, argument in node:
        name = str(op)

        if name == "LITERAL":
            run.append(chr(argument))
            continue
        flush_run()

        if name == "BRANCH":
            # Alternation. Only one branch has to match, so a literal is only
            # required if EVERY branch requires one, and then the requirement
            # is the union. If any branch is unconstrained the alternation as a
            # whole requires nothing.
            branches = [_required(branch, depth + 1) for branch in argument[1]]
            if all(branch for branch in branches):
                found.append(frozenset().union(*branches))

        elif name == "SUBPATTERN":
            # A plain group. Inline flag changes such as (?i:...) are fine to
            # ignore: fold() already compares case-insensitively, so a group
            # turning case sensitivity on only makes the real pattern stricter
            # than the prefilter, never looser.
            inner = _required(argument[3], depth + 1)
            if inner:
                found.append(inner)

        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            # Required only when the fragment has to appear at least once.
            # "x{0,30}" and "x?" can match nothing, so they require nothing.
            minimum, _maximum, inner_node = argument
            if minimum >= 1:
                inner = _required(inner_node, depth + 1)
                if inner:
                    found.append(inner)

        elif name == "ATOMIC_GROUP":
            inner = _required(argument, depth + 1)
            if inner:
                found.append(inner)

        # Everything else contributes nothing, on purpose:
        #   IN, ANY, NOT_LITERAL, CATEGORY   match a character we cannot name
        #   AT                               zero width, consumes nothing
        #   ASSERT, ASSERT_NOT               lookarounds; a negative one must
        #                                    never contribute a requirement, and
        #                                    positive ones are not worth the risk
        #   GROUPREF, GROUPREF_EXISTS        depend on what matched elsewhere

    flush_run()
    return _most_selective(found)


def required_literals(pattern: str) -> frozenset[str] | None:
    """Literals a payload must contain for ``pattern`` to have any chance.

    Returns None when no useful requirement could be proven, meaning the caller
    must run the regex as before. Never raises, whatever it is handed, because
    a crash on the enforcement path is worse than a slow one.
    """
    if not isinstance(pattern, str):
        return None

    cached = _CACHE.get(pattern, False)
    if cached is not False:
        return cached  # type: ignore[return-value]

    result: frozenset[str] | None
    try:
        re.compile(pattern)  # a pattern that cannot compile never matches
        result = _required(_sre_parse.parse(pattern))
    except Exception:
        result = None

    if len(_CACHE) < _MAX_CACHED:
        _CACHE[pattern] = result
    return result


# An operator who suspects the prefilter during an investigation should be able
# to rule it out without patching the package. Setting this only ever makes
# matching slower and more thorough, so it is safe to expose.
DISABLED = os.environ.get("AILERON_NO_PREFILTER", "") not in ("", "0")


def can_skip(pattern: str, folded_haystack: str, seen: dict | None = None) -> bool:
    """True when ``pattern`` cannot match, so the regex can be skipped.

    ``seen`` is an optional per-event memo of which literals are present. Rules
    share literals, so looking each one up once per event rather than once per
    rule keeps the cost proportional to the pack rather than to how many rules
    happen to be checked.
    """
    if DISABLED:
        return False
    literals = required_literals(pattern)
    if literals is None:
        return False  # nothing proven, so the regex has to run

    for literal in literals:
        if seen is None:
            present = literal in folded_haystack
        else:
            present = seen.get(literal)
            if present is None:
                present = literal in folded_haystack
                seen[literal] = present
        if present:
            return False  # might match, run the regex
    return True
