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

__all__ = ["can_skip", "fold", "required_literals", "requirement"]

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


# How a requirement is shaped.
#
# The simplest useful answer to "what must a payload contain" is a set of
# literals, any one of which will do. That is not selective enough on real
# text. Rule aileron-162 has a branch needing (systemctl|service) followed by
# (stop|disable|mask), and "service" is an ordinary English word, so any prose
# containing it paid for a full scan of the payload.
#
# So a requirement is written in disjunctive normal form:
#
#   clause      frozenset of literals, at least one must be present
#   conjunction tuple of clauses, all of them must be satisfied
#   requirement tuple of conjunctions, at least one must be satisfied
#
# A pattern can only match if some conjunction is fully satisfied, so the
# payload can be rejected when every conjunction has at least one clause with
# nothing present. For that rule, prose with "service" but no "stop", "disable"
# or "mask" is now rejected without running the regex.
#
# Both bounds below exist so a pathological rule cannot make this expensive.
# Crossing either weakens the requirement rather than abandoning it, and
# weakening is always the safe direction: it can only cause a regex to run.
_MAX_CONJUNCTIONS = 24  # how wide the disjunction may get
_MAX_CLAUSES = 4  # how many clauses one conjunction may carry


def _clause_rank(clause: frozenset[str]) -> int:
    """How selective a clause is. Longer worst-case literal is better."""
    return min(len(literal) for literal in clause)


def _trim(conjunction: tuple) -> tuple:
    """Keep the most selective clauses. Dropping a clause only weakens."""
    if len(conjunction) <= _MAX_CLAUSES:
        return conjunction
    return tuple(sorted(conjunction, key=_clause_rank, reverse=True)[:_MAX_CLAUSES])


def _collapse(requirement: tuple) -> tuple:
    """Weaken a requirement to a single clause.

    Take the most selective clause out of each conjunction and union them. If
    some conjunction held, its representative clause held, so the union holds.
    That is the old one-set-per-pattern behaviour, used as an overflow valve.
    """
    picks = [max(conjunction, key=_clause_rank) for conjunction in requirement]
    return ((frozenset().union(*picks),),)


def _both(left: tuple | None, right: tuple | None) -> tuple | None:
    """Requirement for two fragments that must both match.

    None means "no constraint", which is the identity here: something we could
    not read tells us nothing, so the other side stands on its own.
    """
    if left is None:
        return right
    if right is None:
        return left
    combined = []
    for first in left:
        for second in right:
            # Most selective clause first. Rejecting a conjunction only needs
            # one clause to come up empty, so testing the discriminating one
            # first usually costs a single substring scan instead of several.
            combined.append(_trim(tuple(sorted(
                first + second, key=_clause_rank, reverse=True))))
            if len(combined) > _MAX_CONJUNCTIONS:
                # Too wide to carry. Weaken both sides to one clause each and
                # keep the conjunction, which is still better than either alone.
                return (_trim(_collapse(left)[0] + _collapse(right)[0]),)
    return tuple(combined)


def _either(options: list) -> tuple | None:
    """Requirement for an alternation.

    Only one branch has to match, so a branch we cannot read means the
    alternation requires nothing at all.
    """
    if any(option is None for option in options):
        return None
    merged: tuple = ()
    for option in options:
        merged += option
    if not merged:
        return None

    # "(systemctl|service)" arrives here as two alternatives that each require
    # one literal. That is exactly what a clause is, so fold them into one
    # rather than carrying two alternatives forward. Without this the products
    # multiply: a branch needing three such groups in a row would become 24
    # alternatives and blow the cap, which is what used to make rule
    # aileron-162 fall back to a single loose union and scan any prose
    # containing the word "service".
    if all(len(conjunction) == 1 for conjunction in merged):
        return ((frozenset().union(*(c[0] for c in merged)),),)

    if len(merged) > _MAX_CONJUNCTIONS:
        return _collapse(merged)
    return merged


def _required(node, depth: int = 0) -> tuple | None:
    """What any string matching this parsed fragment must contain.

    Returns None for "nothing can be required here", which is the safe answer
    and the one every unrecognised construct gets.
    """
    if depth > 20:  # deeply nested rule, not worth reasoning about
        return None

    result: tuple | None = None
    run: list[str] = []

    def flush_run() -> tuple | None:
        """Turn a run of adjacent plain characters into one required literal."""
        if not run:
            return None
        literal = "".join(run)
        run.clear()
        # Non-ASCII literals would need their own folding argument, and no
        # bundled rule uses one, so they are simply not prefiltered.
        if literal.isascii() and len(literal) >= MIN_LITERAL:
            return ((frozenset({fold(literal)}),),)
        return None

    for op, argument in node:
        name = str(op)

        if name == "LITERAL":
            run.append(chr(argument))
            continue
        result = _both(result, flush_run())

        if name == "BRANCH":
            result = _both(result, _either(
                [_required(branch, depth + 1) for branch in argument[1]]))

        elif name == "SUBPATTERN":
            # A plain group. Inline flag changes such as (?i:...) are fine to
            # ignore: fold() already compares case-insensitively, so a group
            # turning case sensitivity on only makes the real pattern stricter
            # than the prefilter, never looser.
            result = _both(result, _required(argument[3], depth + 1))

        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            # Required only when the fragment has to appear at least once.
            # "x{0,30}" and "x?" can match nothing, so they require nothing.
            minimum, _maximum, inner_node = argument
            if minimum >= 1:
                result = _both(result, _required(inner_node, depth + 1))

        elif name == "ATOMIC_GROUP":
            result = _both(result, _required(argument, depth + 1))

        # Everything else contributes nothing, on purpose:
        #   IN, ANY, NOT_LITERAL, CATEGORY   match a character we cannot name
        #   AT                               zero width, consumes nothing
        #   ASSERT, ASSERT_NOT               lookarounds; a negative one must
        #                                    never contribute a requirement, and
        #                                    positive ones are not worth the risk
        #   GROUPREF, GROUPREF_EXISTS        depend on what matched elsewhere

    return _both(result, flush_run())


def requirement(pattern: str) -> tuple | None:
    """Cached disjunctive-normal-form requirement for a pattern."""
    if not isinstance(pattern, str):
        return None

    cached = _CACHE.get(pattern, False)
    if cached is not False:
        return cached  # type: ignore[return-value]

    result: tuple | None
    try:
        re.compile(pattern)  # a pattern that cannot compile never matches
        result = _required(_sre_parse.parse(pattern))
    except Exception:
        result = None

    if len(_CACHE) < _MAX_CACHED:
        _CACHE[pattern] = result
    return result


def required_literals(pattern: str) -> frozenset[str] | None:
    """Literals a payload must contain for ``pattern`` to have any chance.

    This is the weakened, one-set view of :func:`requirement`, kept because it
    is the easiest form to reason about and to test. Returns None when nothing
    could be proven.
    """
    found = requirement(pattern)
    if found is None:
        return None
    return _collapse(found)[0][0]


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
    found = requirement(pattern)
    if found is None:
        return False  # nothing proven, so the regex has to run

    def present(literal: str) -> bool:
        if seen is None:
            return literal in folded_haystack
        hit = seen.get(literal)
        if hit is None:
            hit = literal in folded_haystack
            seen[literal] = hit
        return hit

    for conjunction in found:
        if all(any(present(lit) for lit in clause) for clause in conjunction):
            return False  # this alternative might match, so run the regex
    return True
