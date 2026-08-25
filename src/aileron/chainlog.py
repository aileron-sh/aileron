"""Aileron hash-chained append-only JSONL audit log."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .events import canonical_json, event_hash

GENESIS_PREV_HASH = "0" * 64

# Sentinel for "the chain is broken here" - it equals no real hash, so every
# subsequent event is reported as unverifiable rather than silently accepted
# by resyncing to genesis.
_BROKEN = object()


@dataclass
class VerifyResult:
    """Outcome of verifying a hash-chained log."""

    ok: bool
    count: int
    first_bad_seq: int | None
    errors: list[str] = field(default_factory=list)


class ChainLog:
    """Append-only hash-chained JSONL log.

    Each appended event gets seq = previous seq + 1 (genesis seq = 1),
    prev_hash = hash of the previous event (genesis prev_hash = '0'*64),
    and hash = sha256 of the canonical event. When ``capture_content`` is
    False (default), ``tool.arguments`` and ``result`` are stripped (set to
    None) before hashing/writing; their digests are always kept.
    """

    def __init__(self, path: str, capture_content: bool = False):
        """Open (creating if needed) the log at ``path``."""
        self.path = str(path)
        self.capture_content = capture_content
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.path):
            Path(self.path).touch()
        self._last_seq = 0
        self._last_hash = GENESIS_PREV_HASH
        for ev in self:
            self._last_seq = ev.get("seq", self._last_seq + 1)
            self._last_hash = ev.get("hash", GENESIS_PREV_HASH)

    def append(self, event: dict) -> dict:
        """Chain ``event`` and append it as one JSONL line.

        Returns the stored event (seq, prev_hash, and hash set). The caller's
        dict is not mutated: stripping happens on a copy, so policy engines
        and detectors can keep working with the full in-memory event while
        only digests are persisted when capture_content is False.
        """
        stored = dict(event)
        if not self.capture_content:
            tool = stored.get("tool")
            if isinstance(tool, dict):
                stored["tool"] = {**tool, "arguments": None}
            if "result" in stored:
                stored["result"] = None
        stored["seq"] = self._last_seq + 1
        stored["prev_hash"] = self._last_hash
        stored["hash"] = event_hash(stored)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical_json(stored) + "\n")
        self._last_seq = stored["seq"]
        self._last_hash = stored["hash"]
        return stored

    def __iter__(self) -> Iterator[dict]:
        """Yield event objects from the log file in append order.

        A truncated or corrupt line (e.g. a crash mid-append left a partial
        final line) is skipped rather than raised, so the log stays readable
        and appendable after a crash. ``verify`` is the integrity authority
        and still flags such a line; readers here are best-effort.
        """
        with open(self.path, "rb") as fh:
            for raw_line in fh:
                try:
                    line = raw_line.decode("utf-8").strip()
                except UnicodeDecodeError:
                    continue
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                if isinstance(obj, dict):
                    yield obj

    @classmethod
    def read(cls, path: str) -> list[dict]:
        """Read all events from the log at ``path`` as a list of dicts."""
        return list(cls(path))


@dataclass(frozen=True)
class _JournalLine:
    """One physical line, decoded as far as it could be.

    ``error`` is set when the line could not be read as an event at all, in
    which case ``event`` is None. Separating "what is on this line" from "does
    it fit the chain" is the whole point: reading is about bytes and JSON,
    checking is about hashes and sequence numbers, and mixing them is what made
    the original hard to follow.
    """

    lineno: int
    text: str | None
    event: dict | None
    error: str | None


def _read_journal(path: str) -> Iterator[_JournalLine]:
    """Decode the journal one line at a time, reporting rather than raising.

    Bytes are read and decoded per line on purpose. Raw invalid UTF-8 in a
    journal is evidence of tampering and must be reported as such, not escape
    as an exception out of the integrity check itself.

    Blank lines are skipped entirely: they carry no event and consume no
    sequence number.
    """
    with open(path, "rb") as handle:
        for lineno, raw_line in enumerate(handle, start=1):
            try:
                text = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                yield _JournalLine(lineno, None, None, f"line {lineno}: invalid UTF-8: {exc}")
                continue
            if not text:
                continue
            try:
                event = json.loads(text)
            except (ValueError, RecursionError) as exc:
                yield _JournalLine(lineno, text, None, f"line {lineno}: invalid JSON: {exc}")
                continue
            if not isinstance(event, dict):
                yield _JournalLine(lineno, text, None,
                                   f"line {lineno}: event is not a JSON object")
                continue
            yield _JournalLine(lineno, text, event, None)


def _encoding_errors(line: _JournalLine) -> list[tuple[Any, str]]:
    """Complaints about how the event was written, not about its contents.

    The stored bytes are authoritative, not just the parsed object:
    re-serializing must reproduce the line exactly. This catches duplicate keys,
    non-canonical number literals, and anything else smuggled past json.loads'
    last-value-wins behavior.
    """
    event, seq = line.event, (line.event or {}).get("seq")
    try:
        if canonical_json(event) != line.text:
            return [(seq, f"line {line.lineno}: non-canonical encoding")]
    except (ValueError, TypeError) as exc:
        return [(seq, f"line {line.lineno}: uncanonicalizable content: {exc}")]
    return []


def _chain_errors(line: _JournalLine, expected_seq: int,
                  expected_prev: Any) -> list[tuple[Any, str]]:
    """Complaints about where the event sits in the chain.

    ``expected_prev`` is ``_BROKEN`` when an earlier line could not be read, in
    which case nothing after it can be trusted to link to anything.
    """
    event = line.event or {}
    seq = event.get("seq")
    problems: list[tuple[Any, str]] = []

    if seq != expected_seq:
        problems.append((seq, f"seq discontinuity at line {line.lineno}: "
                              f"expected {expected_seq}, got {seq}"))
    if expected_prev is _BROKEN:
        problems.append((seq, f"seq {seq}: unverifiable, chain broken at an earlier line"))
    elif event.get("prev_hash") != expected_prev:
        problems.append((seq, f"prev_hash mismatch at seq {seq}"))

    try:
        actual = event_hash(event)
    except (ValueError, TypeError):
        actual = None  # already reported as uncanonicalizable
    if actual is None or event.get("hash") != actual:
        problems.append((seq, f"hash mismatch at seq {seq} (content tampered)"))

    return problems


def verify(path: str) -> VerifyResult:
    """Verify the hash-chained log at ``path``.

    Checks seq continuity (1..N), prev_hash links (genesis '0'*64, then each
    event's prev_hash equals the previous event's hash), and recomputes each
    event's hash. Returns a VerifyResult; ``first_bad_seq`` is the seq of the
    first event failing any check.

    Never raises on the journal's contents. Whatever bytes are on disk, the
    answer is a verdict, because the whole point of this function is to be
    trustworthy about a file an attacker may have touched.
    """
    if not os.path.exists(path):
        return VerifyResult(ok=False, count=0, first_bad_seq=None,
                            errors=[f"log file not found: {path}"])

    errors: list[str] = []
    first_bad_seq: int | None = None

    def record(problems: list[tuple[Any, str]]) -> None:
        nonlocal first_bad_seq
        for seq, message in problems:
            errors.append(message)
            if first_bad_seq is None:
                first_bad_seq = seq if isinstance(seq, int) else None

    count = 0
    expected_seq = 1
    expected_prev: Any = GENESIS_PREV_HASH

    for line in _read_journal(path):
        if line.error is not None:
            # An unreadable line still occupies a position in the sequence, and
            # nothing may chain onto it, or a forged event could re-link to
            # genesis and look valid.
            record([(expected_seq, line.error)])
            expected_seq += 1
            expected_prev = _BROKEN
            continue

        record(_encoding_errors(line))
        count += 1
        record(_chain_errors(line, expected_seq, expected_prev))

        event = line.event or {}
        seq = event.get("seq")
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
        expected_prev = event.get("hash", GENESIS_PREV_HASH)

    return VerifyResult(
        ok=not errors, count=count, first_bad_seq=first_bad_seq, errors=errors
    )
