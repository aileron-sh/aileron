"""Aileron hash-chained append-only JSONL audit log."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .events import canonical_json, event_hash

GENESIS_PREV_HASH = "0" * 64

# Sentinel for "the chain is broken here" — it equals no real hash, so every
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
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield obj

    @classmethod
    def read(cls, path: str) -> list[dict]:
        """Read all events from the log at ``path`` as a list of dicts."""
        return list(cls(path))


def verify(path: str) -> VerifyResult:
    """Verify the hash-chained log at ``path``.

    Checks seq continuity (1..N), prev_hash links (genesis '0'*64, then each
    event's prev_hash equals the previous event's hash), and recomputes each
    event's hash. Returns a VerifyResult; ``first_bad_seq`` is the seq of the
    first event failing any check.
    """
    errors: list[str] = []
    first_bad_seq: int | None = None

    if not os.path.exists(path):
        return VerifyResult(ok=False, count=0, first_bad_seq=None,
                            errors=[f"log file not found: {path}"])

    def bad(seq: Any, msg: str) -> None:
        nonlocal first_bad_seq
        errors.append(msg)
        if first_bad_seq is None:
            first_bad_seq = seq if isinstance(seq, int) else None

    count = 0
    expected_seq = 1
    expected_prev = GENESIS_PREV_HASH
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (ValueError, RecursionError) as exc:
                bad(expected_seq, f"line {lineno}: invalid JSON: {exc}")
                expected_seq += 1
                expected_prev = _BROKEN  # nothing may chain onto a bad line
                continue
            if not isinstance(ev, dict):
                bad(expected_seq, f"line {lineno}: event is not a JSON object")
                expected_seq += 1
                expected_prev = _BROKEN
                continue
            # The stored bytes are authoritative, not just the parsed object:
            # re-serializing must reproduce the line exactly. This catches
            # duplicate keys, non-canonical number literals, and any other
            # content smuggled past json.loads' last-value-wins behavior.
            try:
                if canonical_json(ev) != line:
                    bad(ev.get("seq"), f"line {lineno}: non-canonical encoding")
            except (ValueError, TypeError) as exc:
                bad(ev.get("seq"), f"line {lineno}: uncanonicalizable content: {exc}")
            count += 1
            seq = ev.get("seq")
            if seq != expected_seq:
                bad(seq, f"seq discontinuity at line {lineno}: expected {expected_seq}, got {seq}")
            if expected_prev is _BROKEN:
                bad(seq, f"seq {seq}: unverifiable, chain broken at an earlier line")
            elif ev.get("prev_hash") != expected_prev:
                bad(seq, f"prev_hash mismatch at seq {seq}")
            try:
                actual = event_hash(ev)
            except (ValueError, TypeError):
                actual = None  # already reported as uncanonicalizable above
            if actual is None or ev.get("hash") != actual:
                bad(seq, f"hash mismatch at seq {seq} (content tampered)")
            expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
            expected_prev = ev.get("hash", GENESIS_PREV_HASH)

    return VerifyResult(
        ok=not errors, count=count, first_bad_seq=first_bad_seq, errors=errors
    )
