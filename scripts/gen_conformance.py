#!/usr/bin/env python3
"""Generate the cross-implementation conformance fixtures in tests/conformance/.

Aileron ships two verifiers: the Python one in src/aileron and an independent
Go one in verifiers/go. They must agree, byte for byte on canonical JSON and
verdict for verdict on journals. This script produces the evidence that they
do, using the real aileron library to build every fixture:

  tests/conformance/canonical_cases.json
      (source JSON text, expected canonical bytes) pairs, plus inputs that
      canonicalization must refuse.
  tests/conformance/cases/<name>/
      journal.jsonl                      the journal under test
      journal.jsonl.checkpoints.jsonl    signed checkpoints, when the case has them
      aileron_ed25519.pub                the public key to verify them with
      expected.json                      what the Python implementation says

The fixtures are committed so they are stable. Run this script again when the
format changes, and commit the result:

    PYTHONPATH=src python scripts/gen_conformance.py

Output is deterministic: event ids come from a seeded generator, timestamps
are fixed, and the signing key is derived from a constant. That key signs
nothing anyone should trust; it exists so the fixtures do not change on every
run and so tests/test_conformance.py can check that the committed fixtures are
what the current library produces.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import random
import shutil
import struct
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from aileron import cli, signing  # noqa: E402
from aileron.chainlog import ChainLog, verify  # noqa: E402
from aileron.events import canonical_json, event_hash, new_event  # noqa: E402
from aileron.signing import sign_checkpoint, verify_checkpoint  # noqa: E402

LOG = "journal.jsonl"
CHECKPOINTS = f"{LOG}.checkpoints.jsonl"
PUB = "aileron_ed25519.pub"
KEY = "aileron_ed25519.key"
DEFAULT_OUT = ROOT / "tests" / "conformance"

# Checkpoint timestamps come from a private helper in signing.py. Pinning it
# is the one place this script reaches past the public API, and it does so
# only to make the output reproducible.
FIXED_TS = "2026-01-01T00:00:00.000Z"
signing._now_ts = lambda: FIXED_TS

KEY_SEEDS = {
    "A": hashlib.sha256(b"aileron conformance fixture key A").digest(),
    "B": hashlib.sha256(b"aileron conformance fixture key B").digest(),
}


# ------------------------------------------------------------------ helpers


def install_key(seed_name: str, pub_only: bool = False) -> None:
    """Write the fixture key pair for ``seed_name`` into the working directory."""
    private = Ed25519PrivateKey.from_private_bytes(KEY_SEEDS[seed_name])
    if not pub_only:
        Path(KEY).write_bytes(private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    Path(PUB).write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


class EventFactory:
    """Events with deterministic ids and timestamps."""

    def __init__(self, seed: str):
        self.rng = random.Random(seed)  # noqa: S311 - seeded fixture generator, reproducibility is the point
        self.n = 0

    def __call__(self, type: str = "tool_call", **fields):
        self.n += 1
        base = {
            "id": f"{self.rng.getrandbits(128):032x}",
            "ts": f"2026-01-01T00:{self.n // 60:02d}:{self.n % 60:02d}.000Z",
        }
        base.update(fields)
        return new_event(type, "conformance-session", "conformance-agent",
                         "fixture", **base)


def read_lines(path: str = LOG) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()


def write_lines(lines: list[str], path: str = LOG) -> None:
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def redump(event: dict) -> str:
    """Re-serialize an edited event canonically, hash left as it was."""
    return canonical_json(event)


def standard_chain(ev: EventFactory, capture_content: bool = False) -> ChainLog:
    """Six events covering every event type the recorder emits."""
    log = ChainLog(LOG, capture_content=capture_content)
    log.append(ev("agent_start"))
    log.append(ev(tool={"name": "read_file", "arguments": {"path": "/etc/hostname"}},
                  result={"content": "host-01\n"}, latency_ms=8.0))
    log.append(ev(tool={"name": "web_search",
                        "arguments": {"query": "aileron flight recorder"}},
                  result={"hits": 3, "top": ["a", "b"]}, latency_ms=42.5))
    log.append(ev(tool={"name": "shell",
                        "arguments": {"cmd": "rm -rf / --no-preserve-root"}},
                  status="blocked",
                  policy={"rule_id": "aileron-001", "action": "block"}, latency_ms=3))
    log.append(ev("alert", tool={"name": "shell"},
                  meta={"flags": ["first_seen_tool:shell"], "event_id": "see seq 4"}))
    log.append(ev("agent_end", latency_ms=1200.0))
    return log


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def verdict_line(out: str, err: str) -> str:
    for line in (out + err).splitlines():
        if line.startswith(("OK:", "TAMPERED", "FAILED:")):
            return line
    raise AssertionError(f"no verdict line in output:\n{out}\n{err}")


@contextlib.contextmanager
def chdir(path: Path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


# ------------------------------------------------------------------ cases

# Each builder runs with the working directory set to an empty scratch
# directory that already holds key pair A, writes journal.jsonl (and whatever
# else the case needs), and returns a dict of assertions the Python
# implementation must satisfy. The assertions are the intent of the case; the
# expected.json written next to the fixture is what Python actually said.
Builder = Callable[[EventFactory], dict]
CASES: list[tuple[str, str, Builder]] = []


def case(name: str, description: str):
    def register(builder: Builder) -> Builder:
        CASES.append((name, description, builder))
        return builder
    return register


@case("valid_chain", "Six untouched events in digest-only mode.")
def _valid_chain(ev):
    standard_chain(ev)
    return {"ok": True, "count": 6}


@case("edited_event", "Event 4's status rewritten from blocked to ok without re-hashing.")
def _edited_event(ev):
    standard_chain(ev)
    lines = read_lines()
    event = json.loads(lines[3])
    assert event["status"] == "blocked"
    event["status"] = "ok"
    lines[3] = redump(event)
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 4, "count": 6}


@case("deleted_line", "Event 2 removed; event 3 now sits where 2 should be.")
def _deleted_line(ev):
    standard_chain(ev)
    lines = read_lines()
    del lines[1]
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 3, "count": 5}


@case("reordered_pair", "Events 2 and 3 swapped.")
def _reordered_pair(ev):
    standard_chain(ev)
    lines = read_lines()
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 3, "count": 6}


@case("inserted_line",
      "A forged event that chains correctly from event 2 is inserted after it. "
      "The forgery itself passes; the real event 3 behind it no longer links.")
def _inserted_line(ev):
    standard_chain(ev)
    lines = read_lines()
    events = [json.loads(line) for line in lines]
    forged = ev(tool={"name": "forged", "arguments": None}, result=None)
    forged["seq"] = 3
    forged["prev_hash"] = events[1]["hash"]
    forged["hash"] = event_hash(forged)
    lines.insert(2, canonical_json(forged))
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 3, "count": 7}


@case("capture_content", "Same six events with capture_content=True, so arguments and results are present.")
def _capture_content(ev):
    standard_chain(ev, capture_content=True)
    return {"ok": True, "count": 6}


RICH_ARGUMENTS = {
    "accents": "café naïve façade",
    "cjk": "日本語テキスト",
    "emoji": "😀🚀👩" + chr(0x200D) + "💻",  # zero width joiner between the last two
    "control": "\x00\x01\x1f\x7f",
    "escapes": "quote\" backslash\\ slash/ newline\n return\r tab\t backspace\b formfeed\f",
    "html": "<script>&amp;</script>",
    # A high surrogate directly followed by a low one is two code points in a
    # Python str, but json.loads reads the escaped pair back as one. The bytes
    # written are the same either way, which is the property that matters.
    "lone_surrogates": ["\ud800", "\udc00", "\ud800" + "\udfff", "\udfff\ud800", "\ud800A"],
    "ключ": "unicode key",
    "🔑": "emoji key",
    "": "empty key",
    "Zebra": 1, "apple": 2, "B": 3, "a": 4, "ab": 5,
    "floats": [0.0, -0.0, 1.0, 5.0, 0.1, 0.5, 0.0001, 0.00001, 1e-7, 1e15, 1e16,
               9999999999999998.0, 1.5e16, 1e21, 1e22, 1.5e300, 5e-324,
               2.2250738585072014e-308, 1.7976931348623157e308,
               123456789.123456789, 0.30000000000000004, -1e-5, -123.456],
    "ints": [0, -1, 1, 2**31, 2**63, 2**64, 2**100, -(2**100), 10**30],
    "nested": {"a": {"b": {"c": []}}, "empty_obj": {}, "empty_arr": [],
               "mixed": [[], {}, [{}], [[[]]], None, True, False]},
}


@case("unicode_and_numbers",
      "capture_content=True with non-ASCII text, emoji, control characters, lone "
      "surrogates, unicode keys, floats at the exponent boundaries, big ints, "
      "-0.0, and nested and empty containers.")
def _unicode_and_numbers(ev):
    log = ChainLog(LOG, capture_content=True)
    log.append(ev(tool={"name": "rich", "arguments": RICH_ARGUMENTS},
                  result={"value": 1e16, "neg_zero": -0.0, "text": "résumé 😀"},
                  latency_ms=0.000123))
    log.append(ev(tool={"name": "日本", "arguments": {"emoji": "😀", "n": 2**70}},
                  result=[1.0, -0.0, 1e-05, 1e+16], latency_ms=1e-5))
    log.append(ev("agent_end", meta={"note": "\ud800 lone surrogate in meta"}))
    return {"ok": True, "count": 3}


@case("signed_checkpoint", "Two checkpoints, the second signed after two more events were appended.")
def _signed_checkpoint(ev):
    log = standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    log.append(ev(tool={"name": "later_1"}))
    log.append(ev(tool={"name": "later_2"}))
    sign_checkpoint(LOG, KEY)
    return {"ok": True, "count": 8, "checkpoint": True}


@case("appended_after_checkpoint",
      "Events appended after the only checkpoint. Prefix semantics: still valid.")
def _appended_after_checkpoint(ev):
    log = standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    log.append(ev(tool={"name": "later_1"}))
    log.append(ev(tool={"name": "later_2"}))
    return {"ok": True, "count": 8, "checkpoint": True}


@case("truncated_after_checkpoint",
      "Journal cut from six events to four after a checkpoint attested to six. "
      "The chain itself is valid; the checkpoint file contradicts it.")
def _truncated_after_checkpoint(ev):
    standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    write_lines(read_lines()[:4])
    return {"ok": True, "count": 4, "exit_code": 2, "checkpoint": False}


@case("rewritten_prefix",
      "Journal rebuilt with the same number of events but different content after "
      "a checkpoint was signed. Internally valid; tip hash does not match.")
def _rewritten_prefix(ev):
    standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    os.remove(LOG)
    log = ChainLog(LOG)
    for i in range(6):
        log.append(ev(tool={"name": f"forged_{i}"}))
    return {"ok": True, "count": 6, "exit_code": 2, "checkpoint": False}


@case("wrong_key", "Valid checkpoint, but the public key offered is a different key.")
def _wrong_key(ev):
    standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    install_key("B", pub_only=True)
    return {"ok": True, "count": 6, "checkpoint": False}


@case("checkpoint_gap",
      "Three checkpoints with the middle one deleted. Counts and tips still agree "
      "with the journal, so the unauthenticated cross-check passes; the signed "
      "index chain does not.")
def _checkpoint_gap(ev):
    log = ChainLog(LOG)
    for _ in range(3):
        log.append(ev(tool={"name": "t"}))
    sign_checkpoint(LOG, KEY)
    for _ in range(2):
        log.append(ev(tool={"name": "t"}))
    sign_checkpoint(LOG, KEY)
    log.append(ev(tool={"name": "t"}))
    sign_checkpoint(LOG, KEY)
    lines = read_lines(CHECKPOINTS)
    write_lines([lines[0], lines[2]], CHECKPOINTS)
    return {"ok": True, "count": 6, "exit_code": 0, "checkpoint": False}


@case("checkpoint_reordered",
      "Two checkpoints with their lines swapped. File order is not meaningful; "
      "the signed index is.")
def _checkpoint_reordered(ev):
    log = standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    log.append(ev(tool={"name": "later"}))
    sign_checkpoint(LOG, KEY)
    lines = read_lines(CHECKPOINTS)
    write_lines([lines[1], lines[0]], CHECKPOINTS)
    return {"ok": True, "count": 7, "checkpoint": True}


@case("checkpoint_count_edited",
      "The checkpoint's count retyped from 6 to 6.0. The cross-check reports it as "
      "unusable rather than skipping it, and the signature no longer verifies.")
def _checkpoint_count_edited(ev):
    standard_chain(ev)
    sign_checkpoint(LOG, KEY)
    checkpoint = json.loads(read_lines(CHECKPOINTS)[0])
    checkpoint["count"] = 6.0
    write_lines([json.dumps(checkpoint)], CHECKPOINTS)
    return {"ok": True, "count": 6, "exit_code": 2, "checkpoint": False}


@case("empty_log", "An empty file: a valid chain of zero events, with nothing to checkpoint.")
def _empty_log(ev):
    Path(LOG).touch()
    return {"ok": True, "count": 0, "checkpoint": False}


@case("broken_lines",
      "A non-object line, a blank line, a forged event chained from genesis, "
      "invalid JSON, invalid UTF-8, and a truncated trailing line. Nothing after "
      "the first unreadable line may verify.")
def _broken_lines(ev):
    standard_chain(ev)
    lines = read_lines()
    scratch = "scratch.jsonl"
    ChainLog(scratch).append(ev(tool={"name": "forged_from_genesis"}))
    forged = read_lines(scratch)[0]
    os.remove(scratch)
    body = "\n".join([lines[0], lines[1], "   ", "42", forged, "{not json"]).encode("utf-8")
    body += b'\n{"x":"\xff\xfe"}\n' + b'{"seq": 9, "partial'
    Path(LOG).write_bytes(body)
    return {"ok": False, "first_bad_seq": 3, "count": 3}


@case("non_canonical_encoding",
      "Line 2 carries a duplicate key appended after the real one; line 4 spells "
      "an integer as 3e0. Both re-serialize differently from the stored bytes.")
def _non_canonical_encoding(ev):
    standard_chain(ev)
    lines = read_lines()
    lines[1] = lines[1][:-1] + ',"meta":{"INJECTED":"x"}}'
    assert '"latency_ms":3,' in lines[3]
    lines[3] = lines[3].replace('"latency_ms":3,', '"latency_ms":3e0,')
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 2, "count": 6}


@case("non_finite_floats",
      "NaN on line 3 and 1e400 (which parses to infinity) on line 6. Python's "
      "json module accepts both on input; canonicalization refuses them.")
def _non_finite_floats(ev):
    standard_chain(ev)
    lines = read_lines()
    assert '"latency_ms":42.5,' in lines[2] and '"latency_ms":1200.0,' in lines[5]
    lines[2] = lines[2].replace('"latency_ms":42.5,', '"latency_ms":NaN,')
    lines[5] = lines[5].replace('"latency_ms":1200.0,', '"latency_ms":1e400,')
    write_lines(lines)
    return {"ok": False, "first_bad_seq": 3, "count": 6}


@case("seq_as_string",
      "Event 2's seq is the string \"2\" with hashes recomputed around it. The "
      "chain of hashes holds but the sequence does not, and first_bad_seq is "
      "None because the offending seq is not an integer.")
def _seq_as_string(ev):
    e1 = ev(tool={"name": "t", "arguments": None}, result=None)
    e1["seq"], e1["prev_hash"] = 1, "0" * 64
    e1["hash"] = event_hash(e1)
    e2 = ev(tool={"name": "t", "arguments": None}, result=None)
    e2["seq"], e2["prev_hash"] = "2", e1["hash"]
    e2["hash"] = event_hash(e2)
    e3 = ev(tool={"name": "t", "arguments": None}, result=None)
    e3["seq"], e3["prev_hash"] = 3, e2["hash"]
    e3["hash"] = event_hash(e3)
    write_lines([canonical_json(e) for e in (e1, e2, e3)])
    return {"ok": False, "first_bad_seq": None, "count": 3}


@case("seq_as_float",
      "seq values 1.0, 2.0, 3.0 with correct hashes. Documents reference "
      "behaviour: Python compares seq numerically (1.0 == 1), so this verifies. "
      "A second implementation has to make the same comparison or it will "
      "disagree with the reference on this journal.")
def _seq_as_float(ev):
    prev = "0" * 64
    lines = []
    for i in (1.0, 2.0, 3.0):
        e = ev(tool={"name": "t", "arguments": None}, result=None)
        e["seq"], e["prev_hash"] = i, prev
        e["hash"] = event_hash(e)
        prev = e["hash"]
        lines.append(canonical_json(e))
    write_lines(lines)
    return {"ok": True, "count": 3}


@case("whitespace_tolerance",
      "CRLF line endings, indentation, a trailing no-break space, blank lines "
      "between events, and no final newline. Lines are stripped as Python's "
      "str.strip() strips, so all of this is ignored.")
def _whitespace_tolerance(ev):
    standard_chain(ev)
    lines = read_lines()
    text = (lines[0] + "\r\n" + "    " + lines[1] + "\r\n" + lines[2] + "\xa0\r\n"
            + "\r\n" + "  \t \r\n" + lines[3] + "\n" + lines[4] + "\r\n" + lines[5])
    Path(LOG).write_bytes(text.encode("utf-8"))
    return {"ok": True, "count": 6}


# ------------------------------------------------------------------ canonical cases


def canonical_cases() -> list[dict]:
    """(source text, expected canonical bytes) pairs, and inputs that must fail."""
    out: list[dict] = []

    def add(name: str, source: str | None = None, value=None) -> None:
        if source is None:
            # Default separators on purpose: the source carries whitespace the
            # canonical form must not.
            source = json.dumps(value, ensure_ascii=True)
        out.append({"name": name, "source": source,
                    "canonical": canonical_json(json.loads(source))})

    def refuse(name: str, source: str) -> None:
        try:
            canonical_json(json.loads(source))
        except ValueError:
            out.append({"name": name, "source": source, "error": "out of range float"})
        else:
            raise AssertionError(f"{name}: expected canonical_json to refuse {source!r}")

    add("null", value=None)
    add("true", value=True)
    add("false", value=False)
    add("zero", value=0)
    add("negative_zero_int", source="-0")
    add("one", value=1)
    add("minus_one", value=-1)
    add("int_2_63", value=2**63)
    add("int_2_64", value=2**64)
    add("int_2_100", value=2**100)
    add("int_neg_2_100", value=-(2**100))
    add("int_10_30", value=10**30)
    add("int_4300_digits", source="9" * 4300)

    add("float_zero", value=0.0)
    add("float_negative_zero", value=-0.0)
    add("float_one", value=1.0)
    add("float_five", value=5.0)
    add("float_tenth", value=0.1)
    add("float_sum_tenths", value=0.1 + 0.2)
    add("float_1e-4_positional", value=0.0001)
    add("float_1e-5_exponent", value=0.00001)
    add("float_just_above_1e-5", value=0.000010000000000000001)
    add("float_9.99e-5", value=0.0000999)
    add("float_1e15_positional", value=1e15)
    add("float_9999999999999998_positional", value=9999999999999998.0)
    add("float_1e16_exponent", value=1e16)
    add("float_1.5e16_exponent", value=1.5e16)
    add("float_17_digits_exponent", value=123456789012345680.0)
    add("float_1e21", value=1e21)
    add("float_1e22", value=1e22)
    add("float_max", value=1.7976931348623157e308)
    add("float_min_normal", value=2.2250738585072014e-308)
    add("float_min_subnormal", value=5e-324)
    add("float_pi", value=3.141592653589793)
    add("float_negative", value=-123.456)
    add("float_negative_exponent", value=-1e-7)
    add("float_source_1E5", source="1E5")
    add("float_source_1e0", source="1e0")
    add("float_source_100e-2", source="100e-2")
    add("float_source_0.1e1", source="0.1e1")
    add("float_source_1.0e-5", source="1.0e-5")
    add("float_source_long_mantissa", source="0.1000000000000000055511151231257827021181583404541015625")
    add("float_source_underflow_to_zero", source="1e-400")
    add("float_source_negative_underflow", source="-1e-400")
    add("float_source_many_digits", source="3.14159265358979323846264338327950288419716939937510582097494459")

    add("string_empty", value="")
    add("string_ascii", value="hello world")
    add("string_quotes_and_backslash", value='say "hi" \\ done')
    add("string_short_escapes", value="\n\r\t\b\f")
    add("string_control_chars", value="\x00\x01\x1f")
    add("string_delete_char", value="\x7f")
    add("string_solidus_not_escaped", value="a/b")
    add("string_html_not_escaped", value="<tag>&amp;</tag>")
    add("string_latin1", value="café")
    add("string_cjk", value="日本語")
    add("string_emoji_surrogate_pair", value="😀")
    add("string_astral_max", value="\U0010ffff")
    add("string_u2028_u2029", value=chr(0x2028) + chr(0x2029))
    add("string_nbsp", value="\xa0")
    add("string_lone_high_surrogate", value="\ud800")
    add("string_lone_low_surrogate", value="\udc00")
    add("string_low_then_high_surrogate", value="\udfff\ud800")
    add("string_lone_high_then_ascii", value="\ud800A")
    add("string_source_uppercase_hex_escape", source='"\\u00C9"')
    add("string_source_escaped_pair", source='"\\uD83D\\uDE00"')
    add("string_source_escaped_solidus", source='"\\/"')
    add("string_source_raw_non_ascii", source='"é😀"')
    add("string_source_escaped_lone_surrogate", source='"\\ud800"')
    add("string_source_high_then_non_low_escape", source='"\\ud800\\u0041"')
    add("string_source_high_then_high", source='"\\ud800\\ud800"')
    add("string_source_pair_then_lone", source='"\\ud83d\\ude00\\udc00"')

    add("array_empty", value=[])
    add("array_numbers", value=[1, 2.0, -3, 4e2])
    add("array_nested_empty", value=[[], [[]], [[[]]]])
    add("array_of_empty_object", value=[{}])
    add("array_mixed", value=[None, True, False, "x", 1, 1.5, {"k": []}])

    add("object_empty", value={})
    add("object_sorted", value={"b": 1, "a": 2, "c": 3})
    add("object_sort_prefix_before_longer", value={"ab": 1, "a": 2, "abc": 3, "b": 4})
    add("object_sort_uppercase_before_lowercase", value={"a": 1, "B": 2, "A": 3, "b": 4})
    add("object_sort_empty_key_first", value={"x": 1, "": 2})
    add("object_sort_non_ascii_keys", value={"é": 1, "z": 2, "ä": 3, "😀": 4, "日": 5, "\xa0": 6})
    add("object_sort_surrogate_key", value={"\ud800": 1, chr(0xE000): 2, chr(0xFFFF): 3, "😀": 4})
    add("object_nested", value={"outer": {"inner": {"deep": [1, {"x": None}]}}})
    add("object_source_whitespace", source='  { "b" : 1 , "a" : [ 1 , 2 ] }  ')
    add("object_source_duplicate_key_last_wins", source='{"a":1,"a":2}')
    add("object_source_duplicate_key_keeps_first_position",
        source='{"b":1,"a":2,"b":3}')

    refuse("nan", "NaN")
    refuse("infinity", "Infinity")
    refuse("negative_infinity", "-Infinity")
    refuse("overflow_to_infinity", "1e400")
    refuse("nan_nested", '{"a":[1,NaN]}')

    # Random doubles across the whole exponent range, from a fixed seed.
    rng = random.Random(20260101)  # noqa: S311 - seeded fixture generator, reproducibility is the point
    emitted = 0
    while emitted < 300:
        bits = rng.getrandbits(64)
        f = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if f != f or f in (float("inf"), float("-inf")):
            continue
        add(f"float_random_{emitted:03d}", value=f)
        emitted += 1
    return out


# ------------------------------------------------------------------ main


def build_case(name: str, description: str, builder: Builder, out_root: Path) -> None:
    target = out_root / "cases" / name
    work = Path(tempfile.mkdtemp(prefix="aileron-conformance-"))
    try:
        with chdir(work):
            install_key("A")
            intent = builder(EventFactory(name))

            result = verify(LOG)
            code, out, err = run_cli(["verify", LOG])
            assert result.ok == intent["ok"], (name, result)
            assert result.count == intent["count"], (name, result)
            assert result.first_bad_seq == intent.get("first_bad_seq"), (name, result)
            assert code == intent.get("exit_code", 0 if result.ok else 2), (name, code, err)

            valid = verify_checkpoint(LOG, PUB)
            ccode, cout, cerr = run_cli(["verify-checkpoint", LOG, "--key", PUB])
            assert valid == intent.get("checkpoint", False), (name, valid, cerr)
            assert ccode == (0 if valid else 1), (name, ccode, cerr)

            expected = {
                "description": description,
                "verify": {
                    "ok": result.ok,
                    "count": result.count,
                    "first_bad_seq": result.first_bad_seq,
                    "errors": result.errors,
                    "exit_code": code,
                    "verdict": verdict_line(out, err),
                },
                "checkpoint": {
                    "key": PUB,
                    "valid": valid,
                    "exit_code": ccode,
                    "verdict": verdict_line(cout, cerr),
                },
            }

            shutil.rmtree(target, ignore_errors=True)
            target.mkdir(parents=True)
            for filename in (LOG, CHECKPOINTS, PUB):
                if Path(filename).exists():
                    shutil.copyfile(filename, target / filename)
            (target / "expected.json").write_text(
                json.dumps(expected, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help=f"output directory (default: {DEFAULT_OUT})")
    args = parser.parse_args(argv)
    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    shutil.rmtree(out_root / "cases", ignore_errors=True)
    for name, description, builder in CASES:
        build_case(name, description, builder, out_root)

    (out_root / "canonical_cases.json").write_text(
        json.dumps(canonical_cases(), indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {len(CASES)} journal cases and canonical_cases.json to {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
