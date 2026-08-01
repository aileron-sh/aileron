import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog, VerifyResult, verify
from aileron.events import new_event, validate


def make_ev(i=0):
    return new_event(
        "tool_call",
        "sess",
        "bot",
        "fw",
        tool={"name": "shell", "arguments": {"cmd": f"echo {i}"}},
        result={"out": i},
    )


def test_append_happy_path_and_verify(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    log = ChainLog(path)
    e1 = log.append(make_ev(1))
    e2 = log.append(make_ev(2))
    e3 = log.append(make_ev(3))

    assert e1["seq"] == 1 and e2["seq"] == 2 and e3["seq"] == 3
    assert e1["prev_hash"] == "0" * 64
    assert e2["prev_hash"] == e1["hash"]
    assert e3["prev_hash"] == e2["hash"]
    assert len({e1["hash"], e2["hash"], e3["hash"]}) == 3
    for e in (e1, e2, e3):
        assert validate(e) == []

    result = verify(path)
    assert isinstance(result, VerifyResult)
    assert result.ok is True
    assert result.count == 3
    assert result.first_bad_seq is None
    assert result.errors == []


def test_content_stripped_by_default_kept_when_opted_in(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)  # capture_content=False default
    ev = log.append(make_ev(1))
    assert ev["tool"]["arguments"] is None
    assert ev["result"] is None
    # digests kept
    assert ev["tool"]["arguments_digest"] is not None
    assert ev["result_digest"] is not None
    on_disk = json.loads(open(path).readline())
    assert on_disk["tool"]["arguments"] is None
    assert on_disk["result"] is None

    path2 = str(tmp_path / "c2.jsonl")
    log2 = ChainLog(path2, capture_content=True)
    ev2 = log2.append(make_ev(2))
    assert ev2["tool"]["arguments"] == {"cmd": "echo 2"}
    assert ev2["result"] == {"out": 2}
    assert verify(path2).ok


def test_iter_and_read_roundtrip(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)
    appended = [log.append(make_ev(i)) for i in range(4)]
    read_back = ChainLog.read(path)
    assert read_back == appended
    assert list(ChainLog(path)) == appended


def test_append_resumes_existing_log(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)
    log.append(make_ev(1))
    log2 = ChainLog(path)  # reopen
    e = log2.append(make_ev(2))
    assert e["seq"] == 2
    assert verify(path).ok


def test_tamper_detection_first_bad_seq(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)
    for i in range(5):
        log.append(make_ev(i))

    lines = open(path, encoding="utf-8").read().splitlines()
    ev = json.loads(lines[2])  # seq 3
    ev["status"] = "blocked"  # tamper content without fixing hash
    lines[2] = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    result = verify(path)
    assert result.ok is False
    assert result.count == 5
    assert result.first_bad_seq == 3
    assert result.errors


def test_tamper_prev_hash_link(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)
    for i in range(3):
        log.append(make_ev(i))
    lines = open(path, encoding="utf-8").read().splitlines()
    ev = json.loads(lines[1])
    ev["prev_hash"] = "1" * 64
    lines[1] = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    result = verify(path)
    assert result.ok is False
    assert result.first_bad_seq == 2


def test_seq_discontinuity_detected(tmp_path):
    path = str(tmp_path / "c.jsonl")
    log = ChainLog(path)
    for i in range(3):
        log.append(make_ev(i))
    lines = open(path, encoding="utf-8").read().splitlines()
    del lines[1]  # drop seq 2
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    result = verify(path)
    assert result.ok is False


def test_verify_missing_and_empty(tmp_path):
    missing = verify(str(tmp_path / "nope.jsonl"))
    assert missing.ok is False
    assert missing.count == 0

    empty = tmp_path / "empty.jsonl"
    empty.touch()
    result = verify(str(empty))
    assert result.ok is True
    assert result.count == 0


def test_verify_flags_non_object_line_without_crashing(tmp_path):
    path = tmp_path / "c.jsonl"
    log = ChainLog(str(path))
    log.append(make_ev(1))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("42\n")  # valid JSON, not an object
    result = verify(str(path))
    assert result.ok is False
    assert result.first_bad_seq == 2
    # readers tolerate it instead of raising
    assert [e["seq"] for e in ChainLog.read(str(path))] == [1]


def test_partial_trailing_line_does_not_brick_the_log(tmp_path):
    path = tmp_path / "c.jsonl"
    log = ChainLog(str(path))
    log.append(make_ev(1))
    log.append(make_ev(2))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "partial')  # crash mid-append: truncated line
    # Reopening must not raise, and the log stays appendable.
    reopened = ChainLog(str(path))
    e = reopened.append(make_ev(3))
    assert e["seq"] == 3
    assert e["prev_hash"] == ChainLog.read(str(path))[1]["hash"]
