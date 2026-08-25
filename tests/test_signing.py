import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog
from aileron.events import new_event
from aileron.signing import (
    check_against_checkpoints,
    generate_keypair,
    sign_checkpoint,
    verify_checkpoint,
)


def make_log(tmp_path, name="chain.jsonl", n=3):
    path = str(tmp_path / name)
    log = ChainLog(path)
    for i in range(n):
        log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "t"}))
    return path


def test_generate_keypair(tmp_path):
    key_path, pub_path = generate_keypair(str(tmp_path))
    assert os.path.exists(key_path) and os.path.exists(pub_path)
    assert key_path.endswith("aileron_ed25519.key")
    assert pub_path.endswith("aileron_ed25519.pub")
    assert b"PRIVATE KEY" in open(key_path, "rb").read()
    assert b"PUBLIC KEY" in open(pub_path, "rb").read()


def test_sign_and_verify_roundtrip(tmp_path):
    key_path, pub_path = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path)

    ckpt = sign_checkpoint(log_path, key_path)
    assert ckpt["count"] == 3
    assert ckpt["log_path"] == log_path
    assert len(ckpt["tip_hash"]) == 64
    assert ckpt["signature"]
    assert ckpt["ts"].endswith("Z")

    ckpt_file = f"{log_path}.checkpoints.jsonl"
    assert os.path.exists(ckpt_file)
    lines = open(ckpt_file).read().splitlines()
    assert json.loads(lines[-1]) == ckpt

    # verify with private key path or public key path
    assert verify_checkpoint(log_path, key_path) is True
    assert verify_checkpoint(log_path, pub_path) is True

    # Checkpoints cover a prefix: legitimate appends do NOT invalidate them.
    ChainLog(log_path).append(new_event("alert", "s", "bot", "fw"))
    assert verify_checkpoint(log_path, key_path) is True
    ckpt2 = sign_checkpoint(log_path, key_path)
    assert ckpt2["count"] == 4
    assert verify_checkpoint(log_path, key_path) is True


def test_verify_checkpoint_prefix_semantics(tmp_path):
    """Growth after signing is fine; truncation below the prefix is not."""
    key_path, _pub = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path)
    sign_checkpoint(log_path, key_path)

    # Append two more events: checkpoint stays valid (prefix intact).
    log = ChainLog(log_path)
    log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "extra"}))
    log.append(new_event("agent_end", "s", "bot", "fw"))
    assert verify_checkpoint(log_path, key_path) is True

    # Truncate below the checkpointed count: must fail.
    lines = open(log_path, encoding="utf-8").read().splitlines()
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines[:2]) + "\n")
    assert verify_checkpoint(log_path, key_path) is False


def test_verify_checkpoint_tampered_log_fails(tmp_path):
    key_path, _ = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path)
    sign_checkpoint(log_path, key_path)

    lines = open(log_path, encoding="utf-8").read().splitlines()
    ev = json.loads(lines[0])
    ev["status"] = "blocked"
    lines[0] = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    open(log_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    assert verify_checkpoint(log_path, key_path) is False


def test_verify_checkpoint_wrong_key_fails(tmp_path):
    key_path, _ = generate_keypair(str(tmp_path / "a"))
    other_key, _ = generate_keypair(str(tmp_path / "b"))
    log_path = make_log(tmp_path)
    sign_checkpoint(log_path, key_path)
    assert verify_checkpoint(log_path, other_key) is False


def test_verify_checkpoint_no_checkpoints_file(tmp_path):
    key_path, _ = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path)
    assert verify_checkpoint(log_path, key_path) is False


def test_sign_refuses_broken_chain(tmp_path):
    key_path, _ = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path)
    lines = open(log_path, encoding="utf-8").read().splitlines()
    del lines[1]
    open(log_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        sign_checkpoint(log_path, key_path)


def test_private_key_created_restrictive_and_refuses_symlink(tmp_path):
    key_path, _pub = generate_keypair(str(tmp_path))
    mode = os.stat(key_path).st_mode & 0o777
    assert mode == 0o600, oct(mode)
    # Re-running is idempotent (regenerates in place, no crash).
    generate_keypair(str(tmp_path))
    assert (os.stat(key_path).st_mode & 0o777) == 0o600

    # A pre-planted symlink at the key path is refused, not followed.
    d2 = tmp_path / "d2"
    d2.mkdir()
    target = tmp_path / "attacker_target"
    os.symlink(target, d2 / "aileron_ed25519.key")
    with pytest.raises(OSError):
        generate_keypair(str(d2))
    assert not target.exists()


def test_checkpoint_reordering_cannot_roll_back_coverage(tmp_path):
    """Every valid checkpoint must hold, regardless of file order."""
    key_path, _pub = generate_keypair(str(tmp_path))
    log_path = make_log(tmp_path, n=3)
    sign_checkpoint(log_path, key_path)          # count=3
    log = ChainLog(log_path)
    for _ in range(3):
        log.append(new_event("tool_call", "s", "bot", "fw", tool={"name": "t"}))
    sign_checkpoint(log_path, key_path)          # count=6
    assert verify_checkpoint(log_path, key_path) is True

    # Reorder so the narrow checkpoint is last, then truncate to it.
    ckpt = f"{log_path}.checkpoints.jsonl"
    lines = open(ckpt, encoding="utf-8").read().splitlines()
    open(ckpt, "w", encoding="utf-8").write("\n".join([lines[1], lines[0]]) + "\n")
    kept = open(log_path, encoding="utf-8").read().splitlines()[:3]
    open(log_path, "w", encoding="utf-8").write("\n".join(kept) + "\n")
    assert verify_checkpoint(log_path, key_path) is False


def test_refuses_to_sign_empty_log(tmp_path):
    key_path, _pub = generate_keypair(str(tmp_path))
    empty = tmp_path / "empty.jsonl"
    empty.touch()
    with pytest.raises(ValueError, match="empty log"):
        sign_checkpoint(str(empty), key_path)


def test_public_key_write_refuses_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL", encoding="utf-8")
    keydir = tmp_path / "keys"
    keydir.mkdir()
    os.symlink(victim, keydir / "aileron_ed25519.pub")
    with pytest.raises(OSError):
        generate_keypair(str(keydir))
    assert victim.read_text(encoding="utf-8") == "ORIGINAL"


def test_deleting_an_intermediate_checkpoint_is_detected(tmp_path):
    """Checkpoints are chained, so a gap in the sequence is caught."""
    key_path, _pub = generate_keypair(str(tmp_path))
    log_path = str(tmp_path / "a.jsonl")
    log = ChainLog(log_path)
    for c in range(3):
        for i in range(3):
            log.append(new_event("tool_call", "s", "b", "f", tool={"name": f"c{c}i{i}"}))
        sign_checkpoint(log_path, key_path)
    assert verify_checkpoint(log_path, key_path) is True

    ckpt = f"{log_path}.checkpoints.jsonl"
    lines = open(ckpt, encoding="utf-8").read().splitlines()
    open(ckpt, "w", encoding="utf-8").write("\n".join([lines[0], lines[2]]) + "\n")
    assert verify_checkpoint(log_path, key_path) is False


def test_reordering_alone_still_verifies_when_the_log_is_intact(tmp_path):
    """Order in the file is not meaningful; the signed index is."""
    key_path, _pub = generate_keypair(str(tmp_path))
    log_path = str(tmp_path / "a.jsonl")
    log = ChainLog(log_path)
    for c in range(2):
        for i in range(3):
            log.append(new_event("tool_call", "s", "b", "f", tool={"name": "t"}))
        sign_checkpoint(log_path, key_path)
    ckpt = f"{log_path}.checkpoints.jsonl"
    lines = open(ckpt, encoding="utf-8").read().splitlines()
    open(ckpt, "w", encoding="utf-8").write("\n".join([lines[1], lines[0]]) + "\n")
    assert verify_checkpoint(log_path, key_path) is True


@pytest.mark.parametrize("bad_count", [8.0, -8, "8", None, True, [8]])
def test_unusable_checkpoint_count_is_reported_not_skipped(tmp_path, bad_count):
    """A checkpoint that cannot be used must be said out loud.

    The cross-check is unauthenticated by design, so someone who can edit the
    checkpoints file can also delete it. The difference is what the operator
    sees. Deleting it leaves an obvious absence. Retyping `count` from 8 to 8.0
    leaves a checkpoint file sitting next to the log looking perfectly normal,
    and verify used to skip it in silence and print an unqualified
    "OK: 4 events verified" on a journal truncated from 8 events to 4.

    That is the exact answer check_against_checkpoints exists to prevent, so an
    unusable checkpoint is now a problem in its own right.
    """
    log_path = tmp_path / "j.chain.jsonl"
    log = ChainLog(str(log_path))
    for i in range(8):
        log.append(new_event("tool_call", "s", "a", "f", tool={"name": f"t{i}"}))
    generate_keypair(str(tmp_path))
    sign_checkpoint(str(log_path), str(tmp_path / "aileron_ed25519.key"))

    cp_path = Path(str(log_path) + ".checkpoints.jsonl")
    checkpoints = [json.loads(line) for line in cp_path.read_text().splitlines() if line.strip()]
    checkpoints[-1]["count"] = bad_count
    cp_path.write_text("\n".join(json.dumps(c) for c in checkpoints) + "\n")

    # Truncate the journal the checkpoint was supposed to protect.
    lines = log_path.read_text().splitlines()
    log_path.write_text("\n".join(lines[:4]) + "\n")

    problems = check_against_checkpoints(str(log_path))
    assert problems, (
        f"a checkpoint with count={bad_count!r} was skipped silently, so a "
        "truncated journal would verify as OK"
    )
    assert any("unusable count" in p for p in problems), problems


def test_honest_checkpoint_still_passes_on_an_intact_log(tmp_path):
    """The fix must not make ordinary verification noisy."""
    log_path = tmp_path / "j.chain.jsonl"
    log = ChainLog(str(log_path))
    for i in range(5):
        log.append(new_event("tool_call", "s", "a", "f", tool={"name": f"t{i}"}))
    generate_keypair(str(tmp_path))
    sign_checkpoint(str(log_path), str(tmp_path / "aileron_ed25519.key"))
    assert check_against_checkpoints(str(log_path)) == []
