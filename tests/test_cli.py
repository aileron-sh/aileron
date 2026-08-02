"""Tests for the aileron CLI (argparse main())."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron.chainlog import ChainLog  # noqa: E402
from aileron.cli import main  # noqa: E402
from aileron.events import new_event  # noqa: E402


def _build_chain(path: Path) -> Path:
    """Build a small valid chain via the chainlog API."""
    log = ChainLog(str(path))
    log.append(new_event("agent_start", "sess", "researcher", "demo"))
    log.append(new_event("tool_call", "sess", "researcher", "demo",
                         tool={"name": "read_file"}, latency_ms=5.0))
    log.append(new_event("tool_call", "sess", "researcher", "demo",
                         tool={"name": "shell"}, status="error",
                         latency_ms=12.0))
    log.append(new_event("agent_end", "sess", "researcher", "demo"))
    return path


def _tamper(path: Path) -> None:
    """Corrupt one event in place without re-hashing."""
    lines = path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[2])
    event["status"] = "ok"  # rewrite history: hide the shell error
    lines[2] = json.dumps(event, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ verify


def test_verify_happy_path_exit_0(tmp_path, capsys):
    log = _build_chain(tmp_path / "chain.jsonl")
    assert main(["verify", str(log)]) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "4 events" in out


def test_verify_tamper_exit_2(tmp_path, capsys):
    log = _build_chain(tmp_path / "chain.jsonl")
    _tamper(log)
    assert main(["verify", str(log)]) == 2
    err = capsys.readouterr().err
    assert "TAMPERED" in err


def test_verify_missing_log_nonzero(tmp_path, capsys):
    # SPEC: failure exits non-zero; a missing log is either an error (1)
    # or a failed verification (2) depending on the chainlog implementation.
    assert main(["verify", str(tmp_path / "nope.jsonl")]) != 0


# -------------------------------------------------------------------- init


def test_init_creates_keypair_log_rules(tmp_path, capsys):
    assert main(["init", "--dir", str(tmp_path)]) == 0
    assert (tmp_path / "aileron_ed25519.key").exists()
    assert (tmp_path / "aileron_ed25519.pub").exists()
    assert (tmp_path / "aileron.chain.jsonl").exists()
    assert (tmp_path / "rules").is_dir()


# -------------------------------------------------------------- checkpoints


def test_sign_and_verify_checkpoint(tmp_path):
    log = _build_chain(tmp_path / "chain.jsonl")
    assert main(["init", "--dir", str(tmp_path / "keys")]) == 0
    key = str(tmp_path / "keys" / "aileron_ed25519.key")
    assert main(["sign-checkpoint", str(log), "--key", key]) == 0
    assert (tmp_path / "chain.jsonl.checkpoints.jsonl").exists()
    assert main(["verify-checkpoint", str(log), "--key", key]) == 0
    _tamper(log)
    assert main(["verify-checkpoint", str(log), "--key", key]) == 1


# ----------------------------------------------------------- report/export


def test_report_command_writes_html_with_badge(tmp_path):
    log = _build_chain(tmp_path / "chain.jsonl")
    out = tmp_path / "report.html"
    assert main(["report", str(log), "-o", str(out)]) == 0
    assert out.exists()
    doc = out.read_text(encoding="utf-8")
    assert "VERIFIED 4 events" in doc


def test_report_command_tampered_chain_exit_2(tmp_path):
    log = _build_chain(tmp_path / "chain.jsonl")
    _tamper(log)
    out = tmp_path / "report.html"
    assert main(["report", str(log), "-o", str(out)]) == 2
    assert "TAMPERED at seq 3" in out.read_text(encoding="utf-8")


def test_export_command_writes_spans(tmp_path):
    log = _build_chain(tmp_path / "chain.jsonl")
    out = tmp_path / "spans.json"
    assert main(["export", str(log), "-o", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 4
    assert spans[1]["name"] == "execute_tool read_file"


# -------------------------------------------------------------- rules test


def test_rules_test_dry_run(tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "destructive.yml").write_text(
        "id: aileron-001\n"
        "title: Block destructive shell commands\n"
        "severity: high\n"
        "match:\n"
        "  type: tool_call\n"
        "  tool.name: shell\n"
        "action: block\n",
        encoding="utf-8",
    )
    log = _build_chain(tmp_path / "chain.jsonl")
    assert main(["rules", "test", str(rules_dir), str(log)]) == 0
    out = capsys.readouterr().out
    assert "block [aileron-001]" in out
    assert "allow" in out


# -------------------------------------------------------------------- demo


def test_demo_builds_chain_and_report(tmp_path, capsys):
    assert main(["demo", "--dir", str(tmp_path)]) == 0
    chain = tmp_path / "demo.chain.jsonl"
    report = tmp_path / "demo-report.html"
    assert chain.exists() and report.exists()
    events = [json.loads(l) for l in chain.read_text().splitlines() if l.strip()]
    types = [e["type"] for e in events]
    assert types[0] == "agent_start" and types[-1] == "agent_end"
    assert "alert" in types
    blocked = [e for e in events if e.get("status") == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["policy"]["action"] == "block"
    doc = report.read_text(encoding="utf-8")
    assert "VERIFIED" in doc
    summary = capsys.readouterr().out
    assert "VERIFIED" in summary


def test_detect_command_flags_and_saves_state(tmp_path, capsys):
    chain = tmp_path / "chain.jsonl"
    log = ChainLog(str(chain))
    log.append(new_event("tool_call", "sess", "bot", "demo",
                         tool={"name": "read_file"}))
    log.append(new_event("tool_call", "sess", "bot", "demo",
                         tool={"name": "shell"}))
    state = tmp_path / "baseline.json"

    assert main(["detect", str(chain), "--state", str(state), "--save"]) == 0
    out = capsys.readouterr().out
    assert "first_seen_tool:read_file" in out
    assert "first_seen_tool:shell" in out
    assert "novel_sequence:read_file->shell" in out
    assert state.exists()

    # Second run against saved state: both tools are known now.
    assert main(["detect", str(chain), "--state", str(state)]) == 0
    out = capsys.readouterr().out
    assert "first_seen_tool" not in out
    assert "novel_sequence:read_file->shell" not in out


def test_detect_save_requires_state(tmp_path, capsys):
    chain = tmp_path / "chain.jsonl"
    ChainLog(str(chain)).append(new_event("agent_start", "s", "bot", "demo"))
    assert main(["detect", str(chain), "--save"]) == 1
    assert "requires --state" in capsys.readouterr().err


def test_init_seeds_example_rules(tmp_path, capsys):
    assert main(["init", "--dir", str(tmp_path)]) == 0
    rules_dir = tmp_path / "rules"
    seeded = list(rules_dir.glob("*.yml"))
    assert {p.name for p in seeded} >= {"destructive-shell.yml", "secrets-exfil.yml"}
    # The seeded rules load and are usable.
    from aileron.policy import load_rules
    ids = {r.id for r in load_rules(str(rules_dir))}
    assert {"aileron-001", "aileron-002"} <= ids


def _log_with_checkpoint(tmp_path, n=6):
    """A valid log plus a signed checkpoint attesting to all n events."""
    from aileron.signing import generate_keypair, sign_checkpoint

    key, _pub = generate_keypair(str(tmp_path))
    log_path = str(tmp_path / "chain.jsonl")
    log = ChainLog(log_path)
    for i in range(n):
        log.append(new_event("tool_call", "s", "bot", "demo", tool={"name": f"t{i}"}))
    sign_checkpoint(log_path, key)
    return log_path


def _truncate(log_path, keep):
    lines = open(log_path, encoding="utf-8").read().splitlines()
    open(log_path, "w", encoding="utf-8").write("\n".join(lines[:keep]) + "\n")


def test_verify_detects_truncation_via_adjacent_checkpoints(tmp_path, capsys):
    """A truncated log is a valid shorter chain; the checkpoint proves otherwise."""
    log_path = _log_with_checkpoint(tmp_path)
    assert main(["verify", log_path]) == 0  # honest log passes

    _truncate(log_path, 3)
    assert main(["verify", log_path]) == 2
    err = capsys.readouterr().err
    assert "3 events but a checkpoint attests to 6" in err
    assert "appears truncated" in err


def test_verify_checkpoint_cross_check_can_be_skipped(tmp_path):
    """Deliberate rotation needs an escape hatch."""
    log_path = _log_with_checkpoint(tmp_path)
    _truncate(log_path, 3)
    assert main(["verify", log_path]) == 2
    assert main(["verify", log_path, "--skip-checkpoint-check"]) == 0


def test_verify_unaffected_when_no_checkpoints_exist(tmp_path):
    log_path = str(tmp_path / "plain.jsonl")
    log = ChainLog(log_path)
    for _ in range(3):
        log.append(new_event("tool_call", "s", "bot", "demo", tool={"name": "x"}))
    assert main(["verify", log_path]) == 0


def test_report_badge_reflects_checkpoint_contradiction(tmp_path):
    """A truncated journal must not render a VERIFIED report."""
    log_path = _log_with_checkpoint(tmp_path)
    _truncate(log_path, 3)
    out = tmp_path / "r.html"
    assert main(["report", log_path, "-o", str(out)]) == 2
    doc = out.read_text(encoding="utf-8")
    assert "TAMPERED" in doc
    assert "VERIFIED 3 events" not in doc


def test_verify_detects_rewrite_inside_checkpointed_prefix(tmp_path, capsys):
    """Same event count, different content within the signed prefix."""
    log_path = _log_with_checkpoint(tmp_path, n=4)
    lines = open(log_path, encoding="utf-8").read().splitlines()
    # Rebuild a same-length but different chain, so the chain itself is valid.
    import os
    os.remove(log_path)
    log = ChainLog(log_path)
    for i in range(len(lines)):
        log.append(new_event("tool_call", "s", "bot", "demo", tool={"name": f"forged{i}"}))
    assert main(["verify", log_path]) == 2
    assert "appears rewritten" in capsys.readouterr().err
