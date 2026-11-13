"""Tests for the aileron CLI (argparse main())."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron import __version__
from aileron.chainlog import ChainLog
from aileron.cli import main
from aileron.events import new_event


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


def test_verify_missing_log_is_tampered(tmp_path, capsys):
    # Deleting the journal is tampering, so a missing log is a verdict (2),
    # not an operational error. The Go verifier says the same.
    assert main(["verify", str(tmp_path / "nope.jsonl")]) == 2
    assert "TAMPERED at seq None" in capsys.readouterr().err


def _assert_operational_error(capsys, code):
    # Unreadable input is exit 1 with an error line: never OK, never TAMPERED,
    # and never a traceback, because nothing was checked.
    out, err = capsys.readouterr()
    assert code == 1
    assert "error: cannot read" in err
    assert "TAMPERED" not in err and "OK" not in out


def test_verify_directory_is_an_operational_error(tmp_path, capsys):
    (tmp_path / "chain.jsonl").mkdir()
    _assert_operational_error(capsys, main(["verify", str(tmp_path / "chain.jsonl")]))


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="needs POSIX permissions and a non-root user")
def test_verify_unreadable_journal_is_an_operational_error(tmp_path, capsys):
    log = _build_chain(tmp_path / "chain.jsonl")
    log.chmod(0)
    try:
        try:
            log.open("rb").close()
        except PermissionError:
            pass
        else:
            pytest.skip("this filesystem still allows reading a mode 000 file")
        _assert_operational_error(capsys, main(["verify", str(log)]))
    finally:
        log.chmod(0o644)


@pytest.mark.skipif(sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="needs POSIX permissions and a non-root user")
def test_verify_journal_in_unsearchable_directory_counts_as_missing(tmp_path, capsys):
    # SPEC: missing means what os.path.exists says, so this is TAMPERED, exit 2.
    locked = tmp_path / "locked"
    locked.mkdir()
    log = _build_chain(locked / "chain.jsonl")
    locked.chmod(0)
    try:
        assert main(["verify", str(log)]) == 2
        assert "TAMPERED at seq None" in capsys.readouterr().err
    finally:
        locked.chmod(0o755)


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")
def test_checkpoints_file_that_cannot_be_opened_is_not_absent(tmp_path, capsys):
    # A symlink loop exists as far as the directory is concerned but cannot be
    # opened. It used to count as no checkpoints, so verify printed OK.
    log = _build_chain(tmp_path / "chain.jsonl")
    ckpt = tmp_path / "chain.jsonl.checkpoints.jsonl"
    ckpt.symlink_to(ckpt)
    _assert_operational_error(capsys, main(["verify", str(log)]))
    assert main(["init", "--dir", str(tmp_path / "keys")]) == 0
    capsys.readouterr()
    code = main(["verify-checkpoint", str(log), "--key", str(tmp_path / "keys" / "aileron_ed25519.pub")])
    err = capsys.readouterr().err
    assert code == 1 and "error: cannot read" in err and "FAILED" not in err


def test_verify_checkpoint_key_that_cannot_be_read_is_an_operational_error(tmp_path, capsys):
    log = _build_chain(tmp_path / "chain.jsonl")
    (tmp_path / "key.pub").mkdir()
    code = main(["verify-checkpoint", str(log), "--key", str(tmp_path / "key.pub")])
    out, err = capsys.readouterr()
    assert code == 1 and "error: cannot read key" in err and "OK:" not in out


def test_verify_unreadable_checkpoints_file_is_an_operational_error(tmp_path, capsys):
    log = _build_chain(tmp_path / "chain.jsonl")
    (tmp_path / "chain.jsonl.checkpoints.jsonl").mkdir()
    _assert_operational_error(capsys, main(["verify", str(log)]))


def test_verify_checkpoint_directory_journal_is_an_operational_error(tmp_path, capsys):
    # A real signed checkpoint, then a directory where the journal was: the
    # checkpoint is readable, the journal is not.
    log = _build_chain(tmp_path / "chain.jsonl")
    assert main(["init", "--dir", str(tmp_path / "keys")]) == 0
    assert main(["sign-checkpoint", str(log), "--key", str(tmp_path / "keys" / "aileron_ed25519.key")]) == 0
    log.rename(tmp_path / "moved.jsonl")
    log.mkdir()
    capsys.readouterr()
    code = main(["verify-checkpoint", str(log), "--key", str(tmp_path / "keys" / "aileron_ed25519.pub")])
    out, err = capsys.readouterr()
    assert code == 1
    assert "error: cannot read" in err
    assert "FAILED" not in err and "OK:" not in out


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


def test_verify_checkpoint_journal_that_shrinks_between_reads_is_an_error(tmp_path, capsys, monkeypatch):
    log = _build_chain(tmp_path / "chain.jsonl")
    assert main(["init", "--dir", str(tmp_path / "keys")]) == 0
    assert main(["sign-checkpoint", str(log), "--key", str(tmp_path / "keys" / "aileron_ed25519.key")]) == 0
    capsys.readouterr()
    # The second read finds nothing: rotated between the two reads. This used
    # to index past the end and stop with an IndexError traceback.
    import aileron.chainlog
    monkeypatch.setattr(aileron.chainlog.ChainLog, "read", classmethod(lambda cls, path: []))
    code = main(["verify-checkpoint", str(log), "--key", str(tmp_path / "keys" / "aileron_ed25519.pub")])
    out, err = capsys.readouterr()
    assert code == 1 and "changed while it was being verified (4 events, then 0)" in err
    assert "OK:" not in out and "FAILED" not in err


_RULES = str(Path(__file__).resolve().parents[1] / "src" / "aileron" / "rules" / "examples")


@pytest.mark.parametrize("argv", [
    ["report", "gone.jsonl", "-o", "out.html"],
    ["export", "gone.jsonl", "-o", "out.json"],
    ["detect", "gone.jsonl"],
    ["rules", "test", _RULES, "gone.jsonl"],
])
def test_reading_a_missing_journal_does_not_recreate_it(tmp_path, capsys, monkeypatch, argv):
    # main used to recreate the journal as an empty file, and report then gave
    # it a VERIFIED badge with exit 0.
    monkeypatch.chdir(tmp_path)
    assert main(argv) == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "gone.jsonl").exists()
    assert not (tmp_path / "out.html").exists()


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
    events = [json.loads(line) for line in chain.read_text().splitlines() if line.strip()]
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
    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
    Path(log_path).write_text("\n".join(lines[:keep]) + "\n", encoding="utf-8")


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
    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
    # Rebuild a same-length but different chain, so the chain itself is valid.
    import os
    os.remove(log_path)
    log = ChainLog(log_path)
    for i in range(len(lines)):
        log.append(new_event("tool_call", "s", "bot", "demo", tool={"name": f"forged{i}"}))
    assert main(["verify", log_path]) == 2
    assert "appears rewritten" in capsys.readouterr().err


def test_version_flag_prints_package_version(capsys):
    """``aileron --version`` must report the same version the package exports."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"aileron {__version__}"


def test_version_matches_pyproject():
    """The two places the version is written must agree, or releases drift."""
    text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in text


# ------------------------------------------------------------------- proxy


IDENTITY_ENV = ("AILERON_AGENT", "AILERON_FRAMEWORK", "AILERON_SESSION_ID")


@pytest.fixture
def proxy_stub(monkeypatch):
    """Stand in for run_proxy: records what the CLI resolved and starts no child.

    _cmd_proxy imports run_proxy lazily, so patching the module attribute is
    enough. The identity variables are cleared first so the developer's shell
    cannot leak into these tests.
    """
    import aileron.proxy as proxy_module

    for name in IDENTITY_ENV:
        monkeypatch.delenv(name, raising=False)
    calls: list[dict] = []

    def stub(child_argv, log, rules=None, **kwargs):
        calls.append({"child_argv": list(child_argv), "rules": rules, **kwargs})
        return 0

    monkeypatch.setattr(proxy_module, "run_proxy", stub)
    return calls


def test_proxy_identity_flags_reach_run_proxy(tmp_path, proxy_stub):
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--agent", "researcher",
                 "--framework", "crewai", "--session-id", "run-4821", "--", "child", "arg"]) == 0
    assert proxy_stub == [{"child_argv": ["child", "arg"], "rules": None, "session_id": "run-4821",
                           "agent_name": "researcher", "framework": "crewai"}]


def test_proxy_identity_env_fallback(tmp_path, proxy_stub, monkeypatch):
    monkeypatch.setenv("AILERON_AGENT", "env-agent")
    monkeypatch.setenv("AILERON_FRAMEWORK", "env-framework")
    monkeypatch.setenv("AILERON_SESSION_ID", "env-session")
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--", "child"]) == 0
    (call,) = proxy_stub
    assert call["agent_name"] == "env-agent"
    assert call["framework"] == "env-framework"
    assert call["session_id"] == "env-session"


def test_proxy_identity_flag_beats_env(tmp_path, proxy_stub, monkeypatch):
    monkeypatch.setenv("AILERON_AGENT", "env-agent")
    monkeypatch.setenv("AILERON_FRAMEWORK", "env-framework")
    monkeypatch.setenv("AILERON_SESSION_ID", "env-session")
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--agent", "flag-agent",
                 "--framework", "flag-framework", "--session-id", "flag-session", "--", "child"]) == 0
    (call,) = proxy_stub
    assert call["agent_name"] == "flag-agent"
    assert call["framework"] == "flag-framework"
    assert call["session_id"] == "flag-session"


def test_proxy_identity_defaults_when_nothing_set(tmp_path, proxy_stub):
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--", "child"]) == 0
    (call,) = proxy_stub
    assert call["session_id"] is None
    assert call["agent_name"] == "mcp-proxy"
    assert call["framework"] == "mcp"


@pytest.mark.parametrize("value", ["", "  "])
def test_proxy_identity_empty_env_is_unset(tmp_path, proxy_stub, monkeypatch, value):
    """Harness templates leave variables empty; that means unset, not an error."""
    for name in IDENTITY_ENV:
        monkeypatch.setenv(name, value)
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--", "child"]) == 0
    (call,) = proxy_stub
    assert (call["agent_name"], call["framework"], call["session_id"]) == ("mcp-proxy", "mcp", None)


BAD_IDENTITY = ["", " x", "x ", "a\nb", "a\x1b[31m", "a​b", "\xa0x", "x" * 129]
# An empty environment value is unset rather than bad (see the test above), so
# the env route leaves it out.
BAD_IDENTITY_CASES = [("flag", v) for v in BAD_IDENTITY] + [("env", v) for v in BAD_IDENTITY if v]


@pytest.mark.parametrize(("via", "value"), BAD_IDENTITY_CASES)
def test_proxy_identity_rejects_bad_values(tmp_path, proxy_stub, monkeypatch, capsys, via, value):
    """A bad identity exits 1 before a journal is opened or a child is started."""
    log = tmp_path / "run.jsonl"
    argv = ["proxy", "--log", str(log)]
    if via == "flag":
        argv += ["--agent", value]
    else:
        monkeypatch.setenv("AILERON_AGENT", value)
    assert main([*argv, "--", "child"]) == 1
    err = capsys.readouterr().err
    assert ("error: --agent:" if via == "flag" else "error: AILERON_AGENT:") in err
    assert "1 to 128 printable characters" in err
    assert not log.exists()
    assert proxy_stub == []


def test_proxy_identity_checked_before_rules(tmp_path, proxy_stub, capsys):
    """Identity is resolved before rules load, so the identity error is the one reported."""
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--rules", str(tmp_path / "no-such-rules"),
                 "--agent", " x", "--", "child"]) == 1
    err = capsys.readouterr().err
    assert "error: --agent:" in err
    assert "no-such-rules" not in err
    assert proxy_stub == []


@pytest.mark.parametrize("session_id", ["run-2026-10-19-07", "6f1c2a3e-9d2b-4c7e-8a1f-0b3d5e7f9a1c"])
def test_proxy_session_id_accepts_non_hex(tmp_path, proxy_stub, session_id):
    """A session id is any label that passes the identity rule, not a hex uuid."""
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--session-id", session_id, "--", "child"]) == 0
    assert proxy_stub[0]["session_id"] == session_id


def test_proxy_flags_after_double_dash_go_to_child(tmp_path, proxy_stub):
    """Everything after '--' belongs to the child, identity flags included."""
    assert main(["proxy", "--log", str(tmp_path / "run.jsonl"), "--", "child", "--agent", "x"]) == 0
    (call,) = proxy_stub
    assert call["child_argv"] == ["child", "--agent", "x"]
    assert call["agent_name"] == "mcp-proxy"


# -------------------------------------------------------------------- hook


HOOK_PAYLOAD = json.dumps({
    "session_id": "00893aaf-19fa-41d2-8238-13269b9b3ca0",
    "hook_event_name": "PreToolUse",
    "tool_name": "Read",
    "tool_input": {"file_path": "/etc/hostname"},
    "tool_use_id": "toolu_01ABC",
    "cwd": "/home/me/project",
    "permission_mode": "default",
}).encode("utf-8")


@pytest.fixture
def hook_env(monkeypatch):
    """Clear the identity and journal variables so the developer's shell cannot leak in."""
    for name in (*IDENTITY_ENV, "AILERON_LOG"):
        monkeypatch.delenv(name, raising=False)


def _hook_main(monkeypatch, argv, payload=HOOK_PAYLOAD) -> int:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
    return main(["hook", *argv])


def test_hook_dispatch_through_main(tmp_path, monkeypatch, capsys, hook_env):
    log = tmp_path / "hook.jsonl"
    assert _hook_main(monkeypatch, ["--log", str(log)]) == 0
    assert capsys.readouterr() == ("", "")
    (event,) = ChainLog.read(str(log))
    assert event["meta"]["transport"] == "claude-code-hook"
    assert event["tool"]["name"] == "Read"
    assert event["session_id"] == "00893aaf-19fa-41d2-8238-13269b9b3ca0"


def test_hook_missing_log_path_exits_2(tmp_path, monkeypatch, capsys, hook_env):
    # cwd is where a relative default would land, so the directory inspected below must be it.
    monkeypatch.chdir(tmp_path)
    assert _hook_main(monkeypatch, []) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "aileron: no journal path: pass --log or set AILERON_LOG; refusing to continue\n"
    assert list(tmp_path.iterdir()) == []


def test_hook_log_from_env(tmp_path, monkeypatch, hook_env):
    log = tmp_path / "from-env.jsonl"
    monkeypatch.setenv("AILERON_LOG", str(log))
    assert _hook_main(monkeypatch, []) == 0
    assert len(ChainLog.read(str(log))) == 1
    # A flag beats the variable.
    other = tmp_path / "from-flag.jsonl"
    assert _hook_main(monkeypatch, ["--log", str(other)]) == 0
    assert len(ChainLog.read(str(other))) == 1
    assert len(ChainLog.read(str(log))) == 1


def test_bad_identity_exits_2(tmp_path, monkeypatch, capsys, hook_env):
    """The proxy exits 1 on a bad identity; the hook must exit 2, because 1 lets the call run."""
    log = tmp_path / "hook.jsonl"
    monkeypatch.setenv("AILERON_AGENT", "a\nb")
    assert _hook_main(monkeypatch, ["--log", str(log)]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("aileron: AILERON_AGENT: must be 1 to 128 printable characters")
    assert err.endswith("; refusing to continue\n")
    assert not log.exists()
    monkeypatch.delenv("AILERON_AGENT")
    assert _hook_main(monkeypatch, ["--log", str(log), "--framework", "x" * 129]) == 2
    assert capsys.readouterr().err.startswith("aileron: --framework: must be 1 to 128")
    assert not log.exists()


def test_internal_error_exits_2(tmp_path, monkeypatch, capsys, hook_env):
    import aileron.hook as hook_module

    def boom(raw, options):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(hook_module, "run_hook", boom)
    assert _hook_main(monkeypatch, ["--log", str(tmp_path / "hook.jsonl")]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "aileron: hook failed (RuntimeError: unexpected); refusing to continue\n"


def test_hook_never_exits_1(tmp_path, monkeypatch, capsys, hook_env):
    """main() maps ValueError to exit 1 for other commands; the hook never lets one reach it."""
    import aileron.hook as hook_module

    def boom(raw, options):
        raise ValueError("a ValueError that escaped")

    monkeypatch.setattr(hook_module, "run_hook", boom)
    assert _hook_main(monkeypatch, ["--log", str(tmp_path / "hook.jsonl")]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err == "aileron: a ValueError that escaped; refusing to continue\n"


def test_hook_import_failure_exits_2(tmp_path, monkeypatch, capsys, hook_env):
    """A hook module that cannot be imported (pyyaml missing, broken checkout) is still exit 2, never 1.

    The handlers must not depend on a name bound inside the try: when the
    import is what failed, that name is unbound and the UnboundLocalError
    would escape main() as exit 1, which Claude Code treats as non-blocking.
    """
    monkeypatch.setitem(sys.modules, "aileron.hook", None)
    log = tmp_path / "hook.jsonl"
    assert _hook_main(monkeypatch, ["--log", str(log)]) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("aileron: hook failed (")
    assert "Error" in err
    assert err.endswith("; refusing to continue\n")
    assert not log.exists()


class _BrokenStderr:
    """A stderr whose reader has gone away: every write is a broken pipe."""

    def write(self, text):
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")


def test_hook_broken_stderr_still_exits_2(tmp_path, monkeypatch, hook_env):
    """Losing the message must not lose the exit code: the block is on disk and the code stays 2."""
    rules = tmp_path / "rm.yml"
    rules.write_text("id: local-001\ntitle: T\nmatch:\n  tool.arguments_contains: ['rm -rf']\naction: block\n",
                     encoding="utf-8")
    log = tmp_path / "hook.jsonl"
    payload = json.dumps({"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf /"}}).encode("utf-8")
    monkeypatch.setattr(sys, "stderr", _BrokenStderr())
    assert _hook_main(monkeypatch, ["--log", str(log), "--rules", str(rules)], payload) == 2
    (event,) = ChainLog.read(str(log))
    assert event["status"] == "blocked"
    # The config path, where nothing is journaled, exits 2 as well.
    assert _hook_main(monkeypatch, [], payload) == 2
    # A stderr of None would make print() fall back to stdout; the hook prints nothing instead.
    monkeypatch.setattr(sys, "stderr", None)
    assert _hook_main(monkeypatch, [], payload) == 2
