"""Tests for the runnable examples under examples/.

The examples must import and work without the framework they demonstrate, so
these tests force the framework import to fail and exercise the Aileron-side
helpers with fake tools. No network, no servers, no API keys.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aileron import bundled_rules_dir  # noqa: E402
from aileron.chainlog import ChainLog, verify  # noqa: E402
from aileron.policy import Rule, load_rules  # noqa: E402
from aileron.sdk import PolicyBlocked  # noqa: E402


@pytest.fixture
def livekit_example(monkeypatch):
    """The LiveKit example module, imported with LiveKit guaranteed absent."""
    # A None entry in sys.modules makes `import livekit...` raise ImportError
    # even on a machine that happens to have the package.
    monkeypatch.setitem(sys.modules, "livekit", None)
    monkeypatch.setitem(sys.modules, "livekit.agents", None)
    monkeypatch.syspath_prepend(str(ROOT / "examples"))
    sys.modules.pop("livekit_agent_tracking", None)
    mod = importlib.import_module("livekit_agent_tracking")
    yield mod
    sys.modules.pop("livekit_agent_tracking", None)


def test_imports_without_livekit(livekit_example):
    assert livekit_example.HAVE_LIVEKIT is False
    assert not hasattr(livekit_example, "server"), "LiveKit wiring must not be defined"
    # The stand-in keeps the tool signatures readable.
    sig = inspect.signature(livekit_example.lookup_weather)
    assert list(sig.parameters) == ["context", "location"]


def test_guard_tool_records_happy_path(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    seen = []

    async def fake_tool(ctx, location: str) -> dict:
        """Fake weather."""
        seen.append(location)
        return {"ok": location}

    guarded = livekit_example.guard_tool(fake_tool, log=log, rules=[])
    assert inspect.iscoroutinefunction(guarded)
    assert guarded.__name__ == "fake_tool"
    assert guarded.__doc__ == "Fake weather."
    assert inspect.signature(guarded) == inspect.signature(fake_tool)

    assert asyncio.run(guarded(None, location="Oslo")) == {"ok": "Oslo"}
    assert seen == ["Oslo"]
    (ev,) = list(log)
    assert ev["type"] == "tool_call"
    assert ev["tool"]["name"] == "fake_tool"
    assert ev["status"] == "ok"
    assert ev["tool"]["arguments"] is None, "digest-only by default"
    assert ev["tool"]["arguments_digest"]
    assert verify(log.path).ok


def test_guard_tool_blocked_call_becomes_reply(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    rules = load_rules(bundled_rules_dir())
    ran = []

    async def shell(ctx, cmd: str) -> str:
        ran.append(cmd)
        return "ran"

    guarded = livekit_example.guard_tool(shell, log=log, rules=rules)
    reply = asyncio.run(guarded(None, cmd="rm -rf / --no-preserve-root"))

    assert ran == [], "the tool body must never run on a block"
    assert isinstance(reply, str)
    assert "aileron-001" in reply and "shell" in reply
    assert reply == livekit_example.policy_block_reply(PolicyBlocked("aileron-001"), "shell")
    (ev,) = list(log)
    assert ev["status"] == "blocked"
    assert ev["policy"] == {"rule_id": "aileron-001", "action": "block"}
    assert ev["tool"]["arguments"] is None
    assert "rm -rf" not in Path(log.path).read_text(encoding="utf-8")
    assert verify(log.path).ok


def test_guard_tool_tool_name_override_drives_policy(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    rules = load_rules(bundled_rules_dir())

    async def run_command(ctx, cmd: str) -> str:
        return "ran"

    guarded = livekit_example.guard_tool(run_command, log=log, rules=rules, tool_name="shell")
    reply = asyncio.run(guarded(None, cmd="mkfs /dev/sda"))
    assert "aileron-001" in reply
    assert list(log)[0]["tool"]["name"] == "shell"
    assert guarded.__name__ == "run_command", "the LLM-facing name is untouched"


def test_guard_tool_custom_blocked_handler_can_raise(livekit_example, tmp_path):
    """The LiveKit path raises ToolError; any exception type must pass through."""
    log = ChainLog(str(tmp_path / "c.jsonl"))
    rules = [
        Rule(
            id="t-001",
            title="block everything named nope",
            severity="high",
            match={"type": "tool_call", "tool.name": "nope"},
            action="block",
        )
    ]

    class FakeToolError(Exception):
        pass

    def raise_it(exc, tool_name):
        raise FakeToolError(livekit_example.policy_block_reply(exc, tool_name))

    async def nope(ctx) -> str:
        return "never"

    guarded = livekit_example.guard_tool(nope, log=log, rules=rules, on_blocked=raise_it)
    with pytest.raises(FakeToolError, match="t-001"):
        asyncio.run(guarded(None))
    assert list(log)[0]["status"] == "blocked"


def test_guard_tool_error_is_recorded_and_propagates(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    async def flaky(ctx) -> str:
        raise RuntimeError("upstream down: token=SECRET")

    guarded = livekit_example.guard_tool(flaky, log=log, rules=[])
    with pytest.raises(RuntimeError):
        asyncio.run(guarded(None))
    (ev,) = list(log)
    assert ev["status"] == "error"
    assert ev["meta"]["error"] == "RuntimeError"
    assert "SECRET" not in Path(log.path).read_text(encoding="utf-8")


def test_guard_tool_rejects_sync_functions(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    def not_async(ctx):
        return 1

    with pytest.raises(TypeError):
        livekit_example.guard_tool(not_async, log=log, rules=[])


def test_guard_tools_preserves_order_and_names(livekit_example, tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    guarded = livekit_example.guard_tools(livekit_example.TOOLS, log=log, rules=[])
    assert [g.__name__ for g in guarded] == ["lookup_weather", "send_email", "shell"]
    assert all(inspect.iscoroutinefunction(g) for g in guarded)


def test_offline_demo_journal(livekit_example, tmp_path):
    path = str(tmp_path / "demo.jsonl")
    replies = asyncio.run(livekit_example.run_offline_demo(path))

    assert replies[0] == {"location": "Lisbon", "weather": "sunny", "temperature_c": 21}
    assert replies[1] == "queued email to ops@example.com"
    assert "aileron-001" in replies[2]

    recs = list(ChainLog(path))
    assert [r["type"] for r in recs] == [
        "agent_start", "tool_call", "tool_call", "tool_call", "agent_end",
    ]
    assert recs[0]["agent"]["name"] == "voice-agent"
    assert recs[0]["agent"]["framework"] == "livekit"
    assert len({r["session_id"] for r in recs}) == 1
    assert [r["status"] for r in recs[1:4]] == ["ok", "ok", "blocked"]
    assert [r["tool"]["name"] for r in recs[1:4]] == ["lookup_weather", "send_email", "shell"]
    assert all(r["latency_ms"] >= 0 for r in recs[1:4])
    raw = Path(path).read_text(encoding="utf-8")
    assert "rm -rf" not in raw and "ops@example.com" not in raw
    assert verify(path).ok


def test_main_without_livekit_prints_setup_note(livekit_example, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert livekit_example.main([]) == 0
    out = capsys.readouterr().out
    assert "chain VERIFIED: 5 events" in out
    for needle in ("livekit-agents", "LIVEKIT_URL", "LIVEKIT_API_KEY", "LIVEKIT_API_SECRET"):
        assert needle in out
    assert (tmp_path / livekit_example.LOG_PATH).exists()
