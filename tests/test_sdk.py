"""Tests for aileron.sdk: @track, track_agent, PolicyBlocked, capture-content gating."""
from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


from aileron import events  # noqa: E402
from aileron.chainlog import ChainLog, verify  # noqa: E402
from aileron.policy import Rule  # noqa: E402
from aileron.sdk import PolicyBlocked, track, track_agent  # noqa: E402


def test_track_happy_path(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(tool_name="add", log=log)
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    recs = list(log)
    assert len(recs) == 1
    ev = recs[0]
    assert ev["type"] == "tool_call"
    assert ev["tool"]["name"] == "add"
    assert ev["tool"]["arguments_digest"] == events.digest({"args": [2, 3], "kwargs": {}})
    assert ev["status"] == "ok"
    assert ev["latency_ms"] is not None and ev["latency_ms"] >= 0
    assert ev["result_digest"] == events.digest(5)
    res = verify(log.path)
    assert res.ok, res.errors
    assert res.count == 1


def test_track_block_path(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={"type": "tool_call", "tool.name": "shell"},
            action="block",
        )
    ]
    called = []

    @track(log=log, rules=rules)
    def shell(cmd):
        called.append(cmd)
        return "ran"

    with pytest.raises(PolicyBlocked) as excinfo:
        shell("rm -rf /")
    assert excinfo.value.rule_id == "aileron-001"
    assert called == [], "wrapped function must NOT execute on block"
    recs = list(log)
    assert len(recs) == 1
    assert recs[0]["status"] == "blocked"
    assert recs[0]["policy"] == {"rule_id": "aileron-001", "action": "block"}
    assert verify(log.path).ok


def test_track_error_status(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        boom()
    ev = list(log)[0]
    assert ev["status"] == "error"
    assert "ValueError" in ev["meta"]["error"]


def test_track_agent_start_end(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    def ping():
        return "pong"

    with track_agent("bot", "langgraph", log) as sess:
        ping()
    recs = list(log)
    assert [r["type"] for r in recs] == ["agent_start", "tool_call", "agent_end"]
    assert all(r["session_id"] == sess.session_id for r in recs)
    assert recs[0]["agent"]["name"] == "bot"
    assert recs[0]["agent"]["framework"] == "langgraph"
    assert recs[-1]["type"] == "agent_end"
    assert verify(log.path).ok


def test_capture_content_gating(tmp_path):
    log_plain = ChainLog(str(tmp_path / "plain.jsonl"), capture_content=False)
    log_full = ChainLog(str(tmp_path / "full.jsonl"), capture_content=True)

    @track(log=log_plain)
    def f_plain(x):
        return {"v": x}

    @track(log=log_full)
    def f_full(x):
        return {"v": x}

    f_plain(7)
    f_full(7)
    plain = list(log_plain)[0]
    full = list(log_full)[0]
    assert plain["tool"].get("arguments") is None
    assert plain.get("result") is None
    assert plain["tool"]["arguments_digest"] == full["tool"]["arguments_digest"]
    assert full["tool"]["arguments"] == {"args": [7], "kwargs": {}}
    assert full["result"] == {"v": 7}


def test_baseline_flags_emit_alerts(tmp_path):
    class FakeBaseline:
        def __init__(self):
            self.calls = 0

        def flag(self, event):
            self.calls += 1
            return ["first_seen_tool:t"] if self.calls == 1 else []

        def observe(self, event):
            pass

    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log, baseline=FakeBaseline())
    def t():
        return 1

    t()
    t()
    recs = list(log)
    assert [r["type"] for r in recs] == ["tool_call", "alert", "tool_call"]
    assert recs[1]["meta"]["flags"] == ["first_seen_tool:t"]
    assert recs[1]["meta"]["event_id"] == recs[0]["id"]
    assert verify(log.path).ok


def test_block_rule_on_arguments_in_default_digest_mode(tmp_path):
    """Content rules must fire even when only digests are persisted.

    Regression test: policy decisions are made against the full in-memory
    call; capture_content only gates what is written to disk.
    """
    log = ChainLog(str(tmp_path / "c.jsonl"))  # capture_content=False default
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={
                "type": "tool_call",
                "tool.name": "shell",
                "tool.arguments_contains": ["rm -rf"],
            },
            action="block",
        )
    ]
    called = []

    @track(tool_name="shell", log=log, rules=rules)
    def shell(cmd):
        called.append(cmd)
        return "ran"

    with pytest.raises(PolicyBlocked) as excinfo:
        shell("rm -rf / --no-preserve-root")
    assert excinfo.value.rule_id == "aileron-001"
    assert called == []
    rec = list(log)[0]
    assert rec["status"] == "blocked"
    # Privacy posture intact: only the digest was persisted.
    assert rec["tool"]["arguments"] is None
    assert rec["tool"]["arguments_digest"]
    assert "rm -rf" not in open(log.path, encoding="utf-8").read()
    assert verify(log.path).ok


def test_agent_end_error_redacted_without_capture_content(tmp_path):
    """An exception string can embed tool arguments; digest-only must hold."""
    log = ChainLog(str(tmp_path / "c.jsonl"))
    with pytest.raises(ValueError):
        with track_agent("bot", "fw", log):
            raise ValueError("SECRET_TOKEN_abc123")
    raw = open(log.path, encoding="utf-8").read()
    assert "SECRET_TOKEN_abc123" not in raw
    assert "ValueError" in raw


# ---------------------------------------------------------------------------
# async def tools. LiveKit Agents, Pydantic AI and friends declare tools as
# coroutine functions; the event must describe the awaited call, not the
# creation of the coroutine object.
# ---------------------------------------------------------------------------


def test_track_async_happy_path(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(tool_name="add", log=log)
    async def add(a, b):
        await asyncio.sleep(0)
        return a + b

    assert inspect.iscoroutinefunction(add)
    assert asyncio.run(add(2, 3)) == 5
    recs = list(log)
    assert len(recs) == 1
    ev = recs[0]
    assert ev["type"] == "tool_call"
    assert ev["tool"]["name"] == "add"
    assert ev["tool"]["arguments_digest"] == events.digest({"args": [2, 3], "kwargs": {}})
    assert ev["status"] == "ok"
    assert ev["result_digest"] == events.digest(5), "digest of the awaited value, not a coroutine"
    assert verify(log.path).ok


def test_track_async_not_recorded_until_awaited(tmp_path):
    """Creating the coroutine is not a call; nothing is journaled until it runs."""
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    async def ping():
        return "pong"

    coro = ping()
    assert list(log) == []
    assert asyncio.run(coro) == "pong"
    assert len(list(log)) == 1


def test_track_async_blocked_body_never_runs(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={"type": "tool_call", "tool.name": "shell"},
            action="block",
        )
    ]
    called = []

    @track(log=log, rules=rules)
    async def shell(cmd):
        called.append(cmd)
        return "ran"

    with pytest.raises(PolicyBlocked) as excinfo:
        asyncio.run(shell("rm -rf /"))
    assert excinfo.value.rule_id == "aileron-001"
    assert called == [], "coroutine body must NOT execute on block"
    recs = list(log)
    assert len(recs) == 1
    assert recs[0]["status"] == "blocked"
    assert recs[0]["policy"] == {"rule_id": "aileron-001", "action": "block"}
    assert verify(log.path).ok


def test_track_async_error_status(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    async def boom():
        await asyncio.sleep(0)
        raise ValueError("SECRET_VALUE")

    with pytest.raises(ValueError):
        asyncio.run(boom())
    ev = list(log)[0]
    assert ev["status"] == "error"
    assert ev["meta"]["error"] == "ValueError"
    assert "SECRET_VALUE" not in open(log.path, encoding="utf-8").read()


def test_track_async_latency_spans_the_await(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    async def slow():
        await asyncio.sleep(0.05)
        return 1

    asyncio.run(slow())
    ev = list(log)[0]
    assert ev["latency_ms"] >= 40, ev["latency_ms"]


def test_track_async_content_rule_fires_in_digest_mode(tmp_path):
    """Arguments reach the policy engine in memory; the journal keeps digests."""
    log = ChainLog(str(tmp_path / "c.jsonl"))  # capture_content=False default
    rules = [
        Rule(
            id="aileron-001",
            title="Block destructive shell commands",
            severity="high",
            match={
                "type": "tool_call",
                "tool.name": "shell",
                "tool.arguments_contains": ["rm -rf"],
            },
            action="block",
        )
    ]
    called = []

    @track(tool_name="shell", log=log, rules=rules)
    async def shell(cmd):
        called.append(cmd)
        return "ran"

    assert asyncio.run(shell("ls /tmp")) == "ran"
    with pytest.raises(PolicyBlocked):
        asyncio.run(shell("rm -rf / --no-preserve-root"))
    assert called == ["ls /tmp"]
    ok, blocked = list(log)
    assert ok["status"] == "ok"
    assert blocked["status"] == "blocked"
    assert blocked["tool"]["arguments"] is None
    assert blocked["tool"]["arguments_digest"]
    assert "rm -rf" not in open(log.path, encoding="utf-8").read()
    assert verify(log.path).ok


def test_track_async_preserves_signature_and_identity(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    async def lookup(ctx, location: str) -> str:
        """Look up the weather."""
        return location

    wrapped = track(log=log)(lookup)
    assert inspect.iscoroutinefunction(wrapped)
    assert wrapped.__name__ == "lookup"
    assert wrapped.__doc__ == "Look up the weather."
    assert inspect.signature(wrapped) == inspect.signature(lookup)


def test_track_async_inside_track_agent(tmp_path):
    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log)
    async def ping():
        return "pong"

    async def run():
        with track_agent("voice-bot", "livekit", log) as sess:
            await ping()
            await ping()
        return sess.session_id

    session_id = asyncio.run(run())
    recs = list(log)
    assert [r["type"] for r in recs] == ["agent_start", "tool_call", "tool_call", "agent_end"]
    assert all(r["session_id"] == session_id for r in recs)
    assert recs[1]["agent"]["framework"] == "livekit"


def test_track_async_baseline_alerts(tmp_path):
    class FakeBaseline:
        def __init__(self):
            self.calls = 0

        def flag(self, event):
            self.calls += 1
            return ["first_seen_tool:t"] if self.calls == 1 else []

        def observe(self, event):
            pass

    log = ChainLog(str(tmp_path / "c.jsonl"))

    @track(log=log, baseline=FakeBaseline())
    async def t():
        return 1

    asyncio.run(t())
    asyncio.run(t())
    recs = list(log)
    assert [r["type"] for r in recs] == ["tool_call", "alert", "tool_call"]
    assert recs[1]["meta"]["event_id"] == recs[0]["id"]
    assert verify(log.path).ok


def test_sync_function_returning_awaitable_is_unchanged(tmp_path):
    """Only coroutine functions get the async wrapper; a plain def that hands
    back an awaitable is recorded when it returns, as before."""
    log = ChainLog(str(tmp_path / "c.jsonl"))

    async def inner():
        return 1

    @track(log=log)
    def outer():
        return inner()

    assert not inspect.iscoroutinefunction(outer)
    coro = outer()
    assert len(list(log)) == 1
    assert asyncio.run(coro) == 1
