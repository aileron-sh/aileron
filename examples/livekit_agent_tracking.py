"""Example: recording and policing a LiveKit Agents voice agent with Aileron.

LiveKit Agents (https://docs.livekit.io/agents/) runs voice and video agents.
Speech arrives over a LiveKit room, an LLM decides what to do, and the tools it
calls are ordinary Python ``async def`` functions decorated with
``@function_tool``. Those tool calls are the part a flight recorder cares
about. This example wraps each tool with Aileron's ``track`` and brackets the
session in ``track_agent``, so every call the LLM makes is journaled, checked
against policy before it runs, and verifiable offline afterwards.

LiveKit is the thing being recorded, not a transport. Aileron makes no network
calls and gains no dependency on LiveKit. The LiveKit-specific code is kept in
``build_agent`` and ``entrypoint``; the Aileron helpers (``guard_tool``,
``guard_tools``, ``policy_block_reply``) are plain functions that work with any
framework that calls ``async def`` tools, and they are unit tested in
``tests/test_examples.py`` with LiveKit absent.

Targeted API: livekit-agents 1.8.7 (Python 3.10+). That is ``AgentServer``
with ``@server.rtc_session()``, ``AgentSession(stt=..., llm=..., tts=...)``,
and ``@function_tool`` tools whose first parameter is ``context: RunContext``.
``ToolError`` carries a message the LLM is allowed to read.

Run without LiveKit (standard library only) to see the journal and the block:

    PYTHONPATH=src python3 examples/livekit_agent_tracking.py

Run as a real LiveKit agent:

    pip install "livekit-agents~=1.8"
    export LIVEKIT_URL=wss://<your-project>.livekit.cloud
    export LIVEKIT_API_KEY=...
    export LIVEKIT_API_SECRET=...
    # The models below run on LiveKit Inference with those credentials. If you
    # swap in a provider plugin, set its key too (OPENAI_API_KEY, DEEPGRAM_API_KEY, ...).
    PYTHONPATH=src python3 examples/livekit_agent_tracking.py dev

Afterwards: ``aileron verify livekit_demo.chain.jsonl`` and
``aileron report livekit_demo.chain.jsonl -o incident.html``.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import sys
from typing import Any, Awaitable, Callable

from aileron import ChainLog, PolicyBlocked, bundled_rules_dir, track, track_agent
from aileron.chainlog import verify
from aileron.policy import load_rules

try:
    from livekit.agents import (  # type: ignore[import-not-found]
        Agent,
        AgentServer,
        AgentSession,
        JobContext,
        RunContext,
        ToolError,
        cli,
        function_tool,
        inference,
    )

    HAVE_LIVEKIT = True
except ImportError:
    HAVE_LIVEKIT = False

    class RunContext:  # type: ignore[no-redef]
        """Stand-in for ``livekit.agents.RunContext`` so the tool signatures
        below read the same with or without LiveKit installed."""


RULES_DIR = bundled_rules_dir()
LOG_PATH = "livekit_demo.chain.jsonl"
AGENT_NAME = "voice-agent"
FRAMEWORK = "livekit"

INSTRUCTIONS = (
    "You are a concise voice assistant. Use your tools when they help. "
    "If a tool reports that an action was refused by policy, tell the user "
    "so in one sentence and do not try the same action again."
)

MISSING_LIVEKIT_NOTE = """\
LiveKit Agents is not installed, so this example ran its offline demo: the
same tools, wrapped the same way, driven by a scripted stand-in for the LLM.
To run it as a real voice agent, install the framework and give it a LiveKit
project to connect to: `pip install "livekit-agents~=1.8"`, then set
LIVEKIT_URL, LIVEKIT_API_KEY and LIVEKIT_API_SECRET (from your LiveKit Cloud
project or self-hosted server). The STT, LLM and TTS models used here run on
LiveKit Inference with those credentials; if you switch to a provider plugin,
set that provider's key as well (for example OPENAI_API_KEY). Then start the
worker with `python3 examples/livekit_agent_tracking.py dev`. Aileron itself
needs none of this: it only records what the agent does.
"""

AsyncTool = Callable[..., Awaitable[Any]]
BlockedHandler = Callable[[PolicyBlocked, str], Any]


# ---------------------------------------------------------------------------
# 1. Tool bodies: plain async functions, exactly as LiveKit wants them.
#    The first parameter is the RunContext LiveKit injects at call time; the
#    rest become the JSON schema the LLM sees. These are stubs that return
#    canned answers so the example never touches the network.
# ---------------------------------------------------------------------------


async def lookup_weather(context: RunContext, location: str) -> dict:
    """Look up the current weather for a location.

    Args:
        location: City name, for example "Lisbon".
    """
    return {"location": location, "weather": "sunny", "temperature_c": 21}


async def send_email(context: RunContext, to: str, subject: str, body: str) -> str:
    """Send an email on the user's behalf.

    Args:
        to: Recipient address.
        subject: Subject line.
        body: Message body.
    """
    return f"queued email to {to}"


async def shell(context: RunContext, cmd: str) -> str:
    """Run a shell command on the agent host and return its output.

    Args:
        cmd: The command line to run.
    """
    # Stub: a real tool would run the command. The bundled rule aileron-001
    # (rules/examples/destructive-shell.yml) matches tool name "shell" with
    # destructive arguments, which is why this function keeps that name. Use
    # guard_tool(..., tool_name="shell") if yours must be called something else.
    return f"<ran: {cmd}>"


TOOLS: list[AsyncTool] = [lookup_weather, send_email, shell]


# ---------------------------------------------------------------------------
# 2. Aileron helpers. No LiveKit here, so they can be tested and reused.
# ---------------------------------------------------------------------------


def policy_block_reply(exc: PolicyBlocked, tool_name: str) -> str:
    """What the LLM is told when policy refuses a tool call.

    The tool did not run. Rather than let PolicyBlocked unwind the voice
    session, hand the model a short explanation it can relay to the user.
    """
    return (
        f"The {tool_name} call was refused by security policy (rule {exc.rule_id}) "
        "and did not run. Tell the user plainly that this action is not permitted "
        "and offer a safe alternative. Do not retry it with different wording."
    )


def guard_tool(
    fn: AsyncTool,
    *,
    log: ChainLog,
    rules: list,
    tool_name: str | None = None,
    on_blocked: BlockedHandler = policy_block_reply,
) -> AsyncTool:
    """Wrap one ``async def`` tool so Aileron records and polices every call.

    ``track`` journals the call (digest-only by default), raises PolicyBlocked
    before the body runs when a rule says ``block``, and records status and
    latency across the await. This wrapper then converts PolicyBlocked into
    whatever ``on_blocked`` returns or raises, so the agent loop keeps going.

    The result keeps ``fn``'s name, docstring and signature, which is what
    ``function_tool`` reads to build the schema for the LLM.
    """
    if not inspect.iscoroutinefunction(fn):
        raise TypeError(f"{fn!r} is not an async def; LiveKit tools are coroutine functions")
    name = tool_name or fn.__name__
    tracked = track(tool_name=name, log=log, rules=rules)(fn)

    @functools.wraps(fn)
    async def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return await tracked(*args, **kwargs)
        except PolicyBlocked as exc:
            return on_blocked(exc, name)

    return guarded


def guard_tools(
    fns: list[AsyncTool],
    *,
    log: ChainLog,
    rules: list,
    on_blocked: BlockedHandler = policy_block_reply,
) -> list[AsyncTool]:
    """``guard_tool`` for a whole tool list, in order."""
    return [guard_tool(fn, log=log, rules=rules, on_blocked=on_blocked) for fn in fns]


# ---------------------------------------------------------------------------
# 3. LiveKit wiring. Only runs when livekit-agents is installed.
# ---------------------------------------------------------------------------

if HAVE_LIVEKIT:

    def raise_tool_error(exc: PolicyBlocked, tool_name: str) -> Any:
        """LiveKit flavour of ``on_blocked``: ToolError's message reaches the LLM
        as a tool failure rather than a tool result."""
        raise ToolError(policy_block_reply(exc, tool_name))

    def build_agent(log: ChainLog, rules: list) -> Agent:
        """An Agent whose tools are all guarded by Aileron.

        ``function_tool`` sees the guarded wrapper, which reports the original
        signature, so the schema the LLM receives is unchanged.
        """
        guarded = guard_tools(TOOLS, log=log, rules=rules, on_blocked=raise_tool_error)
        return Agent(instructions=INSTRUCTIONS, tools=[function_tool(fn) for fn in guarded])

    server = AgentServer()

    @server.rtc_session()
    async def entrypoint(ctx: JobContext) -> None:
        log = ChainLog(LOG_PATH)  # digest-only; pass capture_content=True for raw args
        rules = load_rules(RULES_DIR)

        session = AgentSession(
            stt=inference.STT("deepgram/nova-3"),
            llm=inference.LLM("openai/gpt-4.1-mini"),
            tts=inference.TTS("cartesia/sonic-3"),
        )
        closed = asyncio.Event()
        session.on("close", lambda _ev: closed.set())

        # One agent_start/agent_end pair per LiveKit job, with every tool call
        # in between attributed to this session id.
        with track_agent(AGENT_NAME, framework=FRAMEWORK, log=log):
            await session.start(agent=build_agent(log, rules), room=ctx.room)
            await session.generate_reply(instructions="Greet the user and offer to help.")
            await closed.wait()


# ---------------------------------------------------------------------------
# 4. Offline demo: the same guarded tools, driven by a scripted stand-in for
#    the LLM. Runs with the standard library only.
# ---------------------------------------------------------------------------


async def run_offline_demo(log_path: str = LOG_PATH) -> list[Any]:
    """Call each guarded tool the way the LLM would and return the replies."""
    log = ChainLog(log_path)
    rules = load_rules(RULES_DIR)
    weather, email, sh = guard_tools(TOOLS, log=log, rules=rules)
    ctx = RunContext()  # LiveKit injects the real one at call time
    replies: list[Any] = []

    with track_agent(AGENT_NAME, framework=FRAMEWORK, log=log):
        replies.append(await weather(ctx, location="Lisbon"))
        replies.append(await email(ctx, to="ops@example.com", subject="Hi", body="All good."))
        # Matches aileron-001: the body never runs and the LLM gets an
        # explanation instead of a crash.
        replies.append(await sh(ctx, cmd="rm -rf / --no-preserve-root"))
    return replies


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if HAVE_LIVEKIT and argv:
        # `dev`, `start`, `console`: LiveKit's own worker CLI.
        cli.run_app(server)
        return 0

    for reply in asyncio.run(run_offline_demo()):
        print(reply)
    result = verify(LOG_PATH)
    status = "VERIFIED" if result.ok else f"TAMPERED at seq {result.first_bad_seq}"
    print(f"chain {status}: {result.count} events in {LOG_PATH}")
    print("next: aileron report", LOG_PATH, "-o incident.html")
    if not HAVE_LIVEKIT:
        print()
        print(MISSING_LIVEKIT_NOTE, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
