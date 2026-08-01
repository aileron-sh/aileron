"""Example: tracking LangChain-style tools with Aileron.

This script is intentionally runnable with the standard library only, so you
can try it before installing anything:

    PYTHONPATH=src python3 examples/langchain_tool_tracking.py

It duck-types the two LangChain interfaces that matter for instrumentation —
a tool object with a ``.run(...)``/callable body, and an agent "run" that
invokes tools. With real LangChain installed, the only change is the import:

    # Real LangChain (pip install langchain-core):
    # from langchain_core.tools import StructuredTool
    #
    # tool = StructuredTool.from_function(shell)          # then wrap as below
    # ... or pass callbacks via track_agent around agent.invoke(...)

The Aileron part is identical either way:

* ``@track``        wraps each tool function -> hash-chained ``tool_call``
                    events, policy enforcement (PolicyBlocked), latency.
* ``track_agent``   brackets one agent run -> ``agent_start``/``agent_end``
                    events that group the tool calls under one session_id.

After the run we verify the chain offline, because that is the point of a
flight recorder: the journal is evidence, not telemetry.
"""

from __future__ import annotations

from aileron import ChainLog, PolicyBlocked, bundled_rules_dir, track, track_agent
from aileron.chainlog import verify
from aileron.policy import load_rules

# The example rules ship inside the installed package, so this resolves the
# same way from a source checkout or a pip install.
RULES_DIR = bundled_rules_dir()
LOG_PATH = "langchain_demo.chain.jsonl"


# ---------------------------------------------------------------------------
# 1. Tool functions — the things your agent is allowed to do.
#    In real LangChain these would be @tool-decorated functions or
#    StructuredTool instances; Aileron wraps the same callables.
# ---------------------------------------------------------------------------

# Default digest-only mode: policy rules (including
# ``tool.arguments_contains``) see the full arguments in memory at decision
# time, but the journal on disk stores only SHA-256 digests. Pass
# capture_content=True only if you want raw arguments persisted for
# forensics.
log = ChainLog(LOG_PATH)
rules = load_rules(RULES_DIR)


@track(log=log, rules=rules)  # -> tool_call event on every call
def read_file(path: str) -> str:
    """Pretend file read."""
    return f"<contents of {path}>"


@track(tool_name="shell", log=log, rules=rules)  # tool_name overrides __name__
def shell(cmd: str) -> str:
    """Pretend shell — intercepted by rules/examples/destructive-shell.yml."""
    return f"<ran: {cmd}>"


# ---------------------------------------------------------------------------
# 2. A duck-typed "LangChain" tool wrapper.
#
#    Real LangChain:
#        from langchain_core.tools import StructuredTool
#        tool = StructuredTool.from_function(read_file, name="read_file")
#    The object below mimics the small surface an agent executor uses:
#    ``.name``, ``.description``, and ``.run(args)``.
# ---------------------------------------------------------------------------


class MiniTool:
    """Stand-in for langchain_core.tools.StructuredTool (stdlib only)."""

    def __init__(self, func, name: str, description: str):
        self.func = func
        self.name = name
        self.description = description

    def run(self, *args, **kwargs):
        return self.func(*args, **kwargs)


def main() -> None:
    tools = {
        "read_file": MiniTool(read_file, "read_file", "Read a file"),
        "shell": MiniTool(shell, "shell", "Run a shell command"),
    }

    # track_agent brackets one agent run: agent_start ... agent_end, with all
    # @track'd calls inside inheriting the session id and agent identity.
    # Real LangChain: wrap your agent.invoke(...) call the same way:
    #
    #     with track_agent("research-agent", framework="langchain", log=log):
    #         agent_executor.invoke({"input": task})
    #
    with track_agent("demo-agent", framework="langchain", log=log):
        # A benign tool call: logged, status=ok.
        print(tools["read_file"].run("/etc/hostname"))

        # A call that matches the block rule aileron-001 (rm -rf). The tool
        # body NEVER executes; the blocked attempt is recorded with
        # status='blocked'. Any production agent loop should catch
        # PolicyBlocked and report back to the planner instead of crashing.
        try:
            tools["shell"].run("rm -rf / --no-preserve-root")
        except PolicyBlocked as exc:
            print(f"shell call blocked by policy ({exc})")

    # Offline verification: recompute every hash and link.
    result = verify(LOG_PATH)
    status = "VERIFIED" if result.ok else f"TAMPERED at seq {result.first_bad_seq}"
    print(f"chain {status}: {result.count} events in {LOG_PATH}")
    print("next: aileron report", LOG_PATH, "-o incident.html")


if __name__ == "__main__":
    main()
