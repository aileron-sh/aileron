"""Aileron SDK instrumentation: the ``@track`` decorator and ``track_agent`` sessions.

Records hash-chained ``tool_call`` events for wrapped functions, enforces policy
rules (raising :class:`PolicyBlocked` on ``block``), and emits ``alert`` events
from behavioral-baseline flags.
"""
from __future__ import annotations

import functools
import json
import os
import time
import uuid
from contextvars import ContextVar
from typing import Any, Callable, TypeVar

from aileron import events
from aileron.chainlog import ChainLog
from aileron.policy import decide

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_LOG_PATH = "./aileron.chain.jsonl"

_FALLBACK_SESSION_ID = uuid.uuid4().hex
_current_agent: ContextVar[tuple[str, str, str] | None] = ContextVar(
    "aileron_current_agent", default=None
)
_default_log: ChainLog | None = None


class PolicyBlocked(RuntimeError):
    """Raised when a policy rule blocks a tracked tool call.

    The wrapped function is NOT executed; a ``tool_call`` event with
    ``status='blocked'`` and ``policy={'rule_id': ..., 'action': 'block'}``
    is recorded before this is raised.
    """

    def __init__(self, rule_id: str) -> None:
        self.rule_id = rule_id
        super().__init__(f"blocked by aileron rule {rule_id}")


def default_log() -> ChainLog:
    """Return the process-wide default ChainLog (env ``AILERON_LOG`` or ./aileron.chain.jsonl)."""
    global _default_log
    if _default_log is None:
        _default_log = ChainLog(os.environ.get("AILERON_LOG", DEFAULT_LOG_PATH))
    return _default_log


def _jsonable(obj: Any) -> Any:
    """Return obj if JSON-serializable, else its repr (so digests never fail)."""
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return repr(obj)


def track(
    tool_name: str | None = None,
    log: ChainLog | None = None,
    rules: list | None = None,
    baseline: Any | None = None,
) -> Callable[[F], F]:
    """Decorator recording each call of the wrapped function as a ``tool_call`` event.

    - ``tool_name``: override for the recorded tool name (defaults to ``fn.__name__``).
    - ``log``: ChainLog sink (defaults to the global default log).
    - ``rules``: policy rules; a ``block`` decision raises :class:`PolicyBlocked`
      and the wrapped function is not executed.
    - ``baseline``: anomaly baseline; ``flag()`` results are emitted as ``alert``
      events, then the event is observed.
    """

    def decorator(fn: F) -> F:
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sink = log if log is not None else default_log()
            session = _current_agent.get()
            if session is not None:
                session_id, agent_name, framework = session
            else:
                session_id, agent_name, framework = (
                    _FALLBACK_SESSION_ID,
                    "aileron-sdk",
                    "sdk",
                )
            arguments = {
                "args": [_jsonable(a) for a in args],
                "kwargs": {str(k): _jsonable(v) for k, v in kwargs.items()},
            }
            started = time.perf_counter()
            # Arguments are always attached in memory so policy rules can
            # match on content; ChainLog.append strips them at persist time
            # unless the sink was opened with capture_content=True.
            ev = events.new_event(
                "tool_call",
                session_id,
                agent_name,
                framework,
                tool={
                    "name": name,
                    "arguments": arguments,
                    "arguments_digest": events.digest(arguments),
                },
                meta={},
            )
            if rules:
                decision = decide(ev, rules)
                if decision.action == "block":
                    rule_id = decision.rule_ids[0]
                    ev["status"] = "blocked"
                    ev["policy"] = {"rule_id": rule_id, "action": "block"}
                    ev["latency_ms"] = (time.perf_counter() - started) * 1000.0
                    sink.append(ev)
                    raise PolicyBlocked(rule_id)
                if decision.rule_ids:
                    ev["policy"] = {
                        "rule_id": decision.rule_ids[0],
                        "action": decision.action,
                    }
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                ev["status"] = "error"
                ev["latency_ms"] = (time.perf_counter() - started) * 1000.0
                # The exception's str can embed argument values; record only
                # the type unless content capture is on, to honor the
                # digest-only promise.
                if getattr(sink, "capture_content", False):
                    err_text = f"{type(exc).__name__}: {exc}"
                else:
                    err_text = type(exc).__name__
                ev["meta"] = {**ev.get("meta", {}), "error": err_text}
                sink.append(ev)
                raise
            ev["status"] = "ok"
            ev["latency_ms"] = (time.perf_counter() - started) * 1000.0
            safe_result = _jsonable(result)
            ev["result_digest"] = events.digest(safe_result)
            ev["result"] = safe_result  # stripped at persist time unless capture_content
            sink.append(ev)
            if baseline is not None:
                flags = baseline.flag(ev)
                baseline.observe(ev)
                if flags:
                    sink.append(
                        events.new_event(
                            "alert",
                            session_id,
                            agent_name,
                            framework,
                            tool={"name": name},
                            meta={"flags": flags, "event_id": ev["id"]},
                        )
                    )
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


class AgentSession:
    """Context manager emitting ``agent_start``/``agent_end`` with its own session_id.

    While active, ``@track``-wrapped calls inherit this session's id and agent
    identity.
    """

    def __init__(self, name: str, framework: str, log: ChainLog | None = None) -> None:
        self.name = name
        self.framework = framework
        self.log = log
        self.session_id = uuid.uuid4().hex
        self._sink: ChainLog | None = None
        self._token: Any = None

    def __enter__(self) -> "AgentSession":
        self._sink = self.log if self.log is not None else default_log()
        self._token = _current_agent.set((self.session_id, self.name, self.framework))
        self._sink.append(
            events.new_event("agent_start", self.session_id, self.name, self.framework, meta={})
        )
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        try:
            ev = events.new_event(
                "agent_end", self.session_id, self.name, self.framework, meta={}
            )
            if exc_type is not None:
                ev["status"] = "error"
                # The exception's str can embed tool arguments; honor the
                # digest-only promise, matching track().
                if getattr(self._sink, "capture_content", False):
                    ev["meta"] = {"error": f"{exc_type.__name__}: {exc}"}
                else:
                    ev["meta"] = {"error": exc_type.__name__}
            assert self._sink is not None
            self._sink.append(ev)
        finally:
            if self._token is not None:
                _current_agent.reset(self._token)
                self._token = None
        return False


def track_agent(name: str, framework: str, log: ChainLog | None = None) -> AgentSession:
    """Create an :class:`AgentSession` context manager for an agent run."""
    return AgentSession(name, framework, log)
