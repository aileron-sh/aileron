"""Behavioral anomaly detection for Aileron.

``Baseline`` learns normal agent behavior from observed ``tool_call`` events
and flags anomalies *before* learning from a new event:

- ``first_seen_tool:<name>``  -- tool never seen in any session before
- ``rate_spike:<tool>``       -- trailing-60s call rate for the tool is more
  than 3x the stored baseline average rate (requires at least 5 prior
  observations of that tool so the baseline is meaningful)
- ``novel_sequence:<a>-><b>`` -- tool ``b`` directly follows tool ``a`` in a
  session, a transition never observed before

State is persisted as JSON: per-session tool counts, per-tool rolling call
timestamps, seen tool names, last tool per session, and observed
a->b transitions.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

RATE_WINDOW_SECONDS = 60.0
RATE_SPIKE_FACTOR = 3.0
RATE_MIN_OBSERVATIONS = 5
MAX_TIMESTAMPS_PER_TOOL = 1000


class Baseline:
    """Rolling behavioral baseline with JSON persistence."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        # session_id -> {tool_name: count}
        self.tool_counts: dict[str, dict[str, int]] = {}
        # tool_name -> [epoch seconds] (rolling, oldest first)
        self.tool_ts: dict[str, list[float]] = {}
        # all tool names ever observed
        self.seen_tools: set[str] = set()
        # session_id -> last tool name called in that session
        self.last_tool: dict[str, str] = {}
        # observed "a->b" transitions
        self.transitions: set[str] = set()
        if path is not None:
            self.load()

    # -- event helpers -----------------------------------------------------

    @staticmethod
    def _tool_name(event: dict) -> str | None:
        """Tool name for tool_call events, else None (event is ignored)."""
        if not isinstance(event, dict) or event.get("type") != "tool_call":
            return None
        tool = event.get("tool")
        if not isinstance(tool, dict):
            return None
        name = tool.get("name")
        return name if isinstance(name, str) and name else None

    @staticmethod
    def _event_ts(event: dict) -> float:
        """Epoch seconds from the event's RFC3339 'ts'; falls back to now."""
        ts = event.get("ts")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                pass
        return time.time()

    # -- detection ----------------------------------------------------------

    def flag(self, event: dict) -> list[str]:
        """Return anomaly flags for an event, compared against baseline state
        *before* the event is learned. Does not mutate state."""
        name = self._tool_name(event)
        if name is None:
            return []
        flags: list[str] = []

        if name not in self.seen_tools:
            flags.append(f"first_seen_tool:{name}")

        now = self._event_ts(event)
        prior = [t for t in self.tool_ts.get(name, []) if t <= now]
        if len(prior) >= RATE_MIN_OBSERVATIONS:
            span = prior[-1] - prior[0]
            if span > 0:
                baseline_rate = len(prior) / span  # calls per second
                in_window = sum(1 for t in prior if t > now - RATE_WINDOW_SECONDS)
                current_rate = (in_window + 1) / RATE_WINDOW_SECONDS
                if current_rate > RATE_SPIKE_FACTOR * baseline_rate:
                    flags.append(f"rate_spike:{name}")

        session = str(event.get("session_id") or "")
        last = self.last_tool.get(session)
        if last is not None and last != name and f"{last}->{name}" not in self.transitions:
            flags.append(f"novel_sequence:{last}->{name}")

        return flags

    # -- learning -----------------------------------------------------------

    def observe(self, event: dict) -> None:
        """Update baseline state from an event (call after flag())."""
        name = self._tool_name(event)
        if name is None:
            return
        session = str(event.get("session_id") or "")

        counts = self.tool_counts.setdefault(session, {})
        counts[name] = counts.get(name, 0) + 1

        ts_list = self.tool_ts.setdefault(name, [])
        ts_list.append(self._event_ts(event))
        ts_list.sort()
        del ts_list[:-MAX_TIMESTAMPS_PER_TOOL]

        self.seen_tools.add(name)

        last = self.last_tool.get(session)
        if last is not None and last != name:
            self.transitions.add(f"{last}->{name}")
        self.last_tool[session] = name

    # -- persistence --------------------------------------------------------

    def save(self) -> None:
        """Persist state to ``self.path`` as JSON. No-op when path is None."""
        if self.path is None:
            return
        data = {
            "version": 1,
            "tool_counts": self.tool_counts,
            "tool_ts": self.tool_ts,
            "seen_tools": sorted(self.seen_tools),
            "last_tool": self.last_tool,
            "transitions": sorted(self.transitions),
        }
        Path(self.path).write_text(
            json.dumps(data, sort_keys=True, indent=2), encoding="utf-8"
        )

    def load(self) -> None:
        """Load state from ``self.path``. Tolerant of a missing or corrupt
        file: the baseline simply starts/keeps empty state."""
        if self.path is None:
            return
        p = Path(self.path)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return

        counts = data.get("tool_counts")
        if isinstance(counts, dict):
            self.tool_counts = {
                str(s): {str(t): int(c) for t, c in tools.items() if isinstance(c, (int, float))}
                for s, tools in counts.items()
                if isinstance(tools, dict)
            }
        tool_ts = data.get("tool_ts")
        if isinstance(tool_ts, dict):
            self.tool_ts = {
                str(t): sorted(float(x) for x in xs if isinstance(x, (int, float)))
                for t, xs in tool_ts.items()
                if isinstance(xs, list)
            }
        seen = data.get("seen_tools")
        if isinstance(seen, list):
            self.seen_tools = {str(t) for t in seen}
        last = data.get("last_tool")
        if isinstance(last, dict):
            self.last_tool = {str(s): str(t) for s, t in last.items()}
        transitions = data.get("transitions")
        if isinstance(transitions, list):
            self.transitions = {str(tr) for tr in transitions}
