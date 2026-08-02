"""Aileron: flight recorder for AI agents.

Tamper-evident, hash-chained audit logging of agent actions with policy
enforcement, anomaly detection, OTel export, and HTML incident reports.

Sibling modules are lazy re-exported so that partial checkouts (where not
every module exists yet) can still import this package.
"""

from __future__ import annotations

from pathlib import Path

__version__ = "0.1.3"

__all__ = [
    "__version__",
    "ChainLog",
    "track",
    "track_agent",
    "PolicyBlocked",
    "load_rules",
    "Baseline",
    "verify",
    "bundled_rules_dir",
]


def bundled_rules_dir() -> Path:
    """Path to the example rules shipped inside the installed package.

    Works both from a source checkout and a ``pip install``ed wheel, so
    examples and ``aileron init`` can seed a working rule set without
    assuming the repository layout.
    """
    return Path(__file__).resolve().parent / "rules" / "examples"


def __getattr__(name: str):
    """Lazy re-export of sibling-module public API (SPEC signatures only)."""
    if name == "ChainLog":
        from .chainlog import ChainLog

        return ChainLog
    if name == "verify":
        from .chainlog import verify

        return verify
    if name == "track":
        from .sdk import track

        return track
    if name == "track_agent":
        from .sdk import track_agent

        return track_agent
    if name == "PolicyBlocked":
        from .sdk import PolicyBlocked

        return PolicyBlocked
    if name == "load_rules":
        from .policy import load_rules

        return load_rules
    if name == "Baseline":
        from .detect import Baseline

        return Baseline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
