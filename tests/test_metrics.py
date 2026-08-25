"""Keep the adoption numbers honest.

These figures exist to answer "is anyone actually using this", and the answer
is only worth anything if it cannot be inflated by the project counting itself.
The metrics workflow commits its own snapshots, so it appears in the
contributors list; before this it was counted as an external contributor and
the headline number read 1 when the truth was 0.

Nothing here talks to the network. The classifiers are pure functions over the
shapes GitHub returns, which is the part that can be wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from collect_metrics import MAINTAINERS, _is_bot, _is_external  # noqa: E402


@pytest.mark.parametrize("account", [
    {"login": "github-actions[bot]", "type": "Bot"},
    {"login": "dependabot[bot]", "type": "Bot"},
    {"login": "github-actions[bot]"},          # type field missing
    {"login": "renovate[bot]", "type": "User"},  # type wrong, suffix right
    {"login": "someone", "type": "Bot"},         # suffix missing, type right
])
def test_bots_are_recognised(account):
    assert _is_bot(account) is True
    assert _is_external(account) is False


@pytest.mark.parametrize("login", sorted(MAINTAINERS))
def test_maintainers_are_not_external(login):
    assert _is_external({"login": login, "type": "User"}) is False
    assert _is_external({"login": login.upper(), "type": "User"}) is False


@pytest.mark.parametrize("account", [
    {"login": "a-real-person", "type": "User"},
    {"login": "Someone-Else", "type": "User"},
    {"login": "robotics-fan", "type": "User"},   # "bot" inside a name is not a bot
    {"login": "bottle", "type": "User"},
])
def test_real_people_count_as_external(account):
    assert _is_bot(account) is False
    assert _is_external(account) is True


@pytest.mark.parametrize("account", [{}, {"login": ""}, {"login": None}])
def test_missing_accounts_are_not_counted(account):
    """A deleted user comes back with no login. Never count it as interest."""
    assert _is_external(account) is False


def test_the_exact_case_that_was_wrong():
    """The metrics bot used to be the whole external contributor count.

    On 2026-08-24 the snapshot read external_contributor_count 1, and that 1
    was github-actions[bot] committing the snapshots themselves.
    """
    contributors = [
        {"login": "k3vs3c", "contributions": 39, "type": "User"},
        {"login": "github-actions[bot]", "contributions": 6, "type": "Bot"},
    ]
    assert sum(1 for c in contributors if _is_external(c)) == 0
