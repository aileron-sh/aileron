# Adoption metrics

`history.jsonl` is an append-only record of this project's adoption signals —
one JSON object per collection run, written by
[`scripts/collect_metrics.py`](../scripts/collect_metrics.py) and committed by
the daily [Metrics workflow](../.github/workflows/metrics.yml).

## Why it's a committed file rather than a dashboard

GitHub's traffic API retains views and clones for **14 days only**. A day that
is never snapshotted cannot be recovered — not by querying later, not by
asking support. Everything else here (stars, downloads, contributors) can be
sampled at any time; traffic cannot. So the record is taken daily and stored
in-repo, where each entry also carries a git commit date as independent
corroboration of when it was taken.

The collector stores the **full per-day breakdown**, not just running totals,
so a missed run is backfilled by the next one inside the 14-day window. A gap
longer than that is permanent.

## What's recorded

| Field | Source | Notes |
|---|---|---|
| `repo` | GitHub API | stars, forks, watchers, open issues |
| `traffic` | GitHub traffic API | 14-day totals **plus** per-day arrays |
| `popular` | GitHub traffic API | referrers and paths |
| `community` | GitHub API | contributors, external issues/PRs |
| `releases` | GitHub API | tags and publication dates |
| `pypi` | pypistats + PyPI | downloads (day/week/month), versions, yanked |

## Honesty properties

These matter more than the numbers themselves — a metric that flatters the
project is worth less than one that can be trusted.

- **Maintainers are excluded from "external" counts.** `external_contributor_count`
  and `external_issue_count` filter out the logins in `AILERON_MAINTAINERS`
  (recorded in each snapshot as `maintainers_excluded`, so the exclusion list
  is auditable rather than implicit).
- **Failures are recorded, not hidden.** If an endpoint is unavailable the
  field holds `{"error": ...}` instead of a missing or zero value, so a gap is
  never mistaken for a real zero.
- **Downloads are not users.** PyPI counts include mirrors, CI, and bots.
  Treat them as an upper bound; unique clones and external issues are the
  better signals of actual interest.
- Nothing here is de-duplicated across time. Each row is what the APIs said on
  that date.

## Required setup: `METRICS_TOKEN`

**The scheduled job cannot collect traffic without this.** GitHub's traffic
endpoints require a *user* token with `repo` scope; the Actions
`GITHUB_TOKEN` is refused with HTTP 403 at every permission level. Traffic is
also the only field that expires, so this is the one piece of setup that
actually matters.

1. Create a token — either a classic PAT with `repo` scope, or a fine-grained
   token limited to this repository with **Administration: Read** and
   **Contents: Read**.
2. Add it to the repository as a secret named `METRICS_TOKEN`
   (Settings → Secrets and variables → Actions → New repository secret).

The workflow falls back to `GITHUB_TOKEN` when the secret is absent, which
collects everything *except* traffic and marks the run failed so the gap is
visible rather than silent.

Until the secret exists, capture traffic by hand — this works today and
backfills the last 14 days:

```console
$ GITHUB_TOKEN=$(gh auth token) python scripts/collect_metrics.py
```

## Usage

```console
$ python scripts/collect_metrics.py            # append a snapshot
$ python scripts/collect_metrics.py --summary  # print the trend
$ python scripts/collect_metrics.py --dry-run  # collect, print, write nothing
```

Requires `GITHUB_TOKEN` with repo scope (traffic endpoints need push access).
Locally: `GITHUB_TOKEN=$(gh auth token) python scripts/collect_metrics.py`.
