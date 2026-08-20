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

## Usage

```console
$ python scripts/collect_metrics.py            # append a snapshot
$ python scripts/collect_metrics.py --summary  # print the trend
$ python scripts/collect_metrics.py --dry-run  # collect, print, write nothing
```

Requires `GITHUB_TOKEN` with repo scope (traffic endpoints need push access).
Locally: `GITHUB_TOKEN=$(gh auth token) python scripts/collect_metrics.py`.
