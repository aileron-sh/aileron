"""Record a dated snapshot of Aileron's adoption signals.

Appends one JSON object per run to ``metrics/history.jsonl``. The file is
committed, so the record is version-controlled and every entry carries a git
commit date as independent corroboration of when it was taken.

Why this exists: GitHub's traffic API retains views and clones for **14 days
only**. A day that is never snapshotted is gone permanently - no query, no
support ticket, and no amount of money recovers it. So this stores the full
per-day breakdown rather than just the running totals: if a scheduled run is
missed, the next run within the window backfills it.

    python scripts/collect_metrics.py                  # append a snapshot
    python scripts/collect_metrics.py --summary        # trend from history
    python scripts/collect_metrics.py --dry-run        # print, do not write

Needs GITHUB_TOKEN with repo scope (the Actions token works; locally,
`GITHUB_TOKEN=$(gh auth token)`). Traffic endpoints require push access.
Every collector fails soft: one unavailable endpoint must not cost the whole
snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = os.environ.get("AILERON_REPO", "Aileron-sh/aileron")
PYPI_PACKAGE = os.environ.get("AILERON_PYPI", "aileron")
# Logins that are the project itself, not independent interest. Counting the
# maintainer as an "external contributor" would inflate the one number that
# most needs to be trustworthy.
MAINTAINERS = {
    m.strip().lower()
    for m in os.environ.get("AILERON_MAINTAINERS", "aileron-sh,k3vs3c").split(",")
    if m.strip()
}
HISTORY = Path("metrics/history.jsonl")
UA = "aileron-metrics/1.0 (+https://github.com/Aileron-sh/aileron)"


def _get(url: str, token: str | None = None, accept: str = "application/vnd.github+json",
         retries: int = 3):
    """GET and decode JSON, retrying transient rate limits with backoff."""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            transient = exc.code in (403, 429, 500, 502, 503, 504)
            if not transient or attempt == retries - 1:
                raise
            time.sleep(2 ** attempt * 3)
    raise RuntimeError("unreachable")


def _try(label: str, fn):
    """Run a collector; record why it failed rather than losing the snapshot."""
    try:
        return fn()
    except urllib.error.HTTPError as exc:
        print(f"  ! {label}: HTTP {exc.code}", file=sys.stderr)
        return {"error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001 - never lose a snapshot to one endpoint
        print(f"  ! {label}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {"error": f"{type(exc).__name__}: {exc}"}


def collect_repo(token):
    d = _get(f"https://api.github.com/repos/{REPO}", token)
    return {
        "stars": d["stargazers_count"],
        "forks": d["forks_count"],
        "watchers": d["subscribers_count"],
        "open_issues": d["open_issues_count"],
        "size_kb": d["size"],
        "pushed_at": d["pushed_at"],
    }


def collect_traffic(token):
    """Views and clones. The daily arrays are the whole point - keep them."""
    views = _get(f"https://api.github.com/repos/{REPO}/traffic/views", token)
    clones = _get(f"https://api.github.com/repos/{REPO}/traffic/clones", token)
    return {
        "views_14d": {"count": views.get("count"), "uniques": views.get("uniques")},
        "clones_14d": {"count": clones.get("count"), "uniques": clones.get("uniques")},
        "views_daily": views.get("views", []),
        "clones_daily": clones.get("clones", []),
    }


def collect_referrers(token):
    refs = _get(f"https://api.github.com/repos/{REPO}/traffic/popular/referrers", token)
    paths = _get(f"https://api.github.com/repos/{REPO}/traffic/popular/paths", token)
    return {
        "referrers": [{"source": r["referrer"], "count": r["count"],
                       "uniques": r["uniques"]} for r in refs],
        "paths": [{"path": p["path"], "count": p["count"],
                   "uniques": p["uniques"]} for p in paths],
    }


def collect_community(token):
    """Contributors and who is opening issues - the 'independent interest' signal."""
    contributors = _get(
        f"https://api.github.com/repos/{REPO}/contributors?per_page=100&anon=0", token)
    issues = _get(
        f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100", token)
    external_issues = [
        {"number": i["number"], "title": i["title"],
         "author": (i.get("user") or {}).get("login"),
         "created_at": i["created_at"],
         "is_pr": "pull_request" in i}
        for i in issues
        if (i.get("user") or {}).get("login", "").lower() not in MAINTAINERS
    ]
    return {
        "maintainers_excluded": sorted(MAINTAINERS),
        "contributors": [{"login": c["login"], "contributions": c["contributions"]}
                         for c in contributors],
        "contributor_count": len(contributors),
        "external_contributor_count": sum(
            1 for c in contributors if c["login"].lower() not in MAINTAINERS),
        "external_issues_and_prs": external_issues,
        "external_issue_count": len(external_issues),
    }


def collect_releases(token):
    rels = _get(f"https://api.github.com/repos/{REPO}/releases?per_page=100", token)
    return {
        "count": len(rels),
        "latest": rels[0]["tag_name"] if rels else None,
        "releases": [{"tag": r["tag_name"], "published_at": r["published_at"]}
                     for r in rels],
    }


def collect_pypi():
    """Download counts via pypistats (PyPI's own API no longer exposes these)."""
    recent = _get(f"https://pypistats.org/api/packages/{PYPI_PACKAGE}/recent",
                  accept="application/json")["data"]
    meta = _get(f"https://pypi.org/pypi/{PYPI_PACKAGE}/json", accept="application/json")
    releases = meta.get("releases", {})
    return {
        "downloads_last_day": recent.get("last_day"),
        "downloads_last_week": recent.get("last_week"),
        "downloads_last_month": recent.get("last_month"),
        "latest_version": meta["info"]["version"],
        "versions": sorted(releases),
        "yanked_versions": sorted(
            v for v, files in releases.items() if any(f.get("yanked") for f in files)),
    }


def snapshot() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("  ! GITHUB_TOKEN unset - GitHub metrics will be limited", file=sys.stderr)
    print(f"collecting {REPO} ...")
    return {
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "repo": _try("repo", lambda: collect_repo(token)),
        "traffic": _try("traffic", lambda: collect_traffic(token)),
        "popular": _try("referrers/paths", lambda: collect_referrers(token)),
        "community": _try("community", lambda: collect_community(token)),
        "releases": _try("releases", lambda: collect_releases(token)),
        "pypi": _try("pypi", collect_pypi),
    }


def _fmt(value):
    return "-" if value is None else value


def print_snapshot(s: dict) -> None:
    r, t, c, p = s.get("repo", {}), s.get("traffic", {}), s.get("community", {}), s.get("pypi", {})
    print(f"\n  {s['date']}")
    print(f"    stars {_fmt(r.get('stars'))}  forks {_fmt(r.get('forks'))}  "
          f"watchers {_fmt(r.get('watchers'))}")
    if "views_14d" in t:
        print(f"    views(14d) {_fmt(t['views_14d'].get('count'))} "
              f"({_fmt(t['views_14d'].get('uniques'))} unique)   "
              f"clones(14d) {_fmt(t['clones_14d'].get('count'))} "
              f"({_fmt(t['clones_14d'].get('uniques'))} unique)")
    print(f"    contributors {_fmt(c.get('contributor_count'))} "
          f"(external {_fmt(c.get('external_contributor_count'))})   "
          f"external issues/PRs {_fmt(c.get('external_issue_count'))}")
    print(f"    pypi {_fmt(p.get('latest_version'))}  "
          f"downloads: day {_fmt(p.get('downloads_last_day'))} / "
          f"week {_fmt(p.get('downloads_last_week'))} / "
          f"month {_fmt(p.get('downloads_last_month'))}")


def summarise() -> int:
    if not HISTORY.exists():
        print(f"no history yet at {HISTORY}")
        return 1
    rows = [json.loads(line) for line in HISTORY.read_text().splitlines() if line.strip()]
    print(f"{len(rows)} snapshot(s), {rows[0]['date']} .. {rows[-1]['date']}\n")
    print(f"{'date':<12}{'stars':>6}{'forks':>7}{'views14':>9}{'clones14':>10}"
          f"{'contrib':>9}{'ext.iss':>9}{'pypi/mo':>9}")
    for r in rows:
        repo, tr = r.get("repo", {}), r.get("traffic", {})
        com, py = r.get("community", {}), r.get("pypi", {})
        v = tr.get("views_14d", {}).get("count") if isinstance(tr.get("views_14d"), dict) else None
        cl = tr.get("clones_14d", {}).get("count") if isinstance(tr.get("clones_14d"), dict) else None
        print(f"{r['date']:<12}{str(_fmt(repo.get('stars'))):>6}"
              f"{str(_fmt(repo.get('forks'))):>7}{str(_fmt(v)):>9}{str(_fmt(cl)):>10}"
              f"{str(_fmt(com.get('contributor_count'))):>9}"
              f"{str(_fmt(com.get('external_issue_count'))):>9}"
              f"{str(_fmt(py.get('downloads_last_month'))):>9}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--summary", action="store_true", help="print the trend and exit")
    ap.add_argument("--dry-run", action="store_true", help="collect and print, do not write")
    args = ap.parse_args(argv)

    if args.summary:
        return summarise()

    s = snapshot()
    print_snapshot(s)
    if args.dry_run:
        print("\n(dry run - nothing written)")
        return 0

    # Traffic is the only field that cannot be recovered later. If it failed,
    # say so loudly rather than banking a snapshot with a hole in it.
    traffic_failed = isinstance(s.get("traffic"), dict) and "error" in s["traffic"]
    if traffic_failed:
        print("\n  WARNING: traffic collection failed - views/clones for today are\n"
              "  unrecoverable after 14 days. The Actions GITHUB_TOKEN cannot read\n"
              "  traffic endpoints; set a METRICS_TOKEN secret (see metrics/README.md)\n"
              "  or run this locally with GITHUB_TOKEN=$(gh auth token).",
              file=sys.stderr)

    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(s, sort_keys=True, separators=(",", ":")) + "\n")
    total = sum(1 for _ in HISTORY.open(encoding="utf-8"))
    print(f"\nappended to {HISTORY} ({total} snapshot(s) recorded)")
    if traffic_failed and os.environ.get("REQUIRE_TRAFFIC"):
        return 1  # snapshot is still recorded; the job is marked failed
    return 0


if __name__ == "__main__":
    sys.exit(main())
