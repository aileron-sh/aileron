"""Measure the latency the Aileron MCP proxy adds to a tools/call round-trip.

Method: drive an identical stdio MCP child server two ways - directly, and
through `aileron proxy` - and subtract. The delta is the proxy's cost:
JSON-RPC parse, policy evaluation, hash-chain append, re-serialization, and
the extra process hop. The absolute baseline is reported alongside the delta
so the subtraction can be checked rather than taken on trust.

Requests are sequential (send, wait for response), which is how an agent
actually calls tools. That is the honest baseline; it does not model many
concurrent clients.

    python scripts/benchmark.py                     # 2000 calls per config
    python scripts/benchmark.py -n 5000             # more samples
    python scripts/benchmark.py --payload 32768     # one argument size
    python scripts/benchmark.py --json out.json     # machine-readable
    python scripts/benchmark.py --baseline b.json --max-regression 2.0

Reported numbers include the chain-log write, so they reflect what a user
pays in production, not just parsing.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# A minimal stdio MCP server: newline-delimited JSON-RPC, echoes tools/call.
# Kept trivial on purpose - we are measuring the proxy, not the server.
CHILD = (
    "import sys, json\n"
    "for line in sys.stdin:\n"
    "    line = line.strip()\n"
    "    if not line:\n"
    "        continue\n"
    "    req = json.loads(line)\n"
    "    out = {'jsonrpc': '2.0', 'id': req.get('id'), 'result': {'ok': True}}\n"
    "    sys.stdout.write(json.dumps(out) + '\\n')\n"
    "    sys.stdout.flush()\n"
)

PAYLOAD_SIZES = (64, 4096, 32768)
_COLS = ("mean", "median", "p95", "p99")


def _request(seq: int, payload: str) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": seq,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": payload}},
            }
        ).encode()
        + b"\n"
    )


def _drive(proc: subprocess.Popen, n: int, warmup: int, payload: str) -> list[float]:
    """Send n+warmup sequential calls; return per-call latencies in ms."""
    assert proc.stdin is not None and proc.stdout is not None
    latencies: list[float] = []
    for i in range(warmup + n):
        start = time.perf_counter()
        proc.stdin.write(_request(i, payload))
        proc.stdin.flush()
        line = proc.stdout.readline()
        elapsed = (time.perf_counter() - start) * 1000.0
        if not line:
            raise RuntimeError("child closed the stream early")
        if i >= warmup:  # discard warmup: import cost, page faults, cache warming
            latencies.append(elapsed)
    return latencies


def bench_direct(n: int, warmup: int, payload: str) -> list[float]:
    """Baseline: talk to the child server with no proxy in the path."""
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    try:
        return _drive(proc, n, warmup, payload)
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)


def bench_proxied(n: int, warmup: int, payload: str, rules: str | None) -> list[float]:
    """Same child, but every call traverses `aileron proxy`."""
    with tempfile.TemporaryDirectory() as tmp:
        argv = [sys.executable, "-m", "aileron.cli", "proxy",
                "--log", str(Path(tmp) / "bench.chain.jsonl")]
        if rules:
            argv += ["--rules", rules]
        argv += ["--", sys.executable, "-c", CHILD]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            return _drive(proc, n, warmup, payload)
        finally:
            proc.stdin.close()
            proc.wait(timeout=60)


def stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def pct(p: float) -> float:
        return ordered[min(int(len(ordered) * p), len(ordered) - 1)]

    return {
        "mean": statistics.fmean(ordered),
        "median": statistics.median(ordered),
        "p95": pct(0.95),
        "p99": pct(0.99),
    }


def _row(label: str, s: dict[str, float]) -> str:
    return f"{label:<30}" + "".join(f"{s[c]:>10.3f}" for c in _COLS)


# A run of one repeated character is the friendliest possible input both to
# the regex engine, which fails on the first character everywhere, and to the
# literal prefilter, which finds nothing anywhere. Measuring with it flattered
# the result by about 3x once rules started prefiltering. This looks like real
# tool arguments instead: English words, paths, flags, quotes and punctuation.
# It is fixed text rather than random so the benchmark stays reproducible, and
# a test asserts no bundled rule fires on it, because measuring the alert path
# would not be measuring the same thing.
_FILLER = (
    "The service reads its configuration at start up and then waits.\n"
    "path: /srv/app/config.yaml\n"
    "args: [--data-dir, /var/lib/app, --verbose]\n"
    "def handler(request):\n"
    '    data = request.get("body")\n'
    '    return {"ok": True, "count": 3}\n'
)


PAYLOAD_SHAPE = "realistic-text-v1"


def make_payload(size: int) -> str:
    """Deterministic filler of exactly ``size`` characters."""
    return (_FILLER * (size // len(_FILLER) + 1))[:size]


def measure(payload_size: int, calls: int, warmup: int, rules_dir: str) -> dict:
    payload = make_payload(payload_size)
    direct = stats(bench_direct(calls, warmup, payload))
    proxied = stats(bench_proxied(calls, warmup, payload, None))
    ruled = stats(bench_proxied(calls, warmup, payload, rules_dir))
    return {
        "payload_bytes": payload_size,
        "direct": direct,
        "proxy": proxied,
        "proxy_with_rules": ruled,
        "added_overhead": {c: ruled[c] - direct[c] for c in _COLS},
    }


def _print_table(result: dict) -> None:
    print(f"\n### tool arguments: {result['payload_bytes']} B")
    print(f"{'configuration':<30}" + "".join(f"{c:>10}" for c in _COLS) + "   (ms)")
    print("-" * 72)
    print(_row("direct to child (baseline)", result["direct"]))
    print(_row("through proxy (no rules)", result["proxy"]))
    print(_row("through proxy + rules", result["proxy_with_rules"]))
    print("-" * 72)
    print(_row("ADDED OVERHEAD", result["added_overhead"]))


def _check_regression(document: dict, baseline_path: str, factor: float) -> int:
    """Compare median overhead against a committed baseline.

    Deliberately tolerant: CI runners are noisy and shared, so only a large
    regression should fail. The point is to catch silent decay, not to gate on
    ordinary variance.
    """
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    by_size = {r["payload_bytes"]: r for r in baseline["results"]}
    print(f"\nregression check vs {baseline_path} (allowed: {factor}x median)")

    # Rule-pack size is part of the workload, not of the code. Comparing a
    # 32-rule run against a 2-rule baseline reports a code regression that is
    # not there, which is exactly what happened once. Say so plainly. This
    # still fails the run: a bigger pack is a real cost users pay, and it must
    # be re-recorded deliberately rather than waved through, or a genuine
    # regression could hide behind a rules bump.
    was_rules = baseline.get("meta", {}).get("rules")
    now_rules = document.get("meta", {}).get("rules")
    if was_rules is not None and now_rules is not None and was_rules != now_rules:
        print(f"  note: the bundled rule pack changed, {was_rules} rules -> "
              f"{now_rules}. Content rules are\n        matched against the whole "
              "payload, so cost scales with pack size as well as\n        payload "
              "size. Any difference below is workload, not necessarily code.")

    was_shape = baseline.get("meta", {}).get("payload_shape", "repeated-char")
    now_shape = document.get("meta", {}).get("payload_shape", "repeated-char")
    if was_shape != now_shape:
        print(f"  note: the payload shape changed, {was_shape} -> {now_shape}. "
              "How much work\n        the rules do depends on what the payload "
              "contains, so any difference\n        below is workload, not "
              "necessarily code.")
    print(f"{'payload':>10}{'baseline':>12}{'current':>12}{'ratio':>9}   verdict")
    failed = False
    for result in document["results"]:
        size = result["payload_bytes"]
        if size not in by_size:
            continue
        was = by_size[size]["added_overhead"]["median"]
        now = result["added_overhead"]["median"]
        ratio = now / was if was > 0 else float("inf")
        bad = ratio > factor
        failed = failed or bad
        print(f"{size:>10}{was:>12.3f}{now:>12.3f}{ratio:>8.2f}x   "
              f"{'REGRESSED' if bad else 'ok'}")
    if failed:
        print(f"\nMedian proxy overhead regressed by more than {factor}x. If that "
              "is intentional\n(e.g. a security fix that costs latency), re-record "
              "the baseline:\n  python scripts/benchmark.py --json "
              "scripts/benchmark_baseline.json")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-n", "--calls", type=int, default=2000,
                        help="measured calls per configuration (default: 2000)")
    parser.add_argument("--warmup", type=int, default=200,
                        help="discarded warmup calls (default: 200)")
    parser.add_argument("--payload", type=int, default=None,
                        help="single tool-argument size in bytes "
                             "(default: 64, 4096, 32768)")
    parser.add_argument("--json", metavar="PATH",
                        help="also write machine-readable results here")
    parser.add_argument("--baseline", metavar="PATH",
                        help="compare median overhead against a previous --json run")
    parser.add_argument("--max-regression", type=float, default=2.0,
                        help="fail if median overhead exceeds the baseline by this "
                             "factor (default: 2.0)")
    args = parser.parse_args(argv)

    from aileron import __version__, bundled_rules_dir

    rules_dir = str(bundled_rules_dir())
    sizes = (args.payload,) if args.payload is not None else PAYLOAD_SIZES

    meta = {
        "aileron": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "calls_per_config": args.calls,
        "warmup": args.warmup,
        "mode": "sequential stdio",
        "rules": len(list(Path(rules_dir).glob("*.yml"))),
        # Payload shape belongs in the baseline for the same reason rule count
        # does. Changing the filler changes how much work the rules do, and
        # without this a shape change reads as a code regression.
        "payload_shape": PAYLOAD_SHAPE,
    }
    print(f"aileron {meta['aileron']} | Python {meta['python']} | {meta['platform']}")
    print(f"{args.calls} sequential tools/call per configuration, "
          f"{args.warmup} warmup discarded")
    print(f"{meta['rules']} bundled rules loaded for the '+ rules' configuration")

    results = [measure(size, args.calls, args.warmup, rules_dir) for size in sizes]
    for result in results:
        _print_table(result)

    print("\nADDED OVERHEAD = (through proxy + rules) - (direct to child). It "
          "covers JSON-RPC\nparsing, policy evaluation, hash-chain append, "
          "re-serialization, and the extra\nprocess hop. Sequential stdio - this "
          "is not a concurrent-client benchmark.")

    document = {"meta": meta, "results": results}
    if args.json:
        Path(args.json).write_text(json.dumps(document, indent=2) + "\n",
                                   encoding="utf-8")
        print(f"\nwrote {args.json}")

    if args.baseline:
        return _check_regression(document, args.baseline, args.max_regression)
    return 0


if __name__ == "__main__":
    sys.exit(main())
