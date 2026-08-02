"""Measure the latency the Aileron MCP proxy adds to a tools/call round-trip.

Method: drive an identical stdio MCP child server two ways — directly, and
through `aileron proxy` — and subtract. The delta is the proxy's cost:
JSON-RPC parse, policy evaluation, hash-chain append, and the extra process
hop. Requests are sequential (send, wait for response), matching how an
agent actually calls tools.

    python benchmarks/bench_proxy.py                # 2000 calls, default
    python benchmarks/bench_proxy.py -n 5000        # more samples
    python benchmarks/bench_proxy.py --payload 4096 # larger tool arguments

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
# Kept trivial on purpose — we are measuring the proxy, not the server.
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
        if i >= warmup:  # discard warmup: import cost, page faults, JIT-ish effects
            latencies.append(elapsed)
    return latencies


def bench_direct(n: int, warmup: int, payload: str) -> list[float]:
    """Baseline: talk to the child server with no proxy in the path."""
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        return _drive(proc, n, warmup, payload)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


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
            proc.wait(timeout=30)


def stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    def pct(p: float) -> float:
        return ordered[min(int(len(ordered) * p), len(ordered) - 1)]
    return {
        "mean": statistics.fmean(ordered),
        "p50": pct(0.50),
        "p95": pct(0.95),
        "p99": pct(0.99),
    }


def _row(label: str, s: dict[str, float]) -> str:
    return (f"{label:<28} {s['mean']:>8.3f} {s['p50']:>8.3f} "
            f"{s['p95']:>8.3f} {s['p99']:>8.3f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--calls", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--payload", type=int, default=64,
                        help="tool-argument size in bytes")
    args = parser.parse_args(argv)

    from aileron import __version__, bundled_rules_dir

    payload = "x" * args.payload
    rules_dir = str(bundled_rules_dir())

    print(f"aileron {__version__} | Python {platform.python_version()} | "
          f"{platform.system()} {platform.machine()}")
    print(f"{args.calls} sequential tools/call, {args.warmup} warmup, "
          f"{args.payload}B arguments\n")

    direct = stats(bench_direct(args.calls, args.warmup, payload))
    proxied = stats(bench_proxied(args.calls, args.warmup, payload, None))
    ruled = stats(bench_proxied(args.calls, args.warmup, payload, rules_dir))

    print(f"{'round-trip (ms)':<28} {'mean':>8} {'p50':>8} {'p95':>8} {'p99':>8}")
    print("-" * 64)
    print(_row("direct to child", direct))
    print(_row("through proxy", proxied))
    print(_row("through proxy + rules", ruled))
    print("-" * 64)
    print(_row("proxy overhead (no rules)", {k: proxied[k] - direct[k] for k in direct}))
    print(_row("  + policy evaluation", {k: ruled[k] - proxied[k] for k in direct}))
    print(_row("TOTAL OVERHEAD (w/ rules)", {k: ruled[k] - direct[k] for k in direct}))
    print("\nOverhead includes JSON-RPC parse, policy check, hash-chain append,")
    print("and the extra process hop. Real MCP servers take orders of magnitude")
    print("longer than this echo child, so proxy cost is a rounding error in")
    print("practice — but measure on your own hardware before quoting a number.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
