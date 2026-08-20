"""Aileron command-line interface.

Subcommands (per SPEC): init, verify, sign-checkpoint, verify-checkpoint,
report, export, rules test, proxy, demo.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_LOG = "aileron.chain.jsonl"
DEFAULT_KEY = "aileron_ed25519.key"
DEFAULT_PUB = "aileron_ed25519.pub"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aileron",
        description="Flight recorder for AI agents: tamper-evident audit "
        "logging, policy enforcement, and incident reports.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create keypair, chain log, and rules dir")
    p.add_argument("--dir", default=".", help="target directory (default: .)")

    p = sub.add_parser("verify", help="verify a hash-chained log")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("--skip-checkpoint-check", action="store_true",
                   help="do not cross-check an adjacent <log>.checkpoints.jsonl "
                        "(use when the log was deliberately rotated)")

    p = sub.add_parser("sign-checkpoint", help="sign the current log tip")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("--key", default=None, help="ed25519 private key (PEM)")

    p = sub.add_parser("verify-checkpoint", help="verify the latest checkpoint")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("--key", default=None, help="ed25519 private key (PEM)")

    p = sub.add_parser("report", help="render an HTML incident report")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("-o", "--out", required=True, help="output HTML path")
    p.add_argument("--title", default="Aileron Incident Report")
    p.add_argument("--skip-checkpoint-check", action="store_true",
                   help="do not cross-check an adjacent <log>.checkpoints.jsonl")

    p = sub.add_parser("export", help="export events as OTel spans JSON")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("-o", "--out", required=True, help="output JSON path")

    p = sub.add_parser("serve", help="read-only MCP server over your journals")
    p.add_argument("--root", default=".",
                   help="directory holding journals to serve (default: .)")

    p = sub.add_parser("detect", help="replay a log through the behavioral baseline")
    p.add_argument("log", help="path to chain JSONL log")
    p.add_argument("--state", default=None,
                   help="baseline state JSON (loaded if it exists)")
    p.add_argument("--save", action="store_true",
                   help="write the updated baseline back to --state")

    p = sub.add_parser("rules", help="policy rule utilities")
    rules_sub = p.add_subparsers(dest="rules_command", required=True)
    rt = rules_sub.add_parser("test", help="dry-run rules against a log")
    rt.add_argument("rules_path", help="rule file or directory")
    rt.add_argument("log", help="path to chain JSONL log")

    p = sub.add_parser("proxy", help="run an MCP stdio proxy around a command")
    p.add_argument("--log", required=True, help="path to chain JSONL log")
    p.add_argument("--rules", default=None, help="rules file or directory")
    p.add_argument(
        "--capture-content",
        action="store_true",
        help="record tool arguments/results (default: digests only)",
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- <cmd...>")

    p = sub.add_parser("demo", help="run a scripted fake-agent session")
    p.add_argument(
        "--dir",
        default=".",
        help="output directory for demo.chain.jsonl / demo-report.html",
    )
    return parser


# ---------------------------------------------------------------- commands


def _cmd_init(args: argparse.Namespace) -> int:
    """Create an ed25519 keypair, an empty chain log, and a seeded rules dir."""
    import shutil

    from . import bundled_rules_dir
    from .signing import generate_keypair

    target = Path(args.dir)
    target.mkdir(parents=True, exist_ok=True)
    key_path, pub_path = generate_keypair(str(target))
    log_path = target / DEFAULT_LOG
    log_path.touch(exist_ok=True)
    rules_dir = target / "rules"
    rules_dir.mkdir(exist_ok=True)
    # Seed the starter rules so a fresh install has something to enforce.
    seeded = 0
    for rule in sorted(bundled_rules_dir().glob("*.yml")):
        dest = rules_dir / rule.name
        if not dest.exists():
            shutil.copyfile(rule, dest)
            seeded += 1
    print(f"initialized aileron in {target.resolve()}")
    print(f"  keypair: {key_path} / {pub_path}")
    print(f"  log:     {log_path}")
    print(f"  rules:   {rules_dir} ({seeded} example rule(s) seeded)")
    return 0


def _checkpoint_problems(log_path: str, skip: bool) -> list[str]:
    """Inconsistencies between a log and its adjacent checkpoints file."""
    if skip:
        return []
    try:
        from .signing import check_against_checkpoints
    except ImportError:  # pragma: no cover - cryptography always present
        return []
    return check_against_checkpoints(log_path)


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify hash-chain integrity; exit 2 on tamper."""
    from .chainlog import verify

    result = verify(args.log)
    if not result.ok:
        for err in result.errors:
            print(f"error: {err}", file=sys.stderr)
        print(f"TAMPERED at seq {result.first_bad_seq} in {args.log}", file=sys.stderr)
        return 2

    # An intact chain is not the whole story: truncating the tail leaves a
    # perfectly valid shorter chain. If a checkpoint next to the log says more
    # events existed, that is evidence of tampering and must not be reported
    # as OK.
    problems = _checkpoint_problems(args.log, args.skip_checkpoint_check)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        print(f"TAMPERED: chain is internally valid but contradicts "
              f"{args.log}.checkpoints.jsonl", file=sys.stderr)
        print("note: signatures were not checked here - run "
              "'aileron verify-checkpoint' with the public key you trust.",
              file=sys.stderr)
        return 2

    print(f"OK: {result.count} events verified in {args.log}")
    return 0


def _default_key(log_path: str, key: str | None) -> str:
    if key:
        return key
    candidate = Path(log_path).parent / DEFAULT_KEY
    return str(candidate if candidate.exists() else Path(DEFAULT_KEY))


def _default_verify_key(log_path: str, key: str | None) -> str:
    """Default key for verification: prefer the public key so verifying
    hosts never need the private key present."""
    if key:
        return key
    parent = Path(log_path).parent
    for candidate in (parent / DEFAULT_PUB, parent / DEFAULT_KEY,
                      Path(DEFAULT_PUB), Path(DEFAULT_KEY)):
        if candidate.exists():
            return str(candidate)
    return str(Path(DEFAULT_PUB))


def _cmd_sign_checkpoint(args: argparse.Namespace) -> int:
    from .signing import sign_checkpoint

    checkpoint = sign_checkpoint(args.log, _default_key(args.log, args.key))
    print(f"checkpoint signed: {checkpoint['count']} events, "
          f"tip {checkpoint['tip_hash'][:16]}...")
    print(f"appended to {args.log}.checkpoints.jsonl")
    return 0


def _cmd_verify_checkpoint(args: argparse.Namespace) -> int:
    import hashlib

    from .signing import verify_checkpoint

    key = _default_verify_key(args.log, args.key)
    if not Path(key).exists():
        print(f"error: no verification key found (looked for {key}). "
              f"Pass --key with the public key you trust.", file=sys.stderr)
        return 1
    # The key IS the trust anchor. Resolving it from the directory under audit
    # means an attacker who can rewrite the log can also swap the key and
    # re-sign - so say exactly which key was used, and warn when it came from
    # alongside the evidence rather than from the operator.
    resolved = Path(key).resolve()
    fingerprint = hashlib.sha256(resolved.read_bytes()).hexdigest()[:16]
    print(f"verifying against key {resolved} (sha256:{fingerprint})")
    if not args.key and resolved.parent == Path(args.log).resolve().parent:
        print("warning: this key sits next to the log it attests. An attacker "
              "with write access to that directory could have replaced both. "
              "Pass --key with an out-of-band copy for a meaningful check.",
              file=sys.stderr)

    if verify_checkpoint(args.log, key):
        print(f"OK: checkpoint valid for {args.log}")
        return 0
    print(f"FAILED: checkpoint invalid for {args.log}", file=sys.stderr)
    return 1


def _cmd_report(args: argparse.Namespace) -> int:
    import dataclasses

    from .chainlog import ChainLog, verify
    from .report import render_html

    events = ChainLog.read(args.log)
    result = verify(args.log)
    # A truncated journal yields a valid shorter chain; if an adjacent
    # checkpoint contradicts it, the report must not carry a VERIFIED badge.
    if result.ok:
        problems = _checkpoint_problems(args.log, args.skip_checkpoint_check)
        if problems:
            result = dataclasses.replace(
                result, ok=False, first_bad_seq=None,
                errors=list(result.errors) + problems,
            )
    render_html(events, result, args.out, title=args.title)
    status = "VERIFIED" if result.ok else "TAMPERED"
    if not result.ok and result.first_bad_seq is not None:
        status = f"TAMPERED at seq {result.first_bad_seq}"
    print(f"report written to {args.out} ({len(events)} events, {status})")
    return 0 if result.ok else 2


def _cmd_export(args: argparse.Namespace) -> int:
    from .chainlog import ChainLog
    from .otel import export_json

    events = ChainLog.read(args.log)
    export_json(events, args.out)
    print(f"exported {len(events)} spans to {args.out}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Expose the journals under --root as a read-only MCP server."""
    from .mcpserver import serve

    return serve(args.root)


def _cmd_detect(args: argparse.Namespace) -> int:
    """Replay a recorded log through the behavioral baseline; print flags."""
    from .chainlog import ChainLog
    from .detect import Baseline

    if args.save and not args.state:
        print("error: --save requires --state", file=sys.stderr)
        return 1
    baseline = Baseline(args.state)
    events = ChainLog.read(args.log)
    total = 0
    for event in events:
        flags = baseline.flag(event)
        baseline.observe(event)
        for flag in flags:
            total += 1
            tool = (event.get("tool") or {}).get("name") or "-"
            print(f"seq={event.get('seq')} tool={tool} {flag}")
    if args.save:
        baseline.save()
        print(f"baseline state saved to {args.state}")
    print(f"{total} anomaly flags over {len(events)} events")
    return 0


def _cmd_rules_test(args: argparse.Namespace) -> int:
    """Dry-run rules against a log: print the Decision for each event."""
    from .chainlog import ChainLog
    from .policy import decide, load_rules

    rules = load_rules(args.rules_path)
    events = ChainLog.read(args.log)
    print(f"{len(rules)} rules loaded from {args.rules_path}")
    for event in events:
        decision = decide(event, rules)
        ids = ",".join(decision.rule_ids) or "-"
        print(f"seq={event.get('seq')} type={event.get('type')} "
              f"tool={(event.get('tool') or {}).get('name') or '-'} "
              f"-> {decision.action} [{ids}]")
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    from .chainlog import ChainLog
    from .proxy import run_proxy

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: proxy requires a child command after '--'", file=sys.stderr)
        return 1
    rules = None
    if args.rules:
        from .policy import load_rules

        rules = load_rules(args.rules)
    log = ChainLog(args.log, capture_content=args.capture_content)
    return run_proxy(cmd, log, rules)


def _load_demo_rules():
    """Load the example rules shipped with the package for the demo."""
    from . import bundled_rules_dir
    from .policy import load_rules

    return load_rules(str(bundled_rules_dir()))


def _cmd_demo(args: argparse.Namespace) -> int:
    """Scripted fake-agent session: agent_start, tool calls (one blocked by
    policy, anomalies flagged by a real Baseline), agent_end, HTML report.

    The journal uses the default digest-only mode: policy rules and the
    anomaly detector see full arguments in memory, but only digests are
    persisted - the same privacy posture as production defaults.
    """
    from .chainlog import ChainLog, verify
    from .detect import Baseline
    from .events import digest, new_event
    from .report import render_html

    try:
        from .policy import decide
    except ImportError:
        decide = None

    out_dir = Path(args.dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "demo.chain.jsonl"
    report_path = out_dir / "demo-report.html"
    log_path.unlink(missing_ok=True)

    rules = _load_demo_rules()
    log = ChainLog(str(log_path))  # digest-only, like production defaults
    session_id = "demo-session"

    # Seed the behavioral baseline from a synthetic "yesterday" session so
    # the detector has normal behavior to compare today's run against.
    baseline = Baseline()
    for name in ("read_file", "web_search", "read_file", "write_file"):
        baseline.observe(
            new_event("tool_call", "demo-baseline", "demo-agent", "demo",
                      tool={"name": name})
        )

    alerts = 0

    def tool_call(name: str, arguments: dict, latency_ms: float) -> dict:
        nonlocal alerts
        event = new_event(
            "tool_call",
            session_id,
            "demo-agent",
            "demo",
            tool={
                "name": name,
                "arguments_digest": digest(arguments),
                "arguments": arguments,
            },
            latency_ms=latency_ms,
        )
        if decide is not None and rules:
            decision = decide(event, rules)
            if decision.action == "block":
                event["status"] = "blocked"
                event["policy"] = {
                    "rule_id": decision.rule_ids[0],
                    "action": "block",
                }
            elif decision.action == "alert":
                event["policy"] = {
                    "rule_id": decision.rule_ids[0],
                    "action": "alert",
                }
        stored = log.append(event)
        flags = baseline.flag(event)
        baseline.observe(event)
        if flags:
            alerts += 1
            log.append(
                new_event("alert", session_id, "demo-agent", "demo",
                          tool={"name": name},
                          meta={"flags": flags, "event_id": event["id"]})
            )
        return stored

    print("demo: running scripted fake-agent session ...")
    log.append(new_event("agent_start", session_id, "demo-agent", "demo"))
    tool_call("read_file", {"path": "/etc/hostname"}, 8.0)
    tool_call("web_search", {"query": "aileron flight recorder"}, 42.0)
    blocked = tool_call("shell", {"cmd": "rm -rf / --no-preserve-root"}, 3.0)
    tool_call("write_file", {"path": "/tmp/notes.txt"}, 11.0)
    log.append(new_event("agent_end", session_id, "demo-agent", "demo",
                         latency_ms=1200.0))

    events = list(log)
    result = verify(str(log_path))
    render_html(events, result, str(report_path),
                title="Aileron Demo Incident Report")

    print(f"demo: wrote {len(events)} events to {log_path}")
    print(f"demo: chain {'VERIFIED' if result.ok else 'TAMPERED'} "
          f"({result.count} events)")
    if blocked.get("policy"):
        print(f"demo: blocked shell call by rule "
              f"{blocked['policy']['rule_id']}")
    print(f"demo: {alerts} anomaly alert(s) emitted")
    print(f"demo: report written to {report_path}")
    return 0 if result.ok else 2


_DISPATCH = {
    "init": _cmd_init,
    "verify": _cmd_verify,
    "sign-checkpoint": _cmd_sign_checkpoint,
    "verify-checkpoint": _cmd_verify_checkpoint,
    "report": _cmd_report,
    "export": _cmd_export,
    "detect": _cmd_detect,
    "serve": _cmd_serve,
    "proxy": _cmd_proxy,
    "demo": _cmd_demo,
}


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``aileron`` CLI. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        handler = _cmd_rules_test  # only 'test' exists today
    else:
        handler = _DISPATCH[args.command]
    try:
        return handler(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ImportError as exc:
        print(f"error: required aileron module unavailable: {exc}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
