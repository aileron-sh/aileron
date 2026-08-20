# CLAUDE.md — Aileron

Aileron is a tamper-evident flight recorder for AI agents: a hash-chained journal of every tool call,
Ed25519-signed checkpoints, policy enforcement before execution, and offline verification. Apache-2.0,
pure Python ≥3.10, two runtime dependencies.

**Read `AGENTS.md` for the full working protocol.** It is the canonical instruction file; this file
carries the hard rules inline so they are always in context, and defers the rest.

## Start here

When asked for development work — feature, fix, refactor, hardening — follow the AI-DLC workflow
*before* writing code: read `.aidlc/aidlc-rules/aws-aidlc-rules/core-workflow.md`.

- Rule details root: `.aidlc/aidlc-rules/aws-aidlc-rule-details/`
- Current phase and stage: `aidlc-docs/aidlc-state.md` — **read this first, every session**
- Append intent, decisions, and approvals to `aidlc-docs/audit.md`. Append only.
- The system as actually built: `aidlc-docs/inception/reverse-engineering/` — read these before
  exploring `src/`. Current as of git `6c09efd`; if `src/` has changed since, offer to refresh them.

Those rule paths resolve only if your workspace root is this directory (the one with
`pyproject.toml`). Opened one level up, rule loading fails silently.

## How to behave between gates

- **Design before code.** State the measurable output first. If you cannot say how you will know it
  worked, the design is not finished.
- **Architecture is a human decision.** Module boundaries, the dependency graph, the event schema, the
  wire protocol, and any security invariant: propose, explain the trade-off, and wait. A gate is a
  hard stop, not a status update.
- **Ask in files, not in chat.** Clarifying questions go in a markdown file with lettered options and
  an `[Answer]:` slot, so answers land in the record.
- **Compact at ~50% context.** Write findings into the relevant `aidlc-docs/` artifact and continue
  from the artifact, not from session history. Delegate wide, read-heavy exploration to subagents that
  return conclusions rather than pulling every file into this thread.
- **Work the bottleneck.** Here that is: the untested security invariants in
  `code-quality-assessment.md`, `SPEC.md` having drifted from the code, no lint or type checking
  despite shipping `py.typed`, and `cli.py` being the file nine of sixteen features touch.

## Never break these

Enforced in code today. Weakening any of them as a side effect is a stop-and-ask, not a judgement call.

1. `events.canonical_json` is the format contract — sorted keys, `(",", ":")`, `ensure_ascii=True`,
   `allow_nan=False`. Changing it invalidates every hash ever produced: format migration, never a
   refactor. `ensure_ascii=True` is what makes `verify` total.
2. `verify` never raises on hostile file *content* — a verifier that crashes on hostile input is a DoS
   vector. (It can still raise on the file *handle*: a directory or unreadable path escapes both the
   guards and `main()`'s except clause. That is open debt, not licence to weaken the content guarantee.)
3. On-disk bytes are authoritative — `verify` re-serialises and compares to the original line.
4. Nothing chains onto a broken line (`_BROKEN` sentinel).
5. Digest-only capture is the default and must not weaken enforcement: producers pass **full**
   arguments to policy in memory, `chainlog.append` strips them on write. `capture_content` changes
   what is persisted, never what is enforced.
6. The proxy fails closed — unparseable input is never forwarded, ambiguous framing tears down the
   session, unavailable recording refuses the call.
7. Forward `_canonical_wire(msg)`, not the peer's bytes, in both directions. Critical 0.1.2 fix, still
   untested — do not remove it.
8. A blocked call is journaled and never executes.
9. In-flight calls are drained as `status="error"` when the child dies.
10. Checkpoints attest a prefix and are chained to each other; signing refuses a broken or empty chain.
11. Private keys: `0o600` with `O_NOFOLLOW` at `os.open` time.
12. Detection is advisory. It flags; it never blocks.
13. No network calls anywhere in the library or CLI. No telemetry, no phone-home.
14. Escape everything interpolated into HTML, including the badge fields.

## Conventions

- One test module per source module (`tests/test_<module>.py`); `../src` on `sys.path`; no
  `conftest.py`. Run `python -m pytest tests/ -q`.
- A security fix ships with the test that would have caught it.
- Commits are single-purpose and prefixed (`security:`, `perf:`, `docs:`, `ci:`, `bench:`,
  `release:`). DCO sign-off required, no CLA.
- Code in `src/aileron/`, tests in `tests/`. **Never put code in `aidlc-docs/`** — markdown only.
- `benchmark.yml` fails at >2× baseline median proxy overhead. Never "fix" a regression by editing
  `scripts/benchmark_baseline.json`.
- `SPEC.md` is stale and disagrees with the code in four places. The reverse-engineering artifacts are
  the accurate description; do not change code to match the spec.
