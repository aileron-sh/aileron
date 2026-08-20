# CLAUDE.md - Aileron

Aileron is a tamper-evident flight recorder for AI agents: a hash-chained journal of every tool
call, Ed25519-signed checkpoints, policy enforcement before execution, and offline verification.
Apache-2.0, pure Python ≥3.10, two runtime dependencies (`pyyaml`, `cryptography`).

This is a **security tool that is published on PyPI**. Changes here are changes to something people
rely on to tell them what their agents did. Bias toward correctness and honesty over speed.

## The four invariants

Break any of these and the product is no longer what it claims to be.

1. **Canonical JSON is the hash input.** `events.canonical_json()` is the single serializer the
   chain and signatures depend on - sorted keys, tight separators, `ensure_ascii=True`,
   `allow_nan=False`. Never hand-format event JSON, and never add a second copy of this function.
   Changing it changes every hash and invalidates existing journals.
2. **`capture_content` gates persistence, not enforcement.** Policy rules and the anomaly detector
   always see the full call in memory; `ChainLog.append` strips content from the copy it writes.
   Rules must fire in the default digest-only mode.
3. **A prefilter may only ever skip work, never a detection.** `prefilter.py`
   lets the policy engine skip a rule's regex when the payload provably cannot
   match it. Wrongly skipping is a rule that silently stops firing and a journal
   that looks clean, so everything there is deliberately lopsided: anything not
   understood returns `None`, meaning "run the regex". `fold()` is proven sound
   over every Unicode codepoint by a test, because `str.lower()` and
   `str.casefold()` are both quietly wrong against `re.IGNORECASE`. Set
   `AILERON_NO_PREFILTER=1` to rule it out during an investigation.
4. **A checkpoint signs a prefix.** Appending after signing stays valid; truncating or rewriting
   the signed prefix does not. Checkpoints are chained to each other (`index`,
   `prev_checkpoint_hash`).

## The proxy is the enforcement path - treat it accordingly

`src/aileron/proxy.py` sits inline on every tool call. Two rules that exist because violating them
caused real vulnerabilities:

- **Forward what you policed, never the peer's bytes.** The proxy re-serializes the parsed message
  before sending it on. Forwarding raw bytes let a child re-split the stream and execute calls
  policy never saw (fixed in 0.1.2).
- **Fail closed.** Anything unparseable, ambiguous, or oversized is refused, not passed through. If
  the journal cannot be written, stop mediating rather than let calls run unrecorded.

## Layout

```
src/aileron/
  events.py    schema, canonical JSON, hashing      chainlog.py  append-only chain + verify
  signing.py   Ed25519 checkpoints                  policy.py    Sigma-like YAML rules
  detect.py    behavioral baselines                 sdk.py       @track / track_agent
  prefilter.py regex literal prefilter (speed only)
  proxy.py     MCP stdio proxy (enforcement)        otel.py      OTel + OTLP export
  report.py    single-file HTML report              cli.py       argparse CLI
  rules/examples/   bundled starter rules (shipped as package data)
scripts/       benchmark.py, collect_metrics.py
tests/         one file per module
```

`SPEC.md` is the authoritative description of formats and signatures; keep it in sync.

## Working here

```console
$ python -m pytest tests/ -q          # must stay green (244+ tests)
$ python scripts/benchmark.py         # proxy overhead; CI fails on >2x median regression
```

- Every behavior change needs a test. Security fixes need a regression test that fails without them.
- No new runtime dependencies without strong justification.
- **No network calls in the library or CLI, ever.** The no-telemetry claim is load-bearing; a
  network call would be treated as a vulnerability.
- The HTML report renders attacker-influenced content - every dynamic value goes through
  `html.escape`.
- Read `SECURITY.md` before changing anything in the threat model. It states plainly what Aileron
  does *not* protect against; keep it honest rather than flattering.

## Where bugs hide

- **Proxy concurrency** - a reader thread and the main loop share `pending` and the log under one
  non-reentrant lock. `append()` takes the lock; `log.append()` does not. Mixing them deadlocks.
- **Canonicalization** - anything that changes byte output changes every hash.
- **Baseline math** (`detect.py`) - compares a 60s windowed rate against a lifetime average, so it
  is sensitive to how spread out historical calls are.
