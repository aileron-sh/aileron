# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once 1.0 is reached; 0.x releases may change APIs between minor versions.

## [0.1.2] — 2026-08-02

**Security release. Upgrade from 0.1.1 and 0.1.0.** A follow-up adversarial
audit confirmed the 0.1.1 fixes hold, but found a *critical* enforcement
bypass that both earlier versions share.

### Security

- **Critical: the proxy policed the parsed message but forwarded the raw
  bytes.** `_read_message` returned the exact bytes it received, and
  `run_proxy` wrote those to the child verbatim. Because a child may split
  that byte range differently than the proxy parsed it, a `tools/call` could
  execute without ever being policed or journaled — and `aileron verify`
  still reported OK, because nothing was tampered with; the call was simply
  never recorded. Two working variants:
  - **Header smuggling.** Every line before the blank line was accumulated
    as "headers" and forwarded. A JSON-RPC message parked on its own line in
    the header block is invisible to policy but is executed by a
    newline-delimited child. A 148-byte payload was enough.
  - **Body re-splitting.** A `Content-Length` body may legally contain raw
    newlines; the proxy saw one frame where a newline-delimited child saw
    several.

  Fixed structurally: the proxy now forwards a **re-serialization of the
  message it policed** (compact separators, ASCII-escaped, no raw newlines)
  rather than peer-supplied bytes, in both directions. The message boundary
  the child sees is now the same object the policy engine inspected, by
  construction. Header lines are additionally validated against RFC 7230 and
  the header block is bounded.
- **Checkpoints are now chained.** Each carries a signed `index` and
  `prev_checkpoint_hash`, so deleting, duplicating, or reordering a
  checkpoint within the sequence is detected. Deleting the *newest*
  checkpoint remains undetectable — it is tail truncation, now stated
  explicitly in SECURITY.md.
- `verify()` no longer raises on raw invalid UTF-8 in the journal; it
  reports it as tampering. The integrity check must never terminate by
  exception.
- The HTML report's verification badge now escapes `count` and
  `first_bad_seq`, the only two fields that reached the page unescaped.
- A non-mapping `params` on a `tools/call` no longer crashes the proxy with
  an unhandled `AttributeError`.
- `MAX_MESSAGE_BYTES` now bounds the newline-delimited path and the header
  block, not just `Content-Length`.
- `pending` is capped (`MAX_PENDING`); calls beyond it are refused and
  journaled rather than growing memory without bound.
- The child is waited on with a timeout, so a child that never exits can no
  longer strand in-flight calls outside the journal.
- `record_failed` is re-checked immediately before forwarding, closing the
  window where a call read before a journal failure was still delivered.
- A framing error from the child now sets `record_failed` and prints a
  diagnostic instead of silently ending response recording.
- A blocked batch now answers every request in it, and attributes the denial
  to the call that actually matched.

### Changed

- A blocked JSON-RPC **batch** is answered with a batch response, per
  JSON-RPC 2.0, instead of a single error object.

## [0.1.1] — 2026-08-01

**Security release. Upgrade from 0.1.0.** An adversarial audit found six
high-severity issues, all present in 0.1.0. The most serious is a
policy-enforcement bypass: the MCP proxy failed *open*.

### Security

- **Proxy failed open on the enforcement path (high).** Policy was applied
  only to messages matching `dict` + `method == "tools/call"` + a present
  `id`; everything else was forwarded to the child unchecked and
  unjournaled. Four shapes of an ordinary blocked call slipped through: a
  JSON-RPC batch array, a `tools/call` with no `id`, a payload CPython's
  JSON parser rejects but a child accepts (e.g. an integer literal over
  4300 digits), and a payload with one invalid UTF-8 byte. The proxy now
  polices every `tools/call` in a message — batched or not, with or without
  an `id` — refuses the whole message if any element matches a `block`
  rule, and never forwards a payload it could not parse (it replies
  `-32700` instead).
- **Audit records could be silently dropped (high).** A reused in-flight
  JSON-RPC `id` overwrote the pending entry, erasing an executed call from
  the journal while `verify` still reported OK; a lone surrogate in a child
  response could kill the reader thread the same way. Displaced events are
  now journaled before being replaced, id-less calls are journaled on
  dispatch, and a failed journal write stops mediation instead of letting
  calls through unrecorded.
- **Checkpoint rollback (high).** `verify_checkpoint` trusted only the last
  line of the checkpoints file, so reordering it rolled coverage back and
  permitted truncation. Every checkpoint signature is now verified and the
  log must satisfy all of them. Signing an empty log is refused — a
  `count=0` checkpoint attested to nothing yet reported OK against any
  later content.
- **Trust anchor taken from the audited directory (high).** `aileron
  verify-checkpoint` silently fell back to key material sitting next to the
  log, so anyone who could rewrite the journal could also re-sign it. The
  resolved key path and its SHA-256 fingerprint are now printed, and using
  a key co-located with the log warns.
- **Canonicalization ambiguity (medium).** `verify()` now requires the
  on-disk bytes to equal the canonical re-serialization of the parsed
  event, detecting duplicate JSON keys and non-canonical number literals
  that previously passed. A corrupt line no longer resyncs to genesis, so
  forged events cannot chain onto it.
- **Privacy leak on the SDK error path (medium).** `AgentSession.__exit__`
  persisted the full exception string — which can embed tool arguments —
  regardless of `capture_content`.
- Public-key writes now use `O_NOFOLLOW`, matching the private key; a
  pre-planted symlink at that path turned `aileron init` into an arbitrary
  file overwrite.
- `Content-Length` is now bounded (64 MiB) and bodies are read in chunks.

### Changed

- **BREAKING: canonical JSON is now ASCII-escaped** (`ensure_ascii=True`)
  and rejects `NaN`/`Infinity` (`allow_nan=False`). This makes the
  integrity check total — a peer-supplied lone surrogate could previously
  raise inside `verify()` and suppress a TAMPERED verdict — but it changes
  the hash of any event containing non-ASCII content. **Journals written by
  0.1.0 that contain non-ASCII will not verify under 0.1.1.** Re-sign or
  archive them before upgrading.

### Performance

- The proxy read one byte at a time, costing a syscall per byte. Reading
  line-wise cuts overhead ~11x on 32 KB tool calls (2.16 ms → 0.19 ms).
  Measured overhead is now 0.08 ms (p50) at 64 B and 0.33 ms at 32 KB; see
  `benchmarks/bench_proxy.py`, which is reproducible on any machine.

### Added

- `benchmarks/bench_proxy.py` — measures proxy overhead against an
  identical child with no proxy in the path, and reports the delta.
- 12 security regression tests covering every issue above (112 total).

## [0.1.0] — 2026-07-23

Initial public release.

### Added

- **Hash-chained audit journal** (`chainlog`, `events`): append-only JSONL
  log of `tool_call` / `llm_call` / `agent_start` / `agent_end` /
  `policy_decision` / `alert` events; SHA-256 hash chain over canonical
  JSON; `verify()` with `first_bad_seq` reporting.
- **Ed25519 checkpoints** (`signing`): `generate_keypair`,
  `sign_checkpoint`, `verify_checkpoint` for offline-verifiable log tips.
  Checkpoints use prefix semantics: events appended after signing never
  invalidate a checkpoint; truncating or rewriting the signed prefix does.
- **Policy engine** (`policy`): Sigma-like YAML rules with
  `allow` / `alert` / `block` actions; dotted-key equality, `_contains`,
  `_regex`, and `severity_gte` matchers; example rules
  (`rules/examples/destructive-shell.yml`, `secrets-exfil.yml`). Rules are
  evaluated against the full call in memory, so content matchers fire even
  in the default digest-only mode — `capture_content` controls what is
  persisted, never what is enforced.
- **Behavioral anomaly detection** (`detect`): rolling baselines flagging
  first-seen tools, rate spikes (>3x baseline), and novel tool-call
  sequences; live via the SDK `baseline=` hook or offline via
  `aileron detect`.
- **SDK instrumentation** (`sdk`): `@track` decorator recording tool calls
  (digest-only by default; `capture_content` opt-in) and enforcing policy
  via `PolicyBlocked`; `track_agent` session context manager.
- **MCP stdio proxy** (`proxy`): JSON-RPC 2.0 interception (newline- and
  Content-Length-framed) with pre-execution policy mediation; blocked calls
  return `-32000` without invoking the child. In-flight calls that never
  receive a response (child crash/exit) are journaled with `status=error`
  on shutdown, so a crash cannot erase the attempt.
- **OTel GenAI export** (`otel`): `gen_ai.*`-aligned span dicts
  (`to_otel_spans`) and OTLP/JSON export (`to_otlp_spans`, `export_json`)
  in the proto3 JSON mapping, suitable for OTLP/HTTP ingestion.
- **HTML incident reports** (`report`): single-file, no-external-asset
  incident timeline with `VERIFIED` / `TAMPERED` verification badge.
- **CLI** (`aileron`): `init`, `verify`, `sign-checkpoint`,
  `verify-checkpoint`, `report`, `export`, `detect`, `rules test`, `proxy`,
  `demo`.
- **Privacy posture**: no telemetry anywhere; tool arguments/results stored
  as digests unless content capture is explicitly enabled.
