# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once 1.0 is reached; 0.x releases may change APIs between minor versions.

## [Unreleased]

### Performance

- **Rules now skip their own regex when the payload cannot possibly match it.**
  A rule looking for `auditctl` cannot fire on a payload that does not contain
  the text `auditctl` anywhere, but it was scanning every byte to find that out.
  Each pattern is read once and reduced to a set of literals it requires, and a
  substring search decides whether the regex runs at all. On a benign 32 KB call
  17 of the 19 patterns that used to scan are now skipped.

  This is a speed change only, and the risk is entirely one-sided: skipping a
  regex that would have matched is a rule that silently stops firing. So
  anything the extractor does not fully understand returns "no prefilter, run
  the regex", and `AILERON_NO_PREFILTER=1` turns the whole thing off.

  The case folding is the subtle part. The prefilter needs a case-insensitive
  containment test that agrees with `re.IGNORECASE`, and neither obvious choice
  does. `str.lower()` misses U+017F, and `str.casefold()` misses U+0131 and
  splits multi-character literals apart on U+0130, which casefolds to two
  codepoints. Exactly four codepoints in Unicode are case-equal to an ASCII
  character; a test proves over all 1,114,112 of them that every one folds to
  exactly the character it is equal to.

  Verified by a differential test over every example in the rule pack, a
  property test on generated patterns, and a mutation fuzz that starts from
  inputs the rules must catch and checks the invariant on 25,000 mutants that
  still match. None of them found a verdict difference.

### Performance

- **Each matched path is now rendered to text once per decision, not once per
  rule.** Every content clause used to re-serialize the same value before
  searching it, so cost scaled with rule count multiplied by payload size. With
  the 32-rule pack that was 41 renders of the same arguments per call. Worth
  about 6% at 32 KB on CI; the value is removing the quadratic factor as packs
  grow, not the immediate saving. Pinned by a test asserting a single render per
  decision and a differential test requiring memoized and unmemoized evaluation
  to return the same action and rule ids.

### Changed

- The benchmark records the bundled rule count and reports when a comparison
  spans different pack sizes. Growing the pack from 2 rules to 32 in 0.1.4 made
  CI report a 39x proxy regression that did not exist: content rules match
  against the whole payload, so the workload had changed, not the code. It
  still fails the run, because a bigger pack is a real cost that should be
  re-recorded deliberately rather than waved through.

### Documentation

- **The performance section reports the proxy's cost and the rule pack's cost
  separately, and the headline no longer claims sub-millisecond overhead for
  the bundled pack.** That claim was measured when 2 rules shipped. With 32 it
  is 0.30 ms at 64 B but 23 ms at 32 KB, essentially all of it rule evaluation;
  the proxy itself stays between 0.14 and 0.38 ms. Anyone running the
  documented benchmark command would have seen the difference immediately, so
  the README now states it, explains that the cost is rule evaluation rather
  than the enforcement path, and says how to reduce it.

## [0.1.4] - 2026-08-20

### Added

- **`aileron serve`, a read-only MCP server over your journals.** Aileron sits
  in front of MCP servers; this makes it one, so an assistant can be asked what
  an agent did and read the answer out of the tamper-evident record. Three
  tools: `verify_journal`, `query_events`, `explain_rule`.

  Read only is load-bearing, not cosmetic. The agent being recorded is the
  untrusted party, so a write or delete tool would hand the suspect the
  evidence locker. There is none, and a test enforces it.

  Four defences beyond that: paths are confined to `--root` and only `.jsonl`
  opens, because `verify_journal(path)` would otherwise be an arbitrary file
  read; every answer carries its own integrity status, because confinement does
  not stop an agent writing a plausible journal inside the root and handing you
  invented history; recorded values are stripped of control characters,
  truncated, and labelled untrusted, because tool names are attacker-chosen and
  become a prompt-injection channel when read by an assistant; and replies are
  byte-capped, the same reasoning as `MAX_MESSAGE_BYTES` in the proxy.

- **32 bundled detection rules**, up from 2, across credential theft, cloud
  metadata abuse, exfiltration, supply chain, persistence, anti-forensics,
  database destruction, and agent-specific abuse. Each ships with the calls it
  must catch and the ordinary work it must ignore; a false positive fails the
  build.

- `server.json`, so Aileron can be listed in the official MCP Registry. It was
  not a server before this release, so listing it would have been
  miscategorised.

- `examples/incident_replay.py` and `docs/what-did-it-touch.md`.

## [0.1.3] - 2026-08-03

### Security

- **`aileron verify` now cross-checks an adjacent `<log>.checkpoints.jsonl`.**
  Truncating a journal's tail leaves a perfectly valid shorter hash chain, so
  `verify` reported `OK` even when a signed checkpoint sitting beside the log
  proved more events had existed. The evidence of tampering was on disk and
  the tool ignored it - the worst possible answer to give an operator. When a
  checkpoints file is present, `verify` now compares event count and tip hash
  against every checkpoint and exits 2 on a contradiction, naming whether the
  journal appears truncated or rewritten.

  The check is **unauthenticated by design**: `verify` takes no key, so it
  compares structure rather than verifying signatures. It defeats naive
  truncation; `verify-checkpoint` with an out-of-band public key remains the
  cryptographic guarantee, and `verify` now says so in its output.
- `aileron report` applies the same cross-check, so a truncated journal can no
  longer render a `VERIFIED` badge.
- Both commands accept `--skip-checkpoint-check` for deliberate log rotation.

Reported by an external security scan of 0.1.2. No version is affected by a
new vulnerability; this closes a gap between what the tool could detect and
what it actually reported.

## [0.1.2] - 2026-08-02

**Security release. Upgrade from 0.1.1 and 0.1.0.** A follow-up adversarial
audit confirmed the 0.1.1 fixes hold, but found a *critical* enforcement
bypass that both earlier versions share.

### Security

- **Critical: the proxy policed the parsed message but forwarded the raw
  bytes.** `_read_message` returned the exact bytes it received, and
  `run_proxy` wrote those to the child verbatim. Because a child may split
  that byte range differently than the proxy parsed it, a `tools/call` could
  execute without ever being policed or journaled - and `aileron verify`
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
  checkpoint remains undetectable - it is tail truncation, now stated
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

## [0.1.1] - 2026-08-01

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
  polices every `tools/call` in a message - batched or not, with or without
  an `id` - refuses the whole message if any element matches a `block`
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
  log must satisfy all of them. Signing an empty log is refused - a
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
  persisted the full exception string - which can embed tool arguments -
  regardless of `capture_content`.
- Public-key writes now use `O_NOFOLLOW`, matching the private key; a
  pre-planted symlink at that path turned `aileron init` into an arbitrary
  file overwrite.
- `Content-Length` is now bounded (64 MiB) and bodies are read in chunks.

### Changed

- **BREAKING: canonical JSON is now ASCII-escaped** (`ensure_ascii=True`)
  and rejects `NaN`/`Infinity` (`allow_nan=False`). This makes the
  integrity check total - a peer-supplied lone surrogate could previously
  raise inside `verify()` and suppress a TAMPERED verdict - but it changes
  the hash of any event containing non-ASCII content. **Journals written by
  0.1.0 that contain non-ASCII will not verify under 0.1.1.** Re-sign or
  archive them before upgrading.

### Performance

- The proxy read one byte at a time, costing a syscall per byte. Reading
  line-wise cuts overhead ~11x on 32 KB tool calls (2.16 ms → 0.19 ms).
  Measured overhead is now 0.08 ms (p50) at 64 B and 0.33 ms at 32 KB; see
  `scripts/benchmark.py`, which is reproducible on any machine.

### Added

- `scripts/benchmark.py` - measures proxy overhead against an
  identical child with no proxy in the path, and reports the delta.
- 12 security regression tests covering every issue above (112 total).

## [0.1.0] - 2026-07-23

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
  in the default digest-only mode - `capture_content` controls what is
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
