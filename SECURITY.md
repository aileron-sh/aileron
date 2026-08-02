# Security Policy

Aileron is itself a security tool; we hold its own security posture to the
same standard we ask users to trust.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately via **GitHub Private Vulnerability Reporting** — use the
"Security" tab on the repository → "Report a vulnerability" (GitHub private
advisories). This keeps coordination in one place and lets us publish a
credited advisory on release.

Include: affected version/commit, reproduction steps or PoC, impact
assessment, and whether the issue is exploitable against a *user's*
deployment or against Aileron's own verification guarantees. We aim to
acknowledge within 72 hours, keep you updated, and credit reporters in the
release advisory unless you ask otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ security fixes |
| < 0.1.0 | ❌ |

Aileron is pre-1.0; fixes land on the latest release line only.

## Threat model of the tool itself

What Aileron guarantees, what it assumes, and what is explicitly out of
scope. If you find a gap between this model and the implementation, that is
a reportable vulnerability.

### In scope (report these)

- **Chain-verification bypass**: a modification to a logged event (edit,
  reorder, delete, insert) that `aileron verify` fails to detect.
- **Checkpoint forgery**: producing a checkpoint that
  `aileron verify-checkpoint` accepts without access to the private key.
- **Policy-enforcement bypass on the proxy path**: a `tools/call` that a
  matching `block` rule should stop but that reaches the child process
  (including via framing tricks — newline-delimited vs. `Content-Length`
  framing confusion is explicitly in scope).
- **Canonicalization attacks**: two semantically different events that hash
  identically, or event JSON whose canonical encoding is ambiguous.
- **Unsafe content handling**: paths where tool arguments/results are
  persisted despite `capture_content=False`, or log/report injection (the
  HTML report must not execute recorded content — it renders with inline
  CSS and no external assets).
- **Unexpected network behavior**: any network call from the library or
  CLI. There are none by design; one appearing is treated as a
  vulnerability.

### Assumptions (documented, not bugs)

- **Host integrity at write time.** Aileron detects *post-hoc* tampering;
  it cannot prevent an attacker with write access to the log directory from
  truncating the log or rewriting it forward from the last checkpoint.
  Signed checkpoints bound this: forging forward past a checkpoint requires
  the Ed25519 private key. **Keep signing keys off the recorded host.**
  External anchoring (Sigstore/Rekor) is on the roadmap for non-repudiation.
- **Tail truncation, including of the checkpoint file.** Checkpoints are
  chained to each other (each carries a signed `index` and
  `prev_checkpoint_hash`), so deleting, duplicating, or reordering a
  checkpoint *within* the sequence is detected. Deleting the most recent
  checkpoint(s) is not: it is the same problem as truncating the tail of any
  append-only file, and no purely local scheme can detect it. Anchoring the
  newest checkpoint somewhere the attacker does not control — a transparency
  log, a remote copy, a monitoring system — is what closes this.

  Note that `aileron verify` cross-checks an adjacent
  `<log>.checkpoints.jsonl` when one exists, so truncating the journal while
  leaving the checkpoint file behind *is* reported. That check is
  **unauthenticated** — it compares counts and tip hashes without verifying
  signatures, because `verify` requires no key. It raises the cost of naive
  truncation; it is not the cryptographic guarantee. Use
  `aileron verify-checkpoint` with a public key you obtained out of band for
  that.
- **A hostile MCP client or server can stop recording, not corrupt it.** The
  proxy fails closed: if the journal cannot be written it stops forwarding
  tool calls rather than letting them run unrecorded. A peer can therefore
  deny mediation (by crashing the proxy), but cannot obtain unlogged
  execution through it.
- **SDK instrumentation is cooperative.** `@track` records the code paths
  you decorate. Agent code — or an attacker controlling it — can simply not
  call the wrapped function. This is inherent to in-process SDKs; the MCP
  proxy exists for enforcement the agent process cannot skip, and the
  README states this explicitly.
- **Rules are pattern matching.** Policy rules match known-bad shapes, not
  intent. A novel malicious command that matches no rule is allowed and
  logged (logging is the guaranteed floor; blocking is best-effort on top).
- **Availability.** A local attacker who can delete the log, kill the
  proxy, or exhaust disk can deny recording. Aileron prioritizes
  *integrity* of what was recorded over *availability* of recording.

### Out of scope

- Vulnerabilities in agent frameworks, MCP servers, or LLM providers
  themselves (report those upstream).
- Kernel/syscall-level interception — explicitly out of scope for v1 (see
  README roadmap).
- Social engineering of maintainers, and issues requiring physical access.

## Disclosure process

1. Report received → acknowledgment within 72 hours.
2. Triage and reproduction; severity agreed with the reporter.
3. Fix developed privately in a security advisory fork.
4. Coordinated release: patched version + GitHub Security Advisory with
   CVE request where warranted, crediting the reporter.
5. Post-mortem note in the release notes for integrity-relevant fixes —
   for a tamper-evidence tool, transparency about failures is part of the
   product.
