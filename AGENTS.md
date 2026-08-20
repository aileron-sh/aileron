# Working on Aileron with an AI coding agent

This is the canonical instruction file for any AI coding agent working in this repository. It is
harness-neutral: `CLAUDE.md` carries the same non-negotiables inline for Claude Code and points here
for the full protocol. If you are a different agent (Kiro, Amazon Q, Cursor, Copilot, opencode,
Codex), read this file.

Two things govern how work happens here: the **AI-DLC workflow** (a gated, phase-based process) and a
small set of **agentic engineering principles** (how to keep an agent useful over long horizons).
AI-DLC supplies the stages and gates; the principles explain why the gates exist and how to behave
between them.

---

## 1. Starting work: the AI-DLC entrypoint

When the user asks for software development work — a feature, a fix, a refactor, a hardening pass —
read and follow `.aidlc/aidlc-rules/aws-aidlc-rules/core-workflow.md` **first**, before writing code.

- **Rule details root**: `.aidlc/aidlc-rules/aws-aidlc-rule-details/`
- **Upstream**: `awslabs/aidlc-workflows`, `main`, tree `114ef4d0…`, pulled 2026-08-12, unmodified.
- **Current state**: `aidlc-docs/aidlc-state.md` — read this before anything else. It tells you the
  phase, the stage, what was last completed, and what is pending human approval.
- **Audit log**: `aidlc-docs/audit.md` — append the raw user request, every stage transition, and
  every human approval or change request. Append only; never rewrite history here.

**Workspace-root caveat that will silently break the workflow:** the rule paths above resolve only
when the agent's workspace root is *this* directory (the one containing `pyproject.toml`). If you were
opened one level up, none of `core-workflow.md`'s four candidate rule-detail directories match and
rule loading fails quietly. Verify `.aidlc/aidlc-rules/` is visible from your root before proceeding.

### The phases, and what a gate means

- **Inception** — what to build and why. Requirements, stories where useful, application design,
  units of work. For this brownfield repo, Reverse Engineering has already run; its output is in
  `aidlc-docs/inception/reverse-engineering/`.
- **Construction** — how to build it. Per-unit functional design, NFR requirements and design, then
  code generation, then build and test. One unit is finished completely before the next begins.
- **Operations** — upstream placeholder. For Aileron this means release engineering: the CI matrix,
  the benchmark regression guard, and PyPI trusted publishing already in `.github/workflows/`.

A gate is a **hard stop**, not a status update. At a gate you present what you produced, state what
you decided and why, and wait. Do not proceed on an assumed yes. Ask clarifying questions by writing
them into a markdown file with lettered options and an `[Answer]:` slot — that is the upstream
convention, and it exists so answers become part of the record instead of scrolling away in a chat.

---

## 2. Agentic engineering principles

These are the operating principles behind the gates. They come from Dexter Horthy's work on agentic
engineering and the "software factory" idea, and they are recorded here because they change what good
behaviour looks like between stages.

### Program design before implementation
Define the measurable output before you write code. "Add OCSF export" is not a specification; "emit
OCSF events for `tool_call` and `alert`, validated against schema version X, with a round-trip test
and a documented field mapping" is. If you cannot state how you will know the work succeeded, you are
not ready to start — and neither is the design doc.

### The human keeps a grip on the architecture
Coding agents can produce large volumes of plausible code that no one understands a month later. The
antidote is not slower typing; it is keeping architectural decisions in human hands and writing them
down. Any change to module boundaries, the dependency graph, the event schema, the wire protocol, or
a security invariant is a human decision. Propose, explain the trade-off, wait.

### Context engineering: keep high-signal context in the repo
The most valuable thing an agent can be given is a small amount of exactly the right context. That is
why the reverse-engineering artifacts exist and why they are committed rather than regenerated: they
turn "read 2,625 lines and infer the design" into "read one document that already states it."

Consequences for your behaviour:
- Read `aidlc-docs/inception/reverse-engineering/` before exploring the source. It is current as of
  git `6c09efd`; if `src/` has moved since, say so and offer to refresh it rather than trusting it.
- When you learn something durable — an invariant, a constraint, a reason a design is the way it is —
  write it into the relevant artifact. Knowledge that lives only in a session transcript is lost.
- Keep these documents dense. A bloated context file is as harmful as a missing one.

### Compact before you enter the dumb zone
Long sessions degrade: as the window fills with history, output quality drops well before any hard
limit. **At roughly 50% context consumption, stop and compact** — write your findings and decisions
into the appropriate `aidlc-docs/` artifact, then continue working from that artifact rather than from
accumulated history. Prefer delegating wide, read-heavy exploration to subagents that return a
conclusion instead of pulling every file into the main thread.

### Fix the bottleneck, not the agent
Effort should go where the system is actually constrained. For this repo the real constraints are the
untested security invariants listed in `code-quality-assessment.md`, `SPEC.md` having drifted from the
code, the absence of lint and type checking despite shipping `py.typed`, and `cli.py` being the file
nine of sixteen features touch. Tuning prompts or shaving milliseconds elsewhere is motion, not
progress. If asked to optimise something, check first whether it is the constraint.

---

## 3. Aileron non-negotiables

Aileron's entire value proposition is that its record can be trusted. Each item below is enforced in
code today. **Do not weaken any of them as a side effect of another change.** If a change genuinely
requires touching one, that is a gate: stop and raise it.

1. **Canonical JSON is the format contract.** `events.canonical_json` — sorted keys, `(",", ":")`
   separators, `ensure_ascii=True`, `allow_nan=False`. Changing it invalidates every hash ever
   produced. It is a versioned format migration with a changelog entry, never a refactor.
   `ensure_ascii=True` is load-bearing: it is what lets a lone surrogate be hashed instead of raising,
   which is what makes `verify` total.
2. **`verify` must never raise on file content.** A verification tool that crashes on hostile input is
   a denial-of-service vector. Every parse and hash path stays guarded; `RecursionError` counts as
   tampering, not as a crash. Be precise about the current limit: the guarantee covers content, not the
   file handle — a directory or an unreadable path raises `OSError`, which `main()` does not catch.
   That is filed as debt item 6; fixing it is welcome, weakening the content guarantee is not.
3. **On-disk bytes are authoritative.** `verify` re-serialises each parsed event and requires it to
   equal the line it came from. This is what catches duplicate JSON keys and non-canonical numbers.
4. **Nothing chains onto a broken line.** The `_BROKEN` sentinel must keep a forged tail from
   re-syncing to genesis.
5. **Digest-only capture is the default, and it must not weaken enforcement.** Producers hand policy
   and detection the *full* arguments in memory; `chainlog.append` strips them on write.
   `capture_content` controls what is persisted, never what is enforced. Two existing tests assert
   `"rm -rf"` never reaches the journal file — keep them passing.
6. **The proxy fails closed.** Unparseable input is rejected and never forwarded; ambiguous framing
   tears the session down; when recording is unavailable the call is refused with `-32000`;
   `pending` overflow is journaled as blocked. "If we cannot parse it we cannot police it."
7. **Forward what we policed, not the peer's bytes.** `_canonical_wire` is applied in both directions
   so a frame cannot be re-split or smuggled past a parser disagreement. This was the critical 0.1.2
   fix and currently has **no test** — do not remove it, and adding that test is welcome work.
8. **A blocked call is still recorded, and never executes.** Both capture paths journal the attempt
   with `status="blocked"` before refusing.
9. **In-flight calls survive child death.** The `finally` drain journals every pending call with
   `status="error"`. A crash must never erase an attempt.
10. **Checkpoints attest a prefix and are chained to each other.** Honest appends stay valid;
    truncation, rewriting, reordering, or deleting an intermediate checkpoint is detectable. Signing
    refuses a broken or empty chain.
11. **Private keys are created `0o600` with `O_NOFOLLOW`** in a single `os.open`. No world-readable
    window, no symlink redirection.
12. **Detection is advisory.** `detect` flags; it never blocks. Do not give it enforcement power
    without an explicit architectural decision.
13. **No network calls, ever.** No telemetry, no phone-home, no update check, anywhere in the library
    or CLI. For a security tool this is disqualifying to break, and it is advertised in the README.
14. **HTML output escapes everything it interpolates**, including verify-result fields in the badge.

---

## 4. Repository conventions

- **Tests**: one test module per source module, `tests/test_<module>.py`. Each file inserts `../src`
  on `sys.path`; there is no `conftest.py`. Prefer real subprocesses over mocks for the proxy — the
  bugs live in framing and process lifecycle. Run `python -m pytest tests/ -q`.
- **A security fix ships with the test that would have caught it.** Several existing invariants
  predate their tests, which is exactly the debt we are trying not to grow.
- **Commits**: single-purpose, prefixed — `security:`, `perf:`, `docs:`, `ci:`, `bench:`, `release:`.
  Security fixes are separated from features. DCO sign-off is required; there is no CLA.
- **CHANGELOG.md** is maintained by hand; user-visible and security-relevant changes go in it, and
  breaking format changes are called out explicitly.
- **Benchmarks**: `.github/workflows/benchmark.yml` is path-filtered to code that can affect latency
  and fails at >2× the baseline median on two consecutive runs. If you change `proxy.py`, expect it to
  run. Do not "fix" a regression by editing `scripts/benchmark_baseline.json` — that is falsifying the
  measurement. Re-baseline only as a deliberate, explained change.
- **Public API surface** is `__init__.__all__` (nine names). Adding to it is an API commitment;
  submodule imports are the escape hatch for everything else.
- **`cli.py` is the collision hotspot.** Before two workstreams touch it, split it. Note that
  `main()` special-cases the `rules` group outside `_DISPATCH`.
- **`SPEC.md` is currently stale** — it disagrees with the code on canonical JSON, version, checkpoint
  structure, and the detector's window. Until it is fixed, the reverse-engineering artifacts are the
  accurate description. Do not "correct" the code to match the spec.

---

## 5. Where context lives

```
.aidlc/aidlc-rules/            upstream AI-DLC rules (do not edit; re-pull to update)
aidlc-docs/
  aidlc-state.md               phase, stage, extension config, compaction policy — read first
  audit.md                     append-only record of intent, decisions, approvals
  inception/
    reverse-engineering/       the accurate description of the system as built
      business-overview.md     what it does, for whom, and the vocabulary
      architecture.md          components, dependency direction, data flow diagrams
      code-structure.md        build system, module map, design patterns, file inventory
      api-documentation.md     public API, CLI flags, exit codes, data models
      component-inventory.md   modules and counts
      technology-stack.md      languages, deps, tooling, CI
      dependencies.md          internal graph with reasons, external deps with licences
      code-quality-assessment.md  test topology, untested invariants, technical debt, priorities
      existing-feature-units.md   the 16 shipped features as candidate units + collision map
    requirements/ user-stories/ application-design/ plans/    populated as stages run
  construction/                per-unit design and build-and-test artifacts
  operations/                  placeholder upstream; release engineering lives in .github/workflows
```

Application code goes in `src/aileron/`, tests in `tests/`. **Never put code in `aidlc-docs/`** — that
tree is markdown only.

---

## 6. Extensions

Three AI-DLC extensions are available under
`.aidlc/aidlc-rules/aws-aidlc-rule-details/extensions/`. Proposed answers are recorded in
`aidlc-state.md` but are **not settled** — Requirements Analysis must still ask:

- **security/baseline** — proposed *in*, with per-rule N/A. Rules on input validation, hardening,
  supply chain, credential management, integrity, and fail-closed error handling map directly onto a
  library and CLI; the cloud-infrastructure rules do not apply.
- **testing/property-based** — proposed *partial*. Hypothesis is the Python choice, and canonical
  JSON, chain append/verify, JSON-RPC framing, and the policy matcher are textbook round-trip and
  invariant targets.
- **resiliency/baseline** — proposed *out*. It assumes a deployed cloud workload; nearly every rule
  would resolve to N/A here.

---

## 7. Open decisions awaiting the human

Listed in `aidlc-docs/audit.md`. In short: approve or amend the reverse-engineering artifacts; confirm
the three extension opt-ins; decide whether `.aidlc/` and `aidlc-docs/` are committed to the public
repo (recommended — committed context is the point) or kept local; and supply the first real change
request, which is what unblocks Requirements Analysis.
