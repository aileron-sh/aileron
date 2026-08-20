# AI-DLC State Tracking

## Project Information
- **Project Name**: Aileron
- **Project Type**: Brownfield
- **Start Date**: 2026-08-12
- **Current Phase**: INCEPTION
- **Current Stage**: INCEPTION - Requirements Analysis (⛔ blocked at the Step 6 gate, awaiting answers)
- **Last Completed**: Requirements Analysis steps 1–6 — intent analysis, depth decision, completeness analysis, and clarifying questions written
- **Next Step**: Human fills in `aidlc-docs/inception/requirements/requirement-verification-questions.md` (12 questions, including the three extension opt-ins). Then Step 7 generates `requirements.md`.
- **Change Request In Flight**: write tests for the seven security invariants that are enforced in code but asserted by no test
- **Codebase Version Analysed**: 0.1.3, git `6c09efd` (2026-08-02)

## Workspace State
- **Existing Code**: Yes
- **Programming Languages**: Python 3.10–3.13
- **Build System**: setuptools via PEP 621 (`pyproject.toml`)
- **Project Structure**: Library + CLI (single package, `src/` layout)
- **Reverse Engineering Needed**: No — artifacts current as of git `6c09efd`
- **Workspace Root**: the `aileron/` repository root — the directory containing `pyproject.toml`, `CLAUDE.md`, `src/`, and this `aidlc-docs/` tree.
  Deliberately recorded as a relative marker rather than a machine-specific absolute path: these
  artifacts are committed to a public repository, and a hard-coded home directory would both leak
  the maintainer's local layout and break for every other contributor.

## Code Location Rules
- **Application Code**: Workspace root — `src/aileron/` (NEVER in `aidlc-docs/`)
- **Tests**: Workspace root — `tests/` (never in `aidlc-docs/`)
- **Documentation**: `aidlc-docs/` only (markdown summaries and plans)
- **Structure patterns**: See `code-generation.md` Critical Rules. This is a brownfield project, so
  the existing structure wins: new modules go in `src/aileron/`, new tests in `tests/test_<module>.py`,
  one test module per source module as the existing convention.

## Rule Location
- **Rule details root**: `.aidlc/aidlc-rules/aws-aidlc-rule-details/` (candidate 1 in `core-workflow.md`)
- **Core workflow**: `.aidlc/aidlc-rules/aws-aidlc-rules/core-workflow.md`
- **Upstream**: `awslabs/aidlc-workflows`, `main` branch, tree `114ef4d0ae6082e63ff0c7d14a910e3195163235`, pulled 2026-08-12. 32 rule files, unmodified.
- **Resolution caveat**: those paths resolve only when the agent's workspace root is the `aileron/`
  repository root. If an agent is opened one level up (at `ailehero/`), none of the four candidate
  rule-detail directories match and rule loading silently fails. Open the repo directly.

## Extension Configuration
Extensions are enumerated from `.aidlc/aidlc-rules/aws-aidlc-rule-details/extensions/`. Three are
available; the opt-in answers below are **proposed defaults for human confirmation**, not settled
decisions.

Per Step 5.1 of the Requirements Analysis rules, all three opt-in prompts have now been surfaced
verbatim in `requirement-verification-questions.md` and are **awaiting answers**. Enablement status
gets recorded here (with `Decided At: Requirements Analysis`) once the answers arrive, and only then are
the full rules files loaded for the extensions that were opted into — deferred rule loading, so an
opted-out extension's rules are never read.

| Extension | Proposed | Rationale |
|---|---|---|
| `security/baseline` | Opt in, with per-rule N/A | Aileron is security tooling; SECURITY-03, 05, 09, 10, 11, 12, 13, 15 (application-level logging, input validation, hardening, supply chain, secure design, credential management, integrity/deserialization, fail-closed error handling) map directly onto a library + CLI — 03 and 11 arguably most of all, since structured logging without secrets and secure-by-design are what this project *sells*. The cloud-infrastructure rules (01, 02, 04, 06, 07, 08, 14) resolve to N/A — there is no deployed workload. |
| `testing/property-based` | Opt in — Partial | Hypothesis is the named Python framework. Canonical JSON, hash-chain append/verify, JSON-RPC framing, and the policy matcher are textbook round-trip and invariant shapes. Partial mode enforces PBT-02, 03, 07, 08, 09 and leaves the rest advisory. |
| `resiliency/baseline` | Opt out | Written around deployed cloud workloads (multi-AZ, RTO/RPO, auto-scaling, DR runbooks). For a non-deployed Python package nearly all fifteen rules resolve to N/A, so enabling it adds ceremony without findings. Revisit if a hosted verification service is ever built. |

## Context Engineering Policy
Local addition to the upstream workflow — see `CLAUDE.md` for the full rationale.
- **Compaction threshold**: at roughly 50% context consumption, stop and write findings into the
  relevant `aidlc-docs/` artifact, then continue from the artifact rather than the session history.
- **Artifacts are the memory**: session history is scratch; `aidlc-docs/` is the durable record.
- **One unit at a time**: complete a unit's design and code before starting the next.

## Stage Progress

### INCEPTION
- [x] **Workspace Detection** — completed 2026-08-12. Brownfield confirmed: 11 source modules, 10 test modules, 40 git-tracked files.
- [x] **Reverse Engineering** — completed 2026-08-12. Artifacts in `aidlc-docs/inception/reverse-engineering/`. **Awaiting human approval.**
- [~] **Requirements Analysis** — in progress, blocked at the Step 6 gate since 2026-08-12. Intent
      analysis complete (enhancement / test hardening, multiple components, moderate complexity,
      **standard depth**). Questions written to
      `aidlc-docs/inception/requirements/requirement-verification-questions.md`. `requirements.md`
      cannot be written until they are answered.
- [ ] **User Stories** — conditional, not started.
- [ ] **Workflow Planning** — not started.
- [ ] **Application Design** — conditional, not started. `existing-feature-units.md` is the pre-seeded input.
- [ ] **Units Generation** — conditional, not started.

### CONSTRUCTION
- [ ] Per-unit loop — not started. No unit is in progress.
- [ ] Build and Test — not started.

### OPERATIONS
- [ ] Placeholder upstream; nothing to run. Aileron's equivalent concerns (PyPI release via trusted
      publishing, CI matrix, benchmark regression guard) already exist in `.github/workflows/`.

## Reverse Engineering Status
- [x] Reverse Engineering - Completed on 2026-08-12
- **Artifacts Location**: aidlc-docs/inception/reverse-engineering/
- **Analysed Against**: git `6c09efd` — artifacts become stale if `src/aileron/` changes materially.
