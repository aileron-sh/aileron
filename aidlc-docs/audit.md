# AI-DLC Audit Log

Append-only record of user intent, agent decisions, and stage transitions. Newest entries at the
bottom. Every stage transition and every human approval or change request must be logged here with
the raw input that caused it.

A note on why this file matters more here than in most projects: Aileron itself exists to produce a
tamper-evident record of what an agent did. An AI-DLC audit log that is vague, back-dated, or
retro-edited would be an embarrassing contradiction. Treat it the way the code treats its journal —
append, never rewrite.

---

## 2026-08-12 — Session 1

### Initial user request (raw)
> now on the Aileron use the agentic engineering principals along with aidlc framework

Preceded in the same conversation by a request to remember a set of agentic engineering principles
from a talk by Dexter Horthy: program design before implementation, human-in-the-loop review of
architecture, context engineering (keep high-signal context in the repo), compaction of session
history into formal documents at roughly 50% context, and focusing effort on the system's real
bottleneck rather than on optimising individual agents.

### Clarifying questions asked and answered
Asked as multiple choice before any file was written:
- **Scope** → "Scaffold + brownfield docs": install AI-DLC into the repo *and* run the
  reverse-engineering pass so future sessions start with real in-repo context.
- **Rule source** → "Pull from awslabs repo": the attached `aidlc-workflows-main.zip` never reached
  the agent sandbox (empty uploads mount), so rules were fetched from the public upstream instead.
- **Harness** → Claude Code (`CLAUDE.md`) *and* an agent-neutral `AGENTS.md`.
- **First unit** → "all the existing features": units are to be derived from what already ships,
  not from a new roadmap item.

### Stage: Workspace Detection — completed
- **Findings**: Brownfield. Python 3.10–3.13 library + CLI, `src/` layout, setuptools/PEP 621,
  11 source modules (2,625 lines), 10 test modules (2,083 lines, 117 test functions),
  40 git-tracked files, 3 GitHub Actions workflows. No pre-existing AI-DLC state file.
- **Codebase version**: 0.1.3, git `6c09efd` (2026-08-02).
- **Decision**: brownfield = true, no existing reverse-engineering artifacts → proceed to Reverse
  Engineering.
- **No user approval required** (informational stage).

### Rule acquisition — completed
- Pulled 32 rule files from `awslabs/aidlc-workflows`, `main`, tree
  `114ef4d0ae6082e63ff0c7d14a910e3195163235`, into `.aidlc/aidlc-rules/`, unmodified.
- Verified: all 19 rule-detail paths referenced by `core-workflow.md` resolve on disk; the one
  cross-reference (`../common/depth-levels.md`) resolves; no fetch-wrapper text or truncation
  markers leaked into any file.
- **Deviation logged**: three files (`common/overconfidence-prevention.md`,
  `common/process-overview.md`, `common/session-continuity.md`) arrived without a trailing newline;
  a single newline was appended to each. No other byte was altered.
- **Known risk logged**: content was retrieved through a text-fetch service rather than by cloning,
  because the sandbox has no general network egress. Whitespace-level fidelity is therefore
  asserted, not proven. If exact upstream bytes matter, re-clone and diff `.aidlc/` before relying
  on it.

### Stage: Reverse Engineering — completed, awaiting approval
- **Artifacts written** to `aidlc-docs/inception/reverse-engineering/`: `business-overview.md`,
  `architecture.md`, `code-structure.md`, `api-documentation.md`, `component-inventory.md`,
  `technology-stack.md`, `dependencies.md`, `code-quality-assessment.md`,
  `existing-feature-units.md`, `reverse-engineering-timestamp.md`.
- **Method**: every claim derived from reading the source, tests, workflows, and `pyproject.toml` at
  git `6c09efd`. Where the code and `SPEC.md` disagree, the code is recorded as truth and the
  divergence is logged as technical debt.
- **Local deviation from upstream**: `existing-feature-units.md` is not an upstream
  reverse-engineering artifact. It was added because the human asked for units covering all
  existing features, while Units Generation is gated behind Requirements Analysis and Application
  Design. It is recorded as *candidate* units — an input to Units Generation, not a substitute for
  running it.
- **Extension opt-ins**: proposed in `aidlc-state.md` (security baseline in, property-based testing
  partial, resiliency out) but **not** treated as answered. Requirements Analysis must still ask.
- **Status**: awaiting human approval. No code was modified in this session.

### Independent verification pass — completed
A separate agent fact-checked every artifact against the source with no knowledge of how the artifacts
were produced. It confirmed the load-bearing claims (line counts, dependency direction, the nine
public exports, the full CLI table and exit codes, checkpoint signature coverage, all four policy
clause forms and the inert `allow`, detector constants, digest-only stripping semantics, workflow
thresholds, the absence of lint/type/coverage tooling, all four `SPEC.md` divergences, and that no
module makes a network call) and found six substantive errors plus seven imprecisions. All were
corrected:

1. A semicolon inside a Mermaid `sequenceDiagram` message in `architecture.md` would have made the
   first diagram fail to render on GitHub — Mermaid treats `;` as a statement separator.
2. "`verify` never raises" was overstated in five files. It is total over file *content*; the
   unguarded `open(path, "rb")` still raises on a directory or an unreadable file, and `cli.main()`
   does not catch `OSError`. Corrected everywhere and filed as debt item 6 — a real code finding this
   documentation pass surfaced.
3. `code-structure.md` wrongly listed `proxy` as a user of `events.canonical_json`. The proxy's
   `_canonical_wire` omits `sort_keys` and is deliberately not the canonical serialiser.
4. The `cli.py` collision count was inconsistent (U-09 was missing from the table): nine of sixteen
   units touch it, eight besides U-12 itself. Fixed in four files.
5. `validate` was described as checking presence and type only; it also enforces formats and enum
   membership.
6. A `<id>` placeholder in a Mermaid label would have been stripped as an unknown HTML tag.

Imprecisions corrected: the file-count breakdown in the timestamp artifact (summed to 37, not 40);
package-data omitted the `*.md` glob; `actions/download-artifact` was missing from the dependency
list; the "stdlib-only" description of `examples/langchain_tool_tracking.py` (it imports
`aileron.policy`, hence PyYAML — the example's own docstring makes the same overclaim); a
double-counted policy test; unclassified SECURITY-03 and SECURITY-11 in the extension table; and a
loose "header-smuggling terms" grep claim.

**Not verified**: the test suite was **not executed**. pytest is unavailable in the analysis sandbox
and there is no network egress to install it. Only markdown files were added in this session and no
source file was touched, so the suite's status is unchanged from git `6c09efd` — but that is an
inference, not an observation. Run `python -m pytest tests/ -q` locally to confirm.

### Pending human decisions
1. Approve or request changes to the reverse-engineering artifacts.
2. Confirm the three extension opt-in answers.
3. Decide whether `.aidlc/` and `aidlc-docs/` are committed to the public repo or kept local.
4. Supply the first real change request, which is what unblocks Requirements Analysis.

---

## 2026-08-12 — Session 1, continued: Requirements Analysis

### Change request (raw)
> yes do that

In response to a proposal to run Requirements Analysis on the following change request, which the human
accepted: **write tests for the seven security invariants that Aileron enforces in code but that no
test asserts**, as enumerated in `code-quality-assessment.md`. Item 4 of the pending decisions above is
therefore answered; items 1–3 remain open, and item 2 is now in flight as part of this stage.

### Step 1: Reverse-engineering context loaded
`architecture.md`, `component-inventory.md`, and `technology-stack.md`, per the stage prerequisites.

### Step 2: Intent analysis
- **Request clarity**: Clear. The target list is specific and enumerated, and it was derived from the
  code rather than from a wish.
- **Request type**: Enhancement — test hardening. Not a bug fix, though it is expected to *surface*
  bugs, since the `record_failed` and `_HEADER_RE` paths have never been executed by a test.
- **Scope**: Multiple components. Tests land mainly in `tests/test_proxy.py` and `tests/test_cli.py`;
  the invariants under test live in `proxy.py`, `signing.py`, and `cli.py`.
- **Complexity**: Moderate. The work is not algorithmically hard, but injecting failures into a
  subprocess-plus-reader-thread design is fiddly, and several paths may not be reachable from outside
  the module without a seam.

### Step 3: Depth decision
**Standard depth.** The request is clear enough not to need comprehensive treatment, but it is not
trivial either: it touches the most security-critical module in the package, and the answers to scope,
testability seams, and the proof standard genuinely change the design. Minimal depth would skip exactly
the questions that matter.

### Step 5: Completeness analysis
Gaps found across the mandated areas: functional (which invariants, and whether the newly discovered
`verify`/`OSError` defect is in scope); non-functional (suite runtime against an eight-job CI matrix);
quality attributes (what counts as proof that a test actually pins an invariant — critical here,
because the existing framing tests pass with or without the `_canonical_wire` fix); technical context
(whether production code may gain testability seams, and whether the no-`conftest.py` convention
holds); and business context (release intent, sequencing).

### Step 5.1: Extension opt-in prompts surfaced
All three opt-in prompts (`security-baseline`, `property-based-testing`, `resiliency-baseline`) were
copied **verbatim** from their `*.opt-in.md` files into the questions document, with a recommendation
appended to each. Enablement is **not** recorded yet and no extension rules file has been loaded —
deferred loading happens after the answers arrive, per Step 5.1.

### Step 6: Clarifying questions written — ⛔ GATE REACHED
Created `aidlc-docs/inception/requirements/requirement-verification-questions.md`: 9 project questions
plus the 3 extension opt-ins, each with lettered mutually exclusive options, an `X) Other` option, an
empty `[Answer]:` slot, and a stated recommendation so the human can disagree with something specific
rather than starting from blank.

**Stopped here as the rules require.** `requirements.md` (Step 7) is explicitly blocked until the
answers are in and analysed. Recommendations were deliberately not treated as answers.

### Deviation logged
The desktop harness offers an interactive multiple-choice prompt, but `session-continuity.md` item 9
and the convention recorded in `AGENTS.md` both require clarifying questions to live in markdown files
rather than inline in chat, so answers become part of the record. The file is therefore canonical; if
the human answers conversationally, the answers are transcribed into the file before Step 7 proceeds.
