# Requirement Verification Questions

**Stage**: INCEPTION → Requirements Analysis
**Change request**: Write tests for the seven security invariants that Aileron enforces in code but no
test asserts (see `aidlc-docs/inception/reverse-engineering/code-quality-assessment.md`).
**Created**: 2026-08-12
**Status**: ⛔ awaiting answers — Requirements Analysis cannot produce `requirements.md` until these are filled in.

## How to answer

Write your choice after each `[Answer]:` tag, in this file. One letter is enough (`B`), or a letter
plus a note. Every question has an `X) Other` option for anything the options miss.

If you would rather answer in conversation, that works too — the answers get transcribed back into
this file either way, because this file is the durable record and the chat is not.

A recommendation is given for each question. Recommendations are not answers; they exist so you can
disagree with something specific rather than starting from a blank page.

---

## Question 1: Scope of this unit

The seven untested invariants are: (1) `_canonical_wire` applied in both directions — "forward what we
policed, not the peer's bytes"; (2) the `_HEADER_RE` malformed-header rejection; (3) all four
`record_failed` paths; (4) `MAX_PENDING` overflow and its `aileron-pending-limit` pseudo-rule; (5) the
non-mapping `params` and non-scalar response-`id` guards; (6) the proxy's JSON-RPC error redaction to
`{code, digest}`; (7) `verify-checkpoint`'s key-path disclosure, `sha256:` fingerprint, and
co-location warning.

A) The seven invariants only. Tests, and no production-code change unless a test proves a bug.

B) The seven, plus fix debt item 6 — `verify` raises `IsADirectoryError` / `PermissionError` on an
unreadable path or a directory, and `cli.main()` does not catch `OSError`, so `aileron verify <dir>`
exits with a traceback.

C) The seven, plus debt item 6, plus resolving the two inert policy features (`action: allow` is a
no-op; `severity_gte` cannot fire on any event this package produces).

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** Debt item 6 is a small fix in code the new tests are already exercising, and it
is user-visible on the one command users are told to trust. C drags in a public-API semantics decision
(what should `allow` mean?) that deserves its own gate rather than riding along with a test unit.

[Answer]: 

---

## Question 2: What counts as done — the proof standard

This matters more than usual here. For invariant 1, the existing framing tests pass whether or not
`_canonical_wire` is present, so "a test exists and passes" would prove nothing.

A) Each invariant has a test, and the suite passes.

B) Option A, plus every new test is **mutation-checked**: deliberately revert the invariant in a
scratch copy, confirm the new test fails, restore, and record the exact mutation in the test's
docstring so a reviewer can repeat it.

C) Option B, plus a coverage measurement gate in CI.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** This is the measurable output for the unit — a test that cannot fail is
documentation with a misleading badge. C couples this unit to a CI-policy decision; see Question 7.

[Answer]: 

---

## Question 3: May production code change to make these paths testable?

Several `record_failed` paths need a failure injected (a journal write that fails, a reader thread that
aborts). That may be awkward from outside the module.

A) No. Tests use only the existing public surface plus `monkeypatch`.

B) Yes — small, reviewable seams are allowed (for example an injectable sink that raises, or a
narrowly scoped internal hook), documented in the unit's functional design.

C) Yes, and restructuring `proxy.py` is in scope if it makes failure injection cleaner.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B**, with two hard constraints: no seam may weaken any of the fourteen
non-negotiables in `AGENTS.md`, and no seam may change observable wire behaviour. C is a refactor of
the most security-critical module in the package and should be its own unit with its own design gate.

[Answer]: 

---

## Question 4: What happens when a test finds a real bug

Likely, not hypothetical — the `record_failed` and `_HEADER_RE` paths have never been executed by a test.

A) Stop and gate before any fix, every time.

B) Fix it inside this unit, log it in `audit.md`, and add a `CHANGELOG.md` entry — except where the fix
would change public behaviour or the wire format, which stops and gates.

C) Leave the test `xfail` and file the bug for a later unit.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** A security-relevant defect found by a new test should not wait on a round trip,
but anything that changes what a client sees on the wire is an architecture decision and yours to make.

[Answer]: 

---

## Question 5: Test-suite conventions

Today: one test module per source module, each inserting `../src` on `sys.path`, no `conftest.py`, and
`test_proxy.py` carries its own `_ProxySession` helper. The new proxy tests will want shared
failure-injection scaffolding.

A) Keep the conventions exactly as they are; duplicate helper code if needed.

B) Introduce a `conftest.py` for shared proxy fixtures only; leave every other convention alone.

C) Restructure the suite properly — fixtures, markers, maybe test packages.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** Note this deliberately changes a convention I recorded in `AGENTS.md` ("no
`conftest.py`"), which is exactly why it is a question and not an assumption.

[Answer]: 

---

## Question 6: Suite runtime budget (non-functional)

Proxy tests spawn real subprocesses, and CI runs eight matrix jobs.

A) No constraint — correctness first.

B) Keep the whole suite under roughly 60 seconds locally; if a test would blow that, mark it slow.

C) Introduce a `slow` marker now and exclude it from the default run.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** Cheap to honour today, and it keeps the eight-job matrix from becoming the next
bottleneck.

[Answer]: 

---

## Question 7: Are CI or tooling changes in scope for this unit?

The reverse-engineering pass flagged no linter, no type checker, and no coverage tool, despite the
package shipping `py.typed`.

A) No CI or tooling changes in this unit. Handle lint, typing, and coverage as a separate unit.

B) Add coverage reporting, non-blocking, in this unit.

C) Add ruff, mypy, and coverage gates in this unit, since the tests are being touched anyway.

X) Other (please describe after [Answer]: tag below)

**Recommendation: A.** The bottleneck reasoning says tooling gates matter — and also says finish one
unit before starting another. Adopting ruff and mypy will produce findings across all 2,625 lines,
which would swamp a focused security-test unit.

[Answer]: 

---

## Question 8: Release intent

A) Land on `main`, no release.

B) Cut a patch release 0.1.4 with a `CHANGELOG.md` entry once the suite is green.

C) Hold for a larger release alongside a roadmap feature.

X) Other (please describe after [Answer]: tag below)

**Recommendation: B if Question 1 is answered B or C** (a user-visible fix ships, so it should reach
users), otherwise A — a test-only change does not need a release.

[Answer]: 

---

## Question 9: Sequencing within the unit

A) Risk order: `_canonical_wire` first, then `record_failed`, then `_HEADER_RE`, then the remaining
four, as separate commits.

B) Cheapest first, to build momentum.

C) All seven together in one change.

X) Other (please describe after [Answer]: tag below)

**Recommendation: A.** It front-loads the invariant whose absence would be most damaging, and separate
commits keep the security history readable — matching the existing `security:`-prefixed commit style.

[Answer]: 

---

## Question: Security Extensions

Should security extension rules be enforced for this project?

A) Yes — enforce all SECURITY rules as blocking constraints (recommended for production-grade applications)

B) No — skip all SECURITY rules (suitable for PoCs, prototypes, and experimental projects)

X) Other (please describe after [Answer]: tag below)

**Recommendation: A, with per-rule N/A.** SECURITY-03, 05, 09, 10, 11, 12, 13, and 15 map directly onto
a library and CLI; the cloud-infrastructure rules (01, 02, 04, 06, 07, 08, 14) have no deployed
workload to apply to and resolve to N/A. Note the rules are blocking by default: a finding suppresses
"Continue to Next Stage" until it is resolved or marked N/A.

[Answer]: 

---

## Question: Property-Based Testing Extension

Should property-based testing (PBT) rules be enforced for this project?

A) Yes — enforce all PBT rules as blocking constraints (recommended for projects with business logic, data transformations, serialization, or stateful components)

B) Partial — enforce PBT rules only for pure functions and serialization round-trips (suitable for projects with limited algorithmic complexity)

C) No — skip all PBT rules (suitable for simple CRUD applications, UI-only projects, or thin integration layers with no significant business logic)

X) Other (please describe after [Answer]: tag below)

**Recommendation: B (Partial).** Hypothesis is the named Python framework, and canonical JSON,
chain append-then-verify, JSON-RPC framing round-trips, and the policy matcher are textbook invariant
and round-trip targets. Partial mode enforces PBT-02, 03, 07, 08, and 09 and leaves the rest advisory.
Answering A or B adds `hypothesis` to the dev extra, which is a new dependency — say so in `X` if you
would rather not.

[Answer]: 

---

## Question: Resiliency Extensions

Should the resiliency baseline be applied to this project?

**What this extension is.** Enabling it applies a set of **directional, design-time best practices** for building resilient systems, derived from the **AWS Well-Architected Framework (Reliability Pillar)** and resilience-review guidance. It steers requirements, design, and code toward fault tolerance, high availability, observability, and recoverability — covering 15 practice areas across business goals, change management, observability, high availability, disaster recovery, and continuous improvement.

**What this extension is NOT.** Enabling it does **not** make your workload production-ready, nor does it certify or guarantee any availability, RTO, or RPO target. It is a **starting point** that scaffolds good resiliency decisions early — it is not a substitute for a formal **AWS Well-Architected Review** of the built system.

Treat the output as a well-grounded **first draft of your resiliency posture** to build on and validate — not a finished, production-certified result.

A) Yes — apply the resiliency baseline as directional best practices and design-time guidance (recommended for business-critical workloads, as an informed starting point that you can validate and harden before go-live)

B) No — skip the resiliency baseline (suitable for PoCs, prototypes, and experimental projects where rapid iteration matters more than reliability)

X) Other (please describe after [Answer]: tag below)

**Recommendation: B.** The fifteen rules assume a deployed cloud workload — multi-AZ topology, RTO/RPO
targets, auto-scaling, DR runbooks. Aileron deploys nothing; nearly every rule would resolve to N/A,
which is ceremony without findings. Worth revisiting if a hosted verification service is ever built.

[Answer]: 

---

## Follow-up round

Left empty deliberately. Per the stage rules, answers are analysed for ambiguity and a second round of
questions is added here if anything remains unresolved.
