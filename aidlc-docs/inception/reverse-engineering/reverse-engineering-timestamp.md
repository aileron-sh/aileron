# Reverse Engineering Metadata

**Analysis Date**: 2026-08-12
**Analyzer**: AI-DLC (rules from `awslabs/aidlc-workflows`, `main`, tree `114ef4d0ae6082e63ff0c7d14a910e3195163235`)
**Workspace**: the `aileron/` repository root (relative marker — no machine-specific absolute path is
recorded, so these artifacts stay portable and no local directory layout leaks into a public repo)
**Codebase Version**: 0.1.3, git `6c09efd31e27e47a57aec33874f8c8a04905b98a` (2026-08-02)
**Total Files Analyzed**: all 40 git-tracked files — 11 source modules (2,625 lines), 10 test modules
(2,083 lines, 117 test functions), 3 GitHub Actions workflows, 2 bundled YAML rules plus
`rules/examples/rate-spike-note.md`, `py.typed`, 2 examples, 2 benchmark files, `.gitignore`, and the
top-level docs (`README.md`, `SPEC.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`,
`pyproject.toml`)

## Artifacts Generated
- [x] business-overview.md
- [x] architecture.md
- [x] code-structure.md
- [x] api-documentation.md
- [x] component-inventory.md
- [x] technology-stack.md
- [x] dependencies.md
- [x] code-quality-assessment.md
- [x] existing-feature-units.md — local addition, not an upstream artifact; see the status note inside it

## Method and its limits

Every claim in these artifacts was derived by reading the source, the tests, the workflows, and
`pyproject.toml` at the commit above. Where the code and `SPEC.md` disagree, the **code** is recorded
as truth and the divergence is filed as technical debt in `code-quality-assessment.md`.

Two limits are worth stating plainly, because an artifact set that overstates its own certainty is
worse than one that doesn't:

- **The test suite was not executed** during this analysis (pytest was unavailable in the analysis
  sandbox). Test counts are from static reading — 117 `def test_` functions, roughly 122 collected
  once the six parametrisations in `test_policy.py::test_load_rules_error_cases` expand. Coverage
  percentages are **unknown**: no coverage tool is configured in the project.
- **Line counts** are `wc -l` outputs, not logical-statement counts.

## Staleness

These artifacts describe git `6c09efd`. They become stale when `src/aileron/` changes materially.
Per `workspace-detection.md`, a future AI-DLC session compares artifact currency against the
codebase's last significant modification and reruns Reverse Engineering if they have fallen behind.
The cheap check: if `git log --oneline 6c09efd..HEAD -- src/` is non-empty, assume stale and rerun
rather than trusting these files.
