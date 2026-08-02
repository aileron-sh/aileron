# Contributing to Aileron

Thanks for helping build the flight recorder for AI agents. Contributions of
all sizes are welcome — detection rules, framework adapters, engine fixes,
docs, and tests.

## Development setup

Requires Python >= 3.10.

```console
$ git clone https://github.com/aileron-sh/aileron.git
$ cd aileron
$ python3 -m venv .venv && source .venv/bin/activate
$ pip install -e ".[dev]"
```

## Running tests

```console
$ python3 -m pytest tests/ -q
```

The suite must stay green. Tests use
`tmp_path` fixtures and make **no network calls** — keep it that way. New
behavior needs a focused test that exercises it; a PR that changes behavior
without a test will be asked to add one.

## Benchmarking

The proxy sits inline on every tool call, so latency is a correctness-adjacent
concern. To measure it:

```console
$ python scripts/benchmark.py
```

It drives an identical stdio MCP child directly and through `aileron proxy`,
and reports the delta plus the absolute baseline so the subtraction can be
checked. CI runs the same script on every push and fails if median overhead
regresses more than 2× against `scripts/benchmark_baseline.json`.

If a change makes the proxy legitimately slower — a security fix that costs
latency, for example — re-record the baseline on a CI run and commit it,
rather than loosening the threshold:

```console
$ python scripts/benchmark.py --json scripts/benchmark_baseline.json
```

## Code style

- `from __future__ import annotations` at the top of every module.
- Type hints on all public functions; docstrings on public API.
- Standard library + `pyyaml` + `cryptography` only. New runtime
  dependencies need a strong justification in the PR description.
- Canonical JSON (`sort_keys=True, separators=(",", ":")`) is a correctness
  property of the hash chain — never hand-format event JSON.
- Cross-module imports go through the public signatures documented in
  `SPEC.md` only; don't reach into sibling-module internals.

## What to work on (good first issues)

The intended contribution unit is a **detection rule**, not engine code.

- **New rules** — add a Sigma-like YAML rule under `src/aileron/rules/examples/`
  (tool-chain anomaly patterns, exfil-over-tools heuristics, MCP abuse
  cases). A complete rule PR is: the rule file, a short note on what it
  catches, and ideally an example trace it fires on. Bar: one evening, no
  engine code.
- **New framework adapters** — runnable examples under `examples/` showing
  `@track` / `track_agent` wired into a specific framework (LangChain,
  CrewAI, LlamaIndex, ...). Adapters must degrade gracefully: runnable with
  stdlib only when the framework isn't installed, with the real import
  shown in comments.
- **Exporters / reports** — new export targets for `otel.py`-style output,
  or improvements to the HTML incident report (inline CSS only, no external
  assets).
- Look for issues labeled `good first issue` — we aim to keep 6–10 open at
  all times.

## DCO sign-off (no CLA)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a Contributor License Agreement. By signing off your commits you
certify that you wrote the contribution or have the right to submit it under
the Apache-2.0 license:

```console
$ git commit -s -m "policy: add rule for credential-file reads"
```

This adds `Signed-off-by: Your Name <you@example.com>` to the commit
message. PRs without sign-offs will be asked to amend (`git rebase
--signoff` works fine).

## Pull requests

- Keep PRs focused; one concern per PR.
- Describe behavior changes and their security implications explicitly —
  this is a security tool, and "refactor" PRs that change semantics will be
  read accordingly.
- Do not introduce network calls into the library or CLI. Aileron's
  no-telemetry posture is a feature; anything that changes it requires an
  RFC first.

## Security issues

Do **not** open public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for the reporting process.
