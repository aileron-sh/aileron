# Aileron

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/Aileron-sh/aileron/actions/workflows/ci.yml/badge.svg)](https://github.com/Aileron-sh/aileron/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

**Aileron is a flight recorder for AI agents.**

Not another tracer. Aileron produces a tamper-evident, replayable record of
every tool call your agents make — evidence you can verify offline, not
telemetry you have to trust.

- **Tamper-evident audit trail.** Every agent action is appended to a
  SHA-256 hash-chained JSONL journal with Ed25519-signed checkpoints. Edit,
  delete, or reorder a single line and `aileron verify` says exactly where
  the chain broke.
- **Policy enforcement on tool calls.** Sigma-like YAML rules with
  `allow` / `alert` / `block` actions, applied *before* execution via the
  MCP stdio proxy or the SDK decorator. A blocked tool call never runs; the
  attempt is logged anyway.
- **Forensic incident replay.** One command turns a journal into a
  self-contained HTML incident report with a verification badge and a
  filterable timeline — the answer to "what did the agent actually touch?"

## 60-second quickstart

```console
$ pip install aileron
$ aileron demo            # scripted fake-agent session (no network, no keys needed)
demo: wrote 8 events to demo.chain.jsonl
demo: chain VERIFIED (8 events)
demo: blocked shell call by rule aileron-001
demo: 2 anomaly alert(s) emitted
$ aileron verify demo.chain.jsonl
OK: 8 events verified in demo.chain.jsonl
$ aileron report demo.chain.jsonl -o incident.html   # open it in a browser
```

The demo runs in the default digest-only mode: the destructive shell call is
blocked by a content rule and flagged by the behavioral baseline, yet the
journal on disk contains only argument digests — never the raw command.

## Features

| Feature | What you get |
|---|---|
| Hash-chained journal | Append-only JSONL; each event's `prev_hash` links to the previous event's SHA-256 hash; genesis is `0x00…00` |
| Signed checkpoints | Ed25519 signature over the chain tip, verifiable offline against the public key (`aileron sign-checkpoint` / `verify-checkpoint`). Checkpoints cover a *prefix*: appending later events never invalidates them; truncating or rewriting the signed prefix does |
| Policy rules | Sigma-like YAML (bundled `rules/examples/`); substring, regex, and dotted-key matchers. Rules are evaluated against the full call **in memory**, so content rules fire even in digest-only mode |
| Behavioral anomaly detection | Rolling baselines flag first-seen tools, rate spikes (>3x baseline), and novel tool-call sequences — live via the SDK (`baseline=`) or offline via `aileron detect` |
| MCP stdio proxy | Sits between any MCP client and server; logs and mediates every `tools/call` before it reaches the child process |
| OTel GenAI export | Events export as `gen_ai.*`-aligned span dicts (`aileron export`) for your existing collector |
| HTML incident reports | Single file, inline CSS, no external assets, verification badge (`VERIFIED` / `TAMPERED at seq N`) |
| Privacy by default | Tool arguments/results are recorded as digests only, unless you opt in with `--capture-content` |

## Usage

### SDK: `@track` decorator

```python
from aileron import ChainLog, track, PolicyBlocked, bundled_rules_dir
from aileron.policy import load_rules

log = ChainLog("run.chain.jsonl")            # capture_content=False by default
rules = load_rules(bundled_rules_dir())      # or load_rules("rules") after `aileron init`

@track(log=log, rules=rules)
def shell(cmd: str) -> str:
    ...  # your tool implementation

shell("ls /tmp")            # -> tool_call event, status=ok, args recorded as digest
shell("rm -rf /")           # -> PolicyBlocked raised; blocked attempt is logged
```

Rules see the full arguments in memory at decision time; the journal still
stores digests only. Turn on `capture_content=True` only when you want raw
arguments *persisted* for forensics.

### SDK: `track_agent` session

```python
from aileron import track_agent

with track_agent("research-agent", framework="langchain", log=log):
    shell("ls /tmp")   # inherits the session's agent identity and session_id
# agent_start / agent_end events bracket the run automatically
```

### MCP proxy: framework-agnostic interception

Wrap any MCP server. Every `tools/call` is logged and policy-checked *before*
the child process sees it:

```console
$ aileron init                       # seeds a ./rules directory with starter rules
$ aileron proxy --log run.chain.jsonl --rules rules -- \
    npx -y @modelcontextprotocol/server-filesystem /tmp
```

A blocked call returns a JSON-RPC error (`-32000: blocked by aileron rule
<id>`) to the client; the child is never invoked.

Mediation costs **sub-millisecond median overhead per `tools/call`, verified
on commodity hardware** — see [Performance](#performance).

The proxy speaks both newline-delimited and `Content-Length`-framed
JSON-RPC. Content rules
(`tool.arguments_contains`, `_regex`) work in the default digest-only mode —
`--capture-content` changes what is persisted, not what is enforced. Calls
still in flight when the child dies are journaled with `status=error`, so a
crash never erases the attempt.

### Policy rules

```yaml
# a policy rule (see the bundled rules/examples/destructive-shell.yml)
id: aileron-001
title: Block destructive shell commands
severity: high
match:
  type: tool_call
  tool.name: shell
  tool.arguments_contains: ["rm -rf", "DROP TABLE", ":(){ :|:& };:"]
action: block
```

Dry-run rules against a recorded session: `aileron rules test rules/ run.chain.jsonl`

## How it works

```
agent ──tool call──► [ SDK @track ] ──┐
                     [ MCP proxy  ] ──┼─► policy decide (allow/alert/block)
                                      │        │ block? ──► call never executes,
MCP client ──JSON-RPC──► proxy ───────┘        │        attempt still logged
                                               ▼
                              append to chain log (JSONL)

  event 0           event 1                      event N
 ┌──────────────┐  ┌──────────────┐        ┌──────────────┐
 │ seq: 0       │  │ seq: 1       │        │ seq: N       │
 │ prev: 0000…  │─►│ prev: H(e0)  │─► … ──►│ prev: H(eN-1)│
 │ hash: H(e0)  │  │ hash: H(e1)  │        │ hash: H(eN)  │──► Ed25519 checkpoint
 └──────────────┘  └──────────────┘        └──────────────┘    signature over tip

  H(e) = sha256(canonical_json(e \ hash))
  aileron verify          → recompute every hash + link (exit 2 on tamper)
  aileron verify-checkpoint → re-verify chain tip against Ed25519 signature
```

Tampering with any event breaks the hash link at the first modified
sequence; `verify` reports `first_bad_seq` and exits non-zero. The journal
is local-only and self-contained — verification needs no network and no
trusted third party.

## Performance

Aileron adds **sub-millisecond median overhead per `tools/call`, verified on
commodity hardware.** Every number below is reproducible with one command:

```console
$ python scripts/benchmark.py
```

**Method.** [`scripts/benchmark.py`](scripts/benchmark.py) drives an identical
stdio MCP child server two ways — directly, and through `aileron proxy` — and
subtracts. The delta is the proxy's true cost, so you never have to trust an
absolute figure. The absolute baseline is printed alongside it so the
subtraction can be checked. 2,000 sequential calls per configuration after 200
discarded warmup calls; rules loaded; digest-only journaling. Overhead covers
JSON-RPC parsing, policy evaluation, hash-chain append, re-serialization, and
the extra process hop.

### Added latency per `tools/call` (milliseconds)

**Linux x86_64** — GitHub Actions `ubuntu-latest` (2 shared vCPU), Python
3.12.13. Re-measured by CI on every push:
[![Benchmark](https://github.com/Aileron-sh/aileron/actions/workflows/benchmark.yml/badge.svg)](https://github.com/Aileron-sh/aileron/actions/workflows/benchmark.yml)

| tool arguments | direct (baseline) median | + proxy & rules median | **added median** | added p95 |
|---|---|---|---|---|
| 64 B | 0.051 | 0.315 | **0.264** | 0.280 |
| 4 KB | 0.064 | 0.370 | **0.306** | 0.353 |
| 32 KB | 0.171 | 0.800 | **0.629** | 0.668 |

**macOS arm64** — Apple M2 Pro, Python 3.13.7, idle machine. Each row is the
worst of three passes, so these are pessimistic rather than cherry-picked:

| tool arguments | direct (baseline) median | + proxy & rules median | **added median** | added p95 |
|---|---|---|---|---|
| 64 B | 0.0133 | 0.1003 | **0.0870** | 0.183 |
| 4 KB | 0.0290 | 0.1811 | **0.1521** | 0.250 |
| 32 KB | 0.1375 | 0.5227 | **0.3852** | 0.468 |

All values are milliseconds. Every row comes from a **single run**, so
`added = (proxy & rules) − direct` holds exactly and you can check the
subtraction. The tool reports mean / median / p95 / p99; these tables quote
median and p95.

Medians are stable across runs (64 B measured 0.087 / 0.085 / 0.087 ms over
three passes); **p95 is not** — tail latency on a desktop OS swings with
scheduling, and a single pass can look 40% better or worse than its
neighbour. Treat the median as the number and the p95 as an order of
magnitude. Linux is roughly 3× slower than the Mac because a shared-vCPU CI
runner is the slower machine — those are the conservative figures, and the
ones CI enforces.

**Caveats, stated plainly.** These are *sequential* stdio round-trips — one
call in flight at a time, which is how an agent actually calls tools. This is
not a concurrent-client benchmark; a many-client run is on the roadmap.
Overhead grows with argument size because hashing, digesting, and
re-serialization are all linear in payload. For context, a real MCP server
call is typically 10–1000 ms, so mediation costs well under 1% of it. Measure
on your own hardware before quoting a number.

CI enforces this: a job fails if median overhead regresses more than 2× against
[`scripts/benchmark_baseline.json`](scripts/benchmark_baseline.json), so
performance cannot decay silently.

## Integrations & ecosystem

- **OpenTelemetry GenAI** — `aileron export` emits `gen_ai.operation.name` /
  `gen_ai.tool.name` / `gen_ai.agent.name` span attributes plus
  `aileron.event.hash`, so Aileron sits *beside* your existing tracing
  stack as the evidence layer, not instead of it.
- **LangChain / CrewAI / any Python framework** — `@track` is a plain
  decorator; `track_agent` accepts a free-form `framework=` label. No
  framework dependency is required.
- **MCP** — the proxy wraps any stdio MCP server regardless of which client
  or framework drives it.
- **Community rules** — rule contributions are the intended contribution
  unit (see Roadmap).

## Telemetry & privacy

- **Aileron sends no telemetry.** No analytics, no phone-home, no network
  calls anywhere in the library or CLI. If that ever changes, it will be
  opt-in only, behind a documented RFC — for a security tool, anything less
  is disqualifying.
- **Content capture is off by default.** Tool arguments and results are
  recorded as SHA-256 digests; raw content is only stored when you pass
  `capture_content=True` / `--capture-content`. You get a verifiable record
  of *what happened* without persisting secrets or PII by accident.
  Policy rules and the anomaly detector still see the full call in memory
  at decision time — capture only controls what is *persisted*, never what
  is *enforced*.

## Honest limitations

- **SDK instrumentation is bypassable.** `@track` wraps the functions you
  decorate; code paths you don't instrument are not recorded. For
  enforcement that agent code cannot skip, use the MCP proxy — mediation
  happens in a separate process on the tool-call path.
- **Policy rules are pattern matching, not intent classification.** They
  catch known-bad shapes (`rm -rf`, `id_rsa`, exfil patterns); they will not
  reliably detect novel malicious reasoning. Detection-of-effect
  complements detection-of-intent tools (garak, PromptGuard); it does not
  replace them.
- **Tamper-evidence is not tamper-proof.** The chain proves modification
  after the fact; an attacker with write access can truncate or rewrite the
  whole log and forge it forward. Signed checkpoints make forgery require
  the private key — keep keys off the host being recorded, and anchor
  checkpoints externally (see Roadmap) if you need non-repudiation.

## Roadmap

- **`aileron-rules` community rule repo** — Sigma-for-agents: community
  detection rules mapped to the OWASP Agentic Security Initiative's threat
  taxonomy, CI-validated against recorded incident traces.
- **Sigstore/Rekor checkpoint anchoring** — publish signed checkpoints to a
  public transparency log for non-repudiable, third-party-verifiable
  timestamps.
- **OCSF export** — emit Open Cybersecurity Schema Framework events for
  direct SIEM ingestion (Splunk/Elastic quickstarts).
- **Out of scope for v1: eBPF / kernel-level interception.** Aileron stays
  at the MCP-proxy and SDK layer where the semantic meaning of a tool call
  is still visible; syscall-level tracing is Falco/Cilium territory and
  would trade agent semantics for volume.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good
starting points: new detection rules under `src/aileron/rules/examples/` and new
framework adapters under `examples/`. DCO sign-off, no CLA. Security
issues: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
