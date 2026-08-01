# Aileron — SPEC (single source of truth)

Aileron is an open-source (Apache-2.0) "flight recorder for AI agents": tamper-evident,
hash-chained audit logging of agent actions, Sigma-like policy rules with block/alert
enforcement, behavioral anomaly detection, MCP stdio proxy interception, OTel GenAI-aligned
export, and HTML incident-replay reports. Pure Python >=3.10. Runtime deps: `pyyaml`,
`cryptography`. Dev deps: `pytest`.

## Repo layout
```
aileron/
  SPEC.md
  pyproject.toml
  src/aileron/__init__.py  events.py  chainlog.py  signing.py  policy.py
                 detect.py  sdk.py  proxy.py  otel.py  report.py  cli.py  py.typed
  src/aileron/rules/examples/destructive-shell.yml  secrets-exfil.yml  rate-spike-note.md
  tests/test_events.py test_chainlog.py test_signing.py test_policy.py
        test_detect.py test_sdk.py test_proxy.py test_otel.py test_report.py test_cli.py
```
`pyproject.toml`: PEP 621, setuptools, `[project.scripts] aileron = "aileron.cli:main"`,
name `aileron`, version `0.1.0`, license Apache-2.0, requires-python >=3.10.

## Event schema (events.py)
Canonical JSON: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
```python
EVENT_TYPES = {"tool_call","llm_call","agent_start","agent_end","policy_decision","alert"}
def new_event(type, session_id, agent_name, framework, **fields) -> dict
    # fills: id(uuid4 hex), ts(RFC3339 UTC 'Z'), seq=0, session_id,
    # agent={name,framework,version}, type, status='ok', latency_ms=None,
    # tool/result/policy/meta optional, prev_hash/hash placeholders '0'*64
def canonical(event) -> str            # canonical JSON of event minus 'hash'
def event_hash(event) -> str           # sha256 hex of canonical(event)
def digest(obj) -> str                 # sha256 hex of canonical JSON of obj
def validate(event) -> list[str]       # schema errors, [] if valid
```
Event dict keys: id, ts, seq, session_id, agent{name,framework,version}, type,
tool{name,arguments_digest,arguments(opt-in,null default)}, result_digest, result(opt-in),
status('ok|error|blocked'), latency_ms, policy({rule_id,action}|None), meta(dict), prev_hash, hash.

## Hash-chained log (chainlog.py)
Append-only JSONL. Genesis prev_hash = '0'*64.
```python
class ChainLog:
    def __init__(self, path: str, capture_content: bool = False)  # capture_content gates PERSISTED tool.arguments/result only
    def append(self, event: dict) -> dict   # non-mutating: chains a copy (seq=prev+1, prev_hash, hash), strips content on the copy when capture_content False, writes line, returns the stored event
    def __iter__ / classmethod read(path) -> list[dict]
@dataclass VerifyResult: ok: bool; count: int; first_bad_seq: int|None; errors: list[str]
def verify(path) -> VerifyResult   # checks seq continuity, prev_hash links, hash recompute
```

## Signing (signing.py)
```python
def generate_keypair(dir_path) -> tuple[str,str]      # writes aileron_ed25519.key/.pub (PEM), returns paths
def sign_checkpoint(log_path, key_path) -> dict       # {ts, log_path, count, tip_hash, signature(b64), pubkey_path}; appends JSON line to <log_path>.checkpoints.jsonl
def verify_checkpoint(log_path, key_path) -> bool     # PREFIX semantics: chain intact, log count >= checkpoint count, event[count-1].hash == tip_hash, ed25519 signature valid; appends after signing never invalidate, truncation/rewrite of the prefix does. key_path may be pub PEM, private PEM, or a dir (pub preferred)
```

## Policy rules (policy.py)
Rule YAML (Sigma-like):
```yaml
id: aileron-001
title: Block destructive shell commands
severity: high            # low|medium|high|critical
match:
  type: tool_call
  tool.name: shell
  tool.arguments_contains: ["rm -rf", "DROP TABLE", ":(){ :|:& };:"]
action: block             # allow|alert|block
```
Matchers: dotted-key equality (`tool.name: shell`), `<key>_contains: [strings]` (substring
against canonical-serialized value, case-insensitive), `<key>_regex: <pattern>`, `severity_gte: high`.
```python
@dataclass Rule: id, title, severity, match: dict, action: str
def load_rules(path) -> list[Rule]         # file or dir of .yml/.yaml; raises ValueError on bad rule
def matches(rule, event) -> bool
@dataclass Decision: action: str; rule_ids: list[str]
def decide(event, rules) -> Decision       # any block -> block (first wins); else alerts; default allow
SEVERITY_ORDER = ["low","medium","high","critical"]
```
Enforcement contract: SDK and proxy ALWAYS attach tool.arguments to the
in-memory event before decide(), regardless of capture_content — content
matchers must fire in digest-only mode. ChainLog.append strips content from
the persisted copy. capture_content controls persistence, never enforcement.

## Anomaly detection (detect.py)
```python
class Baseline:
    def __init__(self, path: str|None = None)   # JSON persistence: per-session tool counts, per-tool hourly rate, seen tool names
    def observe(self, event) -> None
    def save(self)/load
    def flag(self, event) -> list[str]  # 'first_seen_tool:<name>', 'rate_spike:<tool> (>3x baseline)', 'novel_sequence:<a>-><b>'
```
flag() compares against baseline before observe(); rate computed over trailing window stored in baseline.

## SDK instrumentation (sdk.py)
```python
@track(tool_name=None, log=None, rules=None, baseline=None)
def wrapper(fn): ...   # records tool_call event (args always attached in memory; persisted per log.capture_content),
                       # policy decide -> block raises PolicyBlocked(rule_id); status ok/error; latency_ms;
                       # baseline.flag -> one 'alert' event per flagged call, meta={"flags": [...], "event_id": ...}
class PolicyBlocked(RuntimeError): rule_id: str
def track_agent(name, framework, log) -> AgentSession  # context manager emitting agent_start/agent_end, own session_id
```
Default global log path: env `AILERON_LOG` or `./aileron.chain.jsonl`.

## MCP stdio proxy (proxy.py)
Speaks JSON-RPC 2.0 over stdin/stdout (newline-delimited and Content-Length framed — support both).
Spawns child: `argv` after `--`. Logs every `tools/call` request/response as tool_call events
(tool.name = params.name, args digest from params.arguments; args attached in memory for policy).
Policy block -> JSON-RPC error (-32000, "blocked by aileron rule <id>") returned to client, child
NOT invoked, event status='blocked'. Non-tools/call messages pass through, optionally logged as
meta-only. On shutdown, in-flight tools/call events that never received a response are journaled
with status='error' and meta.error noting the missing response (crash-safe recording).
```python
def run_proxy(child_argv: list[str], log: ChainLog, rules: list[Rule]|None) -> int  # exit code of child
```

## OTel export (otel.py)
```python
def to_otel_spans(events: list[dict]) -> list[dict]   # one dict per event:
    # {name: f"execute_tool {tool.name}" (or invoke_agent for agent_*), kind: 'INTERNAL',
    #  attributes: {'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':...,
    #               'gen_ai.agent.name':..., 'aileron.event.hash':..., 'aileron.status':...},
    #  start_time/end_time from ts+latency_ms (ns)}
def to_otlp_spans(events) -> list[dict]   # OTLP proto3 JSON mapping: traceId (sha256 of session_id,
    # 16 bytes hex), spanId (sha256 of event id, 8 bytes hex), kind=1 (SPAN_KIND_INTERNAL),
    # startTimeUnixNano/endTimeUnixNano as strings, attributes as KeyValue lists
def export_json(events, out_path) -> None  # writes an OTLP/HTTP-JSON-ingestible resourceSpans envelope
```

## Incident report (report.py)
```python
def render_html(events: list[dict], verify_result, out_path, title="Aileron Incident Report") -> None
```
Single-file HTML: header w/ verification badge (VERIFIED ok/count or TAMPERED at seq N),
filterable timeline table (ts, seq, type, tool, status, rule, hash prefix, flags), low-saturation
warm palette, inline CSS only, no external assets, no JS frameworks (vanilla filter ok).

## CLI (cli.py, argparse)
```
aileron init [--dir .]                 # keypair + ./aileron.chain.jsonl + ./rules dir
aileron verify <log>
aileron sign-checkpoint <log> [--key path]
aileron verify-checkpoint <log> [--key path]
aileron report <log> -o out.html
aileron export <log> -o spans.json
aileron detect <log> [--state s.json] [--save]  # replay log through Baseline; prints flags per event
aileron rules test <rules_path> <log>  # dry-run: prints Decision per event
aileron proxy --log <path> [--rules <dir>] [--capture-content] -- <cmd...>
aileron demo                           # scripted fake-agent session (digest-only mode, real Baseline
                                       # alerts) -> demo.chain.jsonl + demo-report.html
```
All commands exit non-zero with clear stderr on failure; `verify` exits 2 on tamper.

## Module ownership (branches)
- core: events.py chainlog.py signing.py + tests (test_events/test_chainlog/test_signing)
- intercept: sdk.py proxy.py + tests (test_sdk/test_proxy)
- policy: policy.py detect.py src/aileron/rules/examples/* + tests (test_policy/test_detect)
- surface: pyproject.toml cli.py otel.py report.py + tests (test_cli/test_otel/test_report) + __init__.py

All modules import across each other ONLY via the signatures above. No other cross-module
internals. Every module has `from __future__ import annotations`. Code style: type hints,
docstrings on public functions. Tests use tmp_path fixtures; no network.
