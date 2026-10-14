# Aileron - SPEC (single source of truth)

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
  src/aileron/__init__.py  events.py  chainlog.py  signing.py  policy.py  prefilter.py
                 detect.py  sdk.py  proxy.py  mcpserver.py  otel.py  report.py  cli.py  py.typed
  src/aileron/rules/examples/*.yml       # bundled rule pack (32 rules) + rate-spike-note.md
  tests/                                 # one test file per module, plus test_rule_pack.py,
                                         # test_metrics.py, test_real_mcp_server.py (opt-in, live)
```
`pyproject.toml`: PEP 621, setuptools, `[project.scripts] aileron = "aileron.cli:main"`,
name `aileron`, license Apache-2.0, requires-python >=3.10. The version lives in
`pyproject.toml` and `src/aileron/__init__.py` (`__version__`); the two must agree, and
`aileron --version` prints it.

## Event schema (events.py)
Canonical JSON: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`.
`ensure_ascii=True` keeps the hash input pure ASCII, so non-ASCII text and lone surrogates become
`\uXXXX` escapes rather than raising at hash time; `allow_nan=False` rejects NaN/Infinity, which are
not valid JSON. `events.canonical_json()` is the only implementation of this; every hash and
signature depends on its exact byte output, so changing it invalidates existing journals.
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
def sign_checkpoint(log_path, key_path) -> dict       # appends one JSON line to <log_path>.checkpoints.jsonl and returns it
def verify_checkpoint(log_path, key_path) -> bool     # PREFIX semantics, see below. key_path may be pub PEM, private PEM, or a dir (pub preferred)
def check_against_checkpoints(log_path) -> list[str]  # unauthenticated cross-check used by `aileron verify`: counts and tip hashes only
def checkpoint_payload(checkpoint) -> bytes           # the exact bytes the signature covers
def checkpoint_hash(checkpoint) -> str                # sha256 hex of checkpoint_payload(); the next checkpoint's prev_checkpoint_hash
def read_checkpoints(log_path) -> list[dict]          # file order, junk lines skipped, nothing verified
def load_public_key(key_path) -> Ed25519PublicKey     # pub PEM, private PEM (public half derived), or a directory
```
A checkpoint line is canonical JSON of
`{ts, log_path, index, prev_checkpoint_hash, count, tip_hash, signature, pubkey_path}`:
- `ts`: RFC3339 UTC with milliseconds and a `Z` suffix.
- `log_path`: the journal path as given to `sign_checkpoint`, usually absolute. **It is signed**, so it
  cannot be changed after the fact, and it is disclosed to anyone the checkpoint is shared with.
- `index`: 1-based position in the checkpoint file. `prev_checkpoint_hash`: `checkpoint_hash()` of the
  previous checkpoint, or the genesis value `'0'*64` for the first. Together these chain checkpoints to
  each other so deleting, duplicating, or reordering one inside the sequence is detected.
- `count`: number of events covered. `tip_hash`: `hash` of event `count-1`.
- `signature`: base64 Ed25519 (pure, not Ed25519ph) over `checkpoint_payload(checkpoint)`, which is the
  canonical JSON of every field above except `signature` and `pubkey_path`.
- `pubkey_path`: where the public key was written at signing time. Informational, not signed.

Signing an empty journal is refused. Verification has PREFIX semantics: the chain must be intact, the
journal must hold at least `count` events, event `count-1` must have `tip_hash`, every signature must
verify, and indexes must run 1..n with each `prev_checkpoint_hash` matching. Appending after signing
never invalidates a checkpoint; truncating or rewriting the signed prefix does. Deleting the newest
checkpoints is not detectable locally (see SECURITY.md); anchoring them outside the host, as the
companion package `aileron-anchor` does with Sigstore Rekor, is what closes that gap.

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
in-memory event before decide(), regardless of capture_content - content
matchers must fire in digest-only mode. ChainLog.append strips content from
the persisted copy. capture_content controls persistence, never enforcement.

## Regex prefilter (prefilter.py)
Speed only, never a detection. Before running a `<key>_regex` pattern the engine asks whether the
payload can possibly match: each pattern is parsed once into a conjunction of literal sets such
that any matching string must contain one literal from every set. Case folding uses `fold()`,
which agrees with `re.IGNORECASE` over the whole Unicode range (`str.lower()` and
`str.casefold()` do not). Anything the extractor does not fully understand returns `None`,
meaning "run the regex". `AILERON_NO_PREFILTER=1` disables it.
```python
def fold(text) -> str
def requirement(pattern) -> tuple | None          # conjunction of frozenset literals, or None
def required_literals(pattern) -> frozenset | None
def can_skip(pattern, folded_haystack, seen=None) -> bool   # True only when a match is impossible
```

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

Coroutine functions: when `inspect.iscoroutinefunction(fn)` is true, `track`
returns an `async def` wrapper with the same event semantics as the sync path.
The policy decision and any `PolicyBlocked` happen when the coroutine is
awaited, before the body starts; the `tool_call` event is appended when the
awaited call returns or raises, so `latency_ms` spans the await and an
exception inside the coroutine records `status='error'`. Creating the
coroutine object without awaiting it records nothing. The wrapper satisfies
`inspect.iscoroutinefunction` and `functools.wraps` preserves `__wrapped__`,
so `inspect.signature` reports the original parameters. A plain `def` that
returns an awaitable is not special-cased: it is recorded when it returns.

## MCP stdio proxy (proxy.py)
Speaks JSON-RPC 2.0 over stdin/stdout (newline-delimited and Content-Length framed - support both).
Spawns child: `argv` after `--`. Logs every `tools/call` request/response as tool_call events
(tool.name = params.name, args digest from params.arguments; args attached in memory for policy).
Policy block -> JSON-RPC error (-32000, "blocked by aileron rule <id>") returned to client, child
NOT invoked, event status='blocked'. Non-tools/call messages pass through, optionally logged as
meta-only. On shutdown, in-flight tools/call events that never received a response are journaled
with status='error' and meta.error noting the missing response (crash-safe recording).
```python
def run_proxy(child_argv: list[str], log: ChainLog, rules: list[Rule]|None) -> int  # exit code of child
```

## Journal MCP server (mcpserver.py)
`aileron serve --root DIR` exposes journals read-only over MCP stdio (protocol `2024-11-05`).
Three tools: `verify_journal(journal)`, `query_events(journal, tool?, status?, since?, until?,
limit?)`, `explain_rule(rule_id)`. No write, delete, rotate, or sign tool, ever. Every journal
name is resolved and must sit inside `--root`; only `.jsonl` opens; signing keys are never read;
every reply carries the journal's integrity status; errors never echo file contents. Responses
are capped (`MAX_RESULTS=200`, `MAX_FIELD_CHARS=200`, `MAX_RESPONSE_BYTES=64 KiB`).
```python
def serve(root: str, stdin=None, stdout=None) -> int
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
aileron --version                      # prints 'aileron <version>'
aileron init [--dir .]                 # keypair + ./aileron.chain.jsonl + ./rules dir
aileron verify <log>
aileron sign-checkpoint <log> [--key path]
aileron verify-checkpoint <log> [--key path]
aileron report <log> -o out.html
aileron export <log> -o spans.json
aileron serve [--root .]        # read-only MCP server over journals in --root
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
- policy: policy.py prefilter.py detect.py src/aileron/rules/examples/* + tests (test_policy/test_prefilter/test_detect/test_rule_pack)
- surface: pyproject.toml cli.py mcpserver.py otel.py report.py + tests (test_cli/test_mcpserver/test_otel/test_report) + __init__.py

All modules import across each other ONLY via the signatures above. No other cross-module
internals. Every module has `from __future__ import annotations`. Code style: type hints,
docstrings on public functions. Tests use tmp_path fixtures; no network.
