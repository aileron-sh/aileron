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
                 detect.py  sdk.py  proxy.py  hook.py  mcpserver.py  otel.py  report.py  cli.py  py.typed
  src/aileron/rules/examples/*.yml       # bundled rule pack (32 rules) + rate-spike-note.md
  tests/                                 # one test file per module (test_hook.py included),
                                         # plus test_rule_pack.py,
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
See "Independent verification" below for the byte-level rules a second implementation must follow.
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

`session_id`, `agent.name` and `agent.framework` are opaque strings. CLI surfaces accept 1 to 128
printable characters with no leading or trailing whitespace; `validate()` does not enforce this
bound, so journals written by older code stay valid.

`meta.transport` (string, optional) names the producing surface: `mcp-stdio` on proxy events,
`claude-code-hook` on hook events, absent on SDK events. Hook events carry `meta.hook` with `event`
(the Claude Code `hook_event_name`), `tool_use_id` (string or null), and when present `cwd`,
`permission_mode`, `agent_id`, `agent_type`, `mcp_server{name,source}`, `is_interrupt`
(PostToolUseFailure only) and `dropped` (names of payload fields omitted for size or type). On a
PreToolUse record `status` is the policy verdict (`ok` released, `blocked` stopped); on a
PostToolUse or PostToolUseFailure record `status` is the outcome and `policy` is the verdict of the
rules against the executed call. Synthetic rule ids: `aileron-pending-limit` (proxy capacity
refusal) and `aileron-hook-config` (hook refused because rules could not be loaded).

## Hash-chained log (chainlog.py)
Append-only JSONL. Genesis prev_hash = '0'*64.
```python
class ChainLog:
    def __init__(self, path: str, capture_content: bool = False)  # capture_content gates PERSISTED tool.arguments/result only
    def append(self, event: dict) -> dict   # non-mutating: chains a copy (seq=prev+1, prev_hash, hash), strips content on the copy when capture_content False, writes line, returns the stored event
    def __iter__ / classmethod read(path) -> list[dict]
@dataclass VerifyResult: ok: bool; count: int; first_bad_seq: int|None; errors: list[str]
def verify(path) -> VerifyResult   # checks seq continuity, prev_hash links, hash recompute
def exclusive_lock(path, timeout) -> ContextManager[None]  # advisory lock on <path>.lock; TimeoutError after timeout
```
A journal is written either by one long-lived process (proxy, SDK) or by short-lived processes that
each hold `exclusive_lock` around construction and append, never both. The lock is `fcntl.flock` on
POSIX and `msvcrt.locking` on Windows, retried every 10 ms; a busy lock is `BlockingIOError` or
`PermissionError`, and any other `OSError` surfaces at once. The Windows branch is untested because
CI has no Windows runner. Where neither module imports, `exclusive_lock` raises `OSError` before
opening anything, so no caller appends unlocked.

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

Environment variables read by the library and the CLI.
- `AILERON_LOG` (`sdk.default_log()`, `aileron hook`): journal path when no flag is given; read as
  given by the SDK, stripped of surrounding whitespace by the hook
- `AILERON_NO_PREFILTER` (`prefilter.py`): disable the regex prefilter; unset only when empty or `0`
- `AILERON_AGENT` (`aileron proxy`, `aileron hook`): `agent.name` when `--agent` is absent
- `AILERON_FRAMEWORK` (`aileron proxy`, `aileron hook`): `agent.framework` when `--framework` is absent
- `AILERON_SESSION_ID` (`aileron proxy` only): `session_id` when `--session-id` is absent;
  `aileron hook` ignores it and always records the payload's `session_id`

For `AILERON_AGENT`, `AILERON_FRAMEWORK` and `AILERON_SESSION_ID`, precedence is flag, then
environment, then default. An empty or whitespace environment value counts as unset; an empty flag
value is an error.

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
NOT invoked, event status='blocked'. Non-tools/call messages pass through and are not logged.
On shutdown, in-flight tools/call events that never received a response are journaled with
status='error' and meta.error noting the missing response (crash-safe recording).
Every event carries the identity the proxy was started with: `session_id` defaults to a fresh
uuid4 hex per run, `agent.name` to `mcp-proxy` and `agent.framework` to `mcp`. A session id reused
across runs groups them: `detect` treats them as one session and the OTel export puts them in one
trace.
```python
def run_proxy(child_argv: list[str], log: ChainLog, rules: list[Rule]|None = None, *,
              session_id: str|None = None, agent_name: str = "mcp-proxy",
              framework: str = "mcp") -> int   # exit code of child; identity values are not validated here
```

## Claude Code hook (hook.py)
`aileron hook` is a Claude Code `PreToolUse`, `PostToolUse` and `PostToolUseFailure` command hook. It
reads one payload from stdin, journals the call as a `tool_call` event under `exclusive_lock`, runs
the rules, and exits 0 or 2. It never writes to stdout, never exits 1 (a non-blocking error in Claude
Code), and prints one line on stderr exactly when it exits 2. The CLI reads stdin first, then resolves
the journal path (`--log`, then `AILERON_LOG`, both stripped of surrounding whitespace, else refuse)
and the identity values; every failure there, and any exception escaping `run_hook`, is exit 2.

Stdin contract: at most 16 MiB (`MAX_INPUT_BYTES`), strict UTF-8, one JSON object with no `NaN` or
`Infinity`, no number that overflows to infinity, no duplicate keys at any depth, and no container
nesting deeper than 256 levels (`MAX_NESTING`, checked without recursion so the bound is the same on
every Python version). Required fields: `hook_event_name` in the three above, `session_id` (1 to 128
printable characters, no surrounding whitespace), `tool_name` (1 to 256 printable characters), and
the `tool_input` key (any value, `null` included). Anything else is refused with exit 2 and nothing
journaled. Optional payload fields are copied into `meta.hook` only when they have the expected type
and fit their cap (`tool_use_id` 128, `cwd` 1024, `permission_mode` 32, `agent_id` 128, `agent_type`
128, `mcp_server.name` 256, `mcp_server.source` 32; `is_interrupt` must be a bool and is read on
PostToolUseFailure only); otherwise they are left out and named in `meta.hook.dropped`. Every other
payload field, `transcript_path` included, is ignored.

Two events per call, joined by `session_id` and `meta.hook.tool_use_id`. The PreToolUse event is the
enforcement record and is on disk before the hook returns; the post event records the outcome
(`status` `ok` or `error`, `latency_ms` from a finite non-negative `duration_ms` else null,
`result_digest` over `tool_response` on PostToolUse, `meta.error` as `{"digest": ...}` or the raw
value with `--capture-content` on PostToolUseFailure). `decide()` runs on both with full content in
memory: `tool.arguments`, `result` and the raw `error` value; the error's digest replaces it just
before the append, since `ChainLog.append` never touches `meta`. A block on PreToolUse sets
`status='blocked'` and exits 2; a block on a post event keeps `status`, records `policy`, and exits 2
so Claude sees the message; an alert records `policy` and exits 0. A rules path that cannot be
loaded (any exception), that yields no rules, or whose rules raise during `decide()` is journaled
with `policy={"rule_id": "aileron-hook-config", "action": "block"}` and exit 2. A journal that
cannot be written, a lock wait past `LOCK_TIMEOUT_S` included, is exit 2 with nothing recorded.

Identity: `agent.name` is `--agent`, then `AILERON_AGENT`, then `claude-code`; `agent.framework` is
`--framework`, then `AILERON_FRAMEWORK`, then `claude-code`; `session_id` is always the payload's and
`AILERON_SESSION_ID` is ignored. `meta.transport` is `claude-code-hook`.
```python
TRANSPORT = "claude-code-hook"; MAX_INPUT_BYTES = 16 * 1024 * 1024; MAX_NESTING = 256
LOCK_TIMEOUT_S = 10.0; RULE_CONFIG_REJECTED = "aileron-hook-config"; BLOCK_EXIT = 2
class HookInputError(ValueError)                    # the message is the one-line reason
@dataclass(frozen=True) HookOptions: log_path, rules_path, capture_content, agent_name, framework
@dataclass(frozen=True) HookOutcome: exit_code (0 or 2), message (empty iff exit_code == 0), event
def parse_payload(raw: bytes) -> dict                          # raises HookInputError
def build_event(payload: dict, options: HookOptions) -> dict   # in-memory event, content attached
def run_hook(raw: bytes, options: HookOptions) -> HookOutcome  # never prints, never raises for an
                                                               # expected failure
def one_line(value) -> str                                     # whitespace-collapsed message text
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
aileron proxy --log <path> [--rules <dir>] [--capture-content]
              [--agent <name>] [--framework <name>] [--session-id <id>] -- <cmd...>
aileron hook [--log <path>] [--rules <path>] [--capture-content] [--agent <name>] [--framework <name>]
                                       # Claude Code hook: one payload on stdin; exit 2 blocks;
                                       # stdout stays empty; never exits 1
aileron demo                           # scripted fake-agent session (digest-only mode, real Baseline
                                       # alerts) -> demo.chain.jsonl + demo-report.html
```
All commands exit non-zero with clear stderr on failure; `verify` exits 2 on tamper; `hook` exits 0 or
2 only.

## Independent verification

A tamper-evidence tool whose only verifier is written by its author is asking
for faith. This section states the rules precisely enough that a verifier can
be written from it without reading the Python code. One such verifier exists in
`verifiers/go/` (Go, standard library only), and `tests/conformance/` holds the
fixtures that pin it and the Python implementation to the same answers. Where
this text and `src/aileron` disagree, the code is the truth and this text has a
bug; please report it.

### Reading a journal

1. The journal is a byte file. Split it on `0x0A`. A final line without a
   trailing newline is still a line.
2. Decode each line as UTF-8, strictly: overlong forms, encoded surrogates and
   truncated sequences are invalid. An undecodable line is a problem (`line N:
   invalid UTF-8`). It occupies one sequence position, and nothing after it may
   chain: every following event gets `seq S: unverifiable, chain broken at an
   earlier line` in addition to its own checks, until the chain is resumed from
   the stored hash of the next readable event.
3. Strip the decoded line as Python's `str.strip()` strips: remove leading and
   trailing code points from the set U+0009..U+000D, U+001C..U+0020, U+0085,
   U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F, U+205F, U+3000.
   A line that is empty after stripping is skipped and consumes no sequence
   number.
4. Parse the stripped text as one JSON document (RFC 8259) with these
   deviations, which are Python's `json.loads` defaults: the literals `NaN`,
   `Infinity` and `-Infinity` are accepted on input; a float literal whose
   magnitude overflows binary64 reads as an infinity; raw control characters
   (below U+0020) inside strings are rejected; a duplicated key keeps the last
   value; an integer literal with more than 4300 digits is rejected. A line
   that fails to parse is a problem (`line N: invalid JSON`) and breaks the
   chain as in step 2. A document that is not an object is a problem (`line N:
   event is not a JSON object`) and also breaks the chain.
5. Every line that parses as an object counts towards `count`, whether or not
   it passes the checks below.

### Canonical JSON

Canonical JSON is the only byte string that is ever hashed or signed. It is
what `json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=True, allow_nan=False)` produces, which means exactly this:

- **Objects** are `{` members `}` with members joined by `,` and each member
  written as the canonical string of the key, `:`, the canonical value. No
  whitespace anywhere. Members are sorted by key, comparing keys as sequences
  of code points (which is the same order as comparing their UTF-8 bytes,
  surrogates included). An empty object is `{}`.
- **Arrays** are `[` values joined by `,` `]`. An empty array is `[]`.
- **Strings** are written between double quotes. Code points U+0020..U+007E
  other than `"` and `\` are written as themselves. These seven have short
  escapes: `\"` `\\` `\n` `\r` `\t` `\b` `\f`. Every other code point,
  including the remaining C0 controls, DEL (U+007F) and everything above
  U+007E, is written as `\u` followed by four lowercase hex digits. Code
  points above U+FFFF are written as their UTF-16 surrogate pair, two
  `\uXXXX` escapes. A lone surrogate (which a Python `str` can hold and which
  reaches the journal through the `\uD800`-style escape in peer-supplied
  JSON) is written as its own `\uXXXX` escape. The solidus `/` is not
  escaped. `<`, `>` and `&` are not escaped. Output is therefore pure ASCII.
- **Integers**: a number literal with no fraction and no exponent is an
  integer of arbitrary precision. It is written as its decimal digits with a
  leading `-` if negative. The only literal that changes is `-0`, which is the
  integer zero and is written `0`. `1e0` is not an integer.
- **Floats**: a number literal with a fraction or an exponent is a float: the
  IEEE 754 binary64 value nearest to the literal. It is written as Python's
  `repr(float)` writes it. Take the shortest decimal digit string that reads
  back to the same double, and let `exp` be the decimal exponent of its first
  digit (the value is `d.ddd × 10^exp`). If `exp < -4` or `exp >= 16`, write
  exponent notation: the digits with a point after the first only when there
  is more than one, then `e`, a sign, and at least two exponent digits
  (`1e-05`, `1e+16`, `1.5e+300`, `5e-324`). Otherwise write positional
  notation with at least one digit after the point (`0.0001`, `5.0`,
  `1000000000000000.0`, `0.30000000000000004`). Zero is `0.0` or `-0.0`.
  A float in the source stays a float: `5.0` is written `5.0`, never `5`.
  `NaN`, `Infinity` and `-Infinity` have no canonical form; an event
  containing one is a problem (`line N: uncanonicalizable content`) and its
  hash cannot be recomputed, so it also fails the hash check.
- **Literals**: `true`, `false`, `null`.

### What is hashed

- `GENESIS = "0" * 64`. The first event has `seq` 1 and `prev_hash` GENESIS.
- `hash(event) = sha256(canonical(event without the "hash" member))` as 64
  lowercase hex digits. Every other member, including `prev_hash` and `seq`,
  is covered.
- `digest(x) = sha256(canonical(x))` as lowercase hex; used for
  `tool.arguments_digest` and `result_digest`. Verification does not recompute
  digests, since the content they summarise may not be present.

For each event line, in order, a verifier records these problems:

1. `line N: non-canonical encoding` when `canonical(event)` is not
   byte-identical to the stripped line. The stored bytes are authoritative;
   this is what catches a duplicated key or a `1e0` where a `1` was hashed.
2. `seq discontinuity at line N: expected E, got S` when `seq` is not a JSON
   integer equal to the expected value. A JSON integer is a number with no
   fraction and no exponent; `1.0`, `1e0`, `true` and `"1"` are not integers
   and are reported even where Python's `==` would call them equal to 1. `S`
   is rendered as Python's `str()` renders the parsed value (`1.0`, `True`,
   `None`). The expected value starts at 1 and, after each event, becomes
   that event's `seq` plus one when `seq` is an integer, otherwise the
   previous expected value plus one.
3. `prev_hash mismatch at seq S` when `prev_hash` is not equal to the stored
   `hash` of the previous readable event (GENESIS for the first).
4. `hash mismatch at seq S (content tampered)` when `hash` is not equal to the
   recomputed hash, or the hash could not be recomputed.

`first_bad_seq` is the `seq` of the first event with a problem when that `seq`
is a JSON integer (a boolean is not one), otherwise it stays unset until a
later problem has one; for an
unreadable line it is the sequence number that line should have carried. The
chain is `ok` when no problem was recorded. A missing journal is not `ok`,
with `count` 0. An empty journal is `ok` with `count` 0.

### What is signed

A checkpoint is one JSON object line in `<log>.checkpoints.jsonl`:

```
{ts, log_path, index, prev_checkpoint_hash, count, tip_hash, signature, pubkey_path}
```

- `signed_payload = canonical(checkpoint without "signature" and "pubkey_path")`.
- `signature` is the Ed25519 signature (RFC 8032) over `signed_payload`,
  encoded with standard base64. The reference decodes it with Python's
  non-validating `base64.b64decode`, which discards characters outside the
  alphabet and stops at the first complete padding; a verifier must accept at
  least every correctly padded standard encoding.
- `checkpoint_hash = sha256(signed_payload)` as lowercase hex. The first
  checkpoint has `index` 1 and `prev_checkpoint_hash` GENESIS; each later one
  names the `checkpoint_hash` of its predecessor.
- `count` is the number of events covered and `tip_hash` the `hash` of event
  number `count`. `log_path` and `pubkey_path` are recorded for the operator
  and are not checked.
- The key is an Ed25519 public key in PEM SubjectPublicKeyInfo form. A
  verifier may also accept a PEM PKCS#8 private key (using its public half) or
  a directory containing `aileron_ed25519.pub` or `aileron_ed25519.key`, as
  the reference does.

`verify-checkpoint` reports valid exactly when all of the following hold:

1. The checkpoints file exists and holds at least one object line. It is read
   as text, so `\n`, `\r\n` and `\r` all end a line; lines that are blank,
   not JSON or not objects are skipped. (Invalid UTF-8 anywhere in this file
   is an operational error, exit 1, not a verdict.)
2. A checkpoint is *usable* when its `count` is a JSON integer greater than
   zero (not a float, not a bool) and its `signature` decodes and verifies
   over `signed_payload` with the given key. Unusable checkpoints are ignored.
   At least one must be usable.
3. The usable checkpoints, sorted by `index` (anything that is not an integer
   sorts first), have `index` equal to 1, 2, ..., N in turn, and each
   `prev_checkpoint_hash` equals the `checkpoint_hash` of the one before it
   (GENESIS for the first). This is what makes deleting or duplicating a
   checkpoint detectable.
4. The journal verifies as above.
5. For every usable checkpoint, the journal holds at least `count` events and
   event number `count` has `hash` equal to `tip_hash`.

This is prefix semantics: events appended after a checkpoint was signed leave
it valid; truncating below `count` or rewriting anything at or before it does
not. Deleting the newest checkpoint lines is not detectable by any local
check; see SECURITY.md.

### The unauthenticated cross-check in `verify`

When the chain verifies and `<log>.checkpoints.jsonl` exists, `verify` also
compares the journal with every checkpoint in file order, without checking
signatures (no key is needed to run `verify`). For each checkpoint: a `count`
that is not a positive JSON integer, or a `tip_hash` that is not a string, is
reported as unusable rather than skipped; otherwise fewer than `count` events
is reported as truncation, and a mismatched hash at event `count` as a
rewrite. Any report makes the verdict TAMPERED with exit 2. The reference
prints a note that signatures were not checked. `--skip-checkpoint-check`
disables this for a deliberately rotated journal.

### Exit codes and verdict lines

```
verify             0  OK: <count> events verified in <log>
                   2  TAMPERED at seq <first_bad_seq or None> in <log>
                   2  TAMPERED: chain is internally valid but contradicts <log>.checkpoints.jsonl
                   1  error: <operational problem>
verify-checkpoint  0  OK: checkpoint valid for <log>
                   1  FAILED: checkpoint invalid for <log>
                   1  error: <operational problem, including no key found>
hook               0  recorded (and, on PreToolUse, allowed); nothing printed
                   2  blocked by rule, input refused, rules unloadable, or journal unavailable;
                      reason on stderr (never 1)
```

Each problem found is printed first as its own `error: <message>` line on
stderr. The message texts above are normative where they are quoted in full;
the exception text that follows `invalid JSON:`, `invalid UTF-8:` and
`uncanonicalizable content:` comes from the runtime and is informational.

### Conformance suite

`scripts/gen_conformance.py` builds `tests/conformance/` with the real library:
`canonical_cases.json` (source text, expected canonical bytes, and inputs that
must be refused) and one directory per journal case holding the journal, any
checkpoints, the public key and `expected.json` with the Python verdict. The
output is deterministic so the committed fixtures can be checked against the
current library. `tests/test_conformance.py` replays everything through Python
and, when `go` is on PATH, through the Go binary; `verifiers/go` has its own
tests that do the same from the Go side, run by
`.github/workflows/go-verifier.yml`.

Two limits of the reference are deliberately not pinned. CPython's recursion
limit for nested JSON depends on the interpreter version, so the depth at which
a hostile line stops parsing varies; the Go verifier refuses more than 10000
levels. And Python versions word some parse errors differently, which is why
only the verdict, exit code, `first_bad_seq` and the fixed message prefixes are
compared.

## Module ownership (branches)
- core: events.py chainlog.py signing.py + tests (test_events/test_chainlog/test_signing)
- intercept: sdk.py proxy.py hook.py + tests (test_sdk/test_proxy/test_hook); `exclusive_lock` stays
  with core in chainlog.py
- policy: policy.py prefilter.py detect.py src/aileron/rules/examples/* + tests (test_policy/test_prefilter/test_detect/test_rule_pack)
- surface: pyproject.toml cli.py mcpserver.py otel.py report.py + tests (test_cli/test_mcpserver/test_otel/test_report) + __init__.py

All modules import across each other ONLY via the signatures above. No other cross-module
internals. `hook.py` uses `events.new_event`, `events.digest`, `chainlog.ChainLog`,
`chainlog.exclusive_lock`, `policy.load_rules`, `policy.decide` and `policy.Rule` (annotations
only); `cli.py` uses `hook.run_hook`, `hook.HookOptions` and the `hook` constants, and formats its
own hook error lines so they work when that import fails. Every module has
`from __future__ import annotations`. Code style: type hints,
docstrings on public functions. Tests use tmp_path fixtures; no network.
