# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once 1.0 is reached; 0.x releases may change APIs between minor versions.

## [0.1.0] — 2026-07-23

Initial public release.

### Added

- **Hash-chained audit journal** (`chainlog`, `events`): append-only JSONL
  log of `tool_call` / `llm_call` / `agent_start` / `agent_end` /
  `policy_decision` / `alert` events; SHA-256 hash chain over canonical
  JSON; `verify()` with `first_bad_seq` reporting.
- **Ed25519 checkpoints** (`signing`): `generate_keypair`,
  `sign_checkpoint`, `verify_checkpoint` for offline-verifiable log tips.
  Checkpoints use prefix semantics: events appended after signing never
  invalidate a checkpoint; truncating or rewriting the signed prefix does.
- **Policy engine** (`policy`): Sigma-like YAML rules with
  `allow` / `alert` / `block` actions; dotted-key equality, `_contains`,
  `_regex`, and `severity_gte` matchers; example rules
  (`rules/examples/destructive-shell.yml`, `secrets-exfil.yml`). Rules are
  evaluated against the full call in memory, so content matchers fire even
  in the default digest-only mode — `capture_content` controls what is
  persisted, never what is enforced.
- **Behavioral anomaly detection** (`detect`): rolling baselines flagging
  first-seen tools, rate spikes (>3x baseline), and novel tool-call
  sequences; live via the SDK `baseline=` hook or offline via
  `aileron detect`.
- **SDK instrumentation** (`sdk`): `@track` decorator recording tool calls
  (digest-only by default; `capture_content` opt-in) and enforcing policy
  via `PolicyBlocked`; `track_agent` session context manager.
- **MCP stdio proxy** (`proxy`): JSON-RPC 2.0 interception (newline- and
  Content-Length-framed) with pre-execution policy mediation; blocked calls
  return `-32000` without invoking the child. In-flight calls that never
  receive a response (child crash/exit) are journaled with `status=error`
  on shutdown, so a crash cannot erase the attempt.
- **OTel GenAI export** (`otel`): `gen_ai.*`-aligned span dicts
  (`to_otel_spans`) and OTLP/JSON export (`to_otlp_spans`, `export_json`)
  in the proto3 JSON mapping, suitable for OTLP/HTTP ingestion.
- **HTML incident reports** (`report`): single-file, no-external-asset
  incident timeline with `VERIFIED` / `TAMPERED` verification badge.
- **CLI** (`aileron`): `init`, `verify`, `sign-checkpoint`,
  `verify-checkpoint`, `report`, `export`, `detect`, `rules test`, `proxy`,
  `demo`.
- **Privacy posture**: no telemetry anywhere; tool arguments/results stored
  as digests unless content capture is explicitly enabled.
