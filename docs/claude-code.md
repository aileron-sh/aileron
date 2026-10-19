# Claude Code hook

*Record and police every tool call Claude Code makes, with one subcommand and
one settings block.*

---

## What you get

`aileron hook` is a Claude Code command hook. Registered under `PreToolUse`,
`PostToolUse` and `PostToolUseFailure`, it runs on every tool call, before and
after, with Claude Code's hook payload on stdin, and does four things:

- Journals the call as a `tool_call` event in a hash-chained JSONL file, once
  before the tool runs and once after it returns or fails.
- Runs your policy rules against the full call in memory. A matching `block`
  rule stops the call before it runs, and the reason appears in the session.
- Stores digests, not content. `tool_input` and `tool_response` are hashed;
  the raw values are written only with `--capture-content`.
- Fails closed. A journal it cannot write, rules it cannot load or run and
  input it cannot parse all block the call instead of letting it run
  unrecorded.

It needs no SDK, no proxy and no change to how Claude Code is launched, and it
makes no network calls. Claude Code's own tools (`Bash`, `Edit`, `Write`,
`Read`), subagent calls and MCP tools all arrive through the same hook.

## Five minutes

Install Aileron where Claude Code can find it, then seed a project:

```console
$ pip install aileron           # or pipx install aileron
$ cd my-project
$ aileron init
initialized aileron in /home/me/my-project
  keypair: ./aileron_ed25519.key / ./aileron_ed25519.pub
  log:     aileron.chain.jsonl
  rules:   rules (32 example rule(s) seeded)
```

`init` writes a signing keypair, an empty journal and a `rules/` directory
holding the bundled rule pack. `.claude/settings.json` is often committed; the
journal, the lock file next to it and the private key must not be:

```gitignore
aileron.chain.jsonl
aileron.chain.jsonl.lock
aileron_ed25519.key
```

The bundled rule `aileron-001` matches a tool literally named `shell`, and
Claude Code's shell tool is `Bash` (`PowerShell` on Windows), so it never
fires here. Paste this in as `rules/claude-code-shell.yml` so there is
something to see in the first five minutes:

```yaml
id: local-001
title: Block destructive shell commands from Claude Code
severity: high
match:
  type: tool_call
  tool.name_regex: '^(Bash|PowerShell)$'
  tool.arguments_contains:
    - "rm -rf"
    - "rm -fr"
    - "mkfs"
    - "dd if=/dev/zero"
    - "> /dev/sda"
action: block
```

Then register the hook. This goes in the project's `.claude/settings.json`,
or in `~/.claude/settings.json` to cover every project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "aileron",
            "args": ["hook",
                     "--log", "${CLAUDE_PROJECT_DIR}/aileron.chain.jsonl",
                     "--rules", "${CLAUDE_PROJECT_DIR}/rules"],
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "aileron",
            "args": ["hook",
                     "--log", "${CLAUDE_PROJECT_DIR}/aileron.chain.jsonl",
                     "--rules", "${CLAUDE_PROJECT_DIR}/rules"],
            "timeout": 30
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "aileron",
            "args": ["hook",
                     "--log", "${CLAUDE_PROJECT_DIR}/aileron.chain.jsonl",
                     "--rules", "${CLAUDE_PROJECT_DIR}/rules"],
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

About the snippet:

- It is the exec form: `command` plus `args`, no shell. A shell profile that
  echoes cannot write to stdout, and `${CLAUDE_PROJECT_DIR}` needs no quoting.
- `aileron` must be on the PATH Claude Code was started with. If it is not,
  use the output of `which aileron` as `command`, or
  `"command": "python3", "args": ["-m", "aileron.cli", "hook", ...]`.
- No `matcher` means every tool, MCP tools included.
- `"onFailure": "block"` makes a hook that crashes or times out block the
  call. It needs Claude Code 2.1.295 or later; before that a PreToolUse hook
  that fails or times out does not block, so on an older version check that
  the hook actually runs. It is set on `PreToolUse` only, because exit 2 does
  not block on the post events.
- `timeout` is in seconds. 30 covers a cold interpreter plus a wait for the
  journal lock; Claude Code's own default is far longer.
- The hook's working directory is not guaranteed to be the project root, so
  the journal path should be absolute or anchored on `${CLAUDE_PROJECT_DIR}`.
  To keep the journal outside the tree Claude edits, use an absolute path.
  Write it out in full: the exec form expands `${CLAUDE_PROJECT_DIR}` but not
  `~`, so `~/aileron/journal.jsonl` would create a directory literally named
  `~` under whatever the working directory is.
- Drop `--rules` to record without enforcing.

Restart Claude Code, accept the workspace trust dialog, and ask it to run
`rm -rf /tmp/aileron-smoke`. The command does not run. Claude sees one line,
shown here wrapped:

```text
PreToolUse:Bash hook error: [aileron hook ...]: blocked by aileron rule
local-001 (Block destructive shell commands from Claude Code); recorded as
seq 3 in /home/me/my-project/aileron.chain.jsonl
```

Everything up to and including the bracketed command is Claude Code's; what
follows it is the hook's stderr. Then check the record:

```console
$ aileron verify aileron.chain.jsonl
OK: 3 events verified in aileron.chain.jsonl
$ aileron report aileron.chain.jsonl -o report.html
report written to report.html (3 events, VERIFIED)
```

## What a journal entry looks like

This is the blocked call above as stored, expanded here with sorted keys; on
disk it is one compact line. It came from a real run, so your hashes and
timestamps will differ.

```json
{
  "agent": {
    "framework": "claude-code",
    "name": "claude-code",
    "version": null
  },
  "hash": "ae1e48ebc9782159b25eabfebedc0dfff8ce59bfa16d2f3bcf22fdeeb4b9784c",
  "id": "eb56eeff21f84b29862afc5fa6cc50fa",
  "latency_ms": null,
  "meta": {
    "hook": {
      "cwd": "/home/me/my-project",
      "event": "PreToolUse",
      "permission_mode": "default",
      "tool_use_id": "toolu_01DEF456"
    },
    "transport": "claude-code-hook"
  },
  "policy": {
    "action": "block",
    "rule_id": "local-001"
  },
  "prev_hash": "03a18dc7b2d9cf7e383b0bb2b9e6652b289e42f9c58c669e6b1cf4e8f56e40ba",
  "result": null,
  "result_digest": null,
  "seq": 3,
  "session_id": "00893aaf-19fa-41d2-8238-13269b9b3ca0",
  "status": "blocked",
  "tool": {
    "arguments": null,
    "arguments_digest": "d8fe69baaa26bf00c1516d209e4e8a57c274d682bb41ad7217512ca4c197b9bc",
    "name": "Bash"
  },
  "ts": "2026-10-19T19:08:05.384Z",
  "type": "tool_call"
}
```

Field by field:

- `type` and `tool.name`: a `tool_call` by Claude Code's `Bash` tool. The name
  is stored as Claude Code sent it, MCP prefixes included.
- `status: blocked` and `policy`: the verdict. On a `PreToolUse` record
  `status` is the verdict, `ok` for released and `blocked` for stopped;
  `policy` names the rule and its action, or is `null` when nothing matched.
- `tool.arguments: null` and `tool.arguments_digest`: digest-only mode. The
  rule matched `rm -rf` in memory; the command is not on disk. The digest is
  SHA-256 of the canonical JSON of `tool_input`.
- `session_id`: Claude Code's own session id, as the payload gave it.
- `meta.transport: claude-code-hook`: which surface wrote the event, so a rule
  can match on it.
- `meta.hook`: the event name, the join key `tool_use_id`, and, when the
  payload carried them, `cwd`, `permission_mode`, and for subagents and MCP
  tools `agent_id`, `agent_type` and `mcp_server` (`name` and `source`).
- `agent.name` and `agent.framework`: both `claude-code` unless you set them.
- `seq`, `prev_hash` and `hash`: the chain. `aileron verify` recomputes it.

## Pre and post

Every call that runs produces two events: a `PreToolUse` record written before
the tool runs and a `PostToolUse` or `PostToolUseFailure` record written after.
They share `session_id` and `meta.hook.tool_use_id`. The journal is append
only and the pre record has to be on disk before the tool runs, so the outcome
can only be a second line.

The pre record is the enforcement record; its `status` is the verdict. The
post record is the outcome: `status: ok` on `PostToolUse`, `status: error` on
`PostToolUseFailure`, with `latency_ms` taken from Claude Code's `duration_ms`
when it is a finite, non-negative number (otherwise `null`) and, on
`PostToolUse`, `result_digest` over `tool_response`.

Both records carry `tool.arguments_digest`. Equal digests mean the input did
not change between the gate and the run. Unequal digests mean something
rewrote it after Aileron saw it, such as another PreToolUse hook's
`updatedInput`. The rules run again on the post record, against the input
that actually ran, and a block rule that matches there makes the hook exit 2
so the message reaches Claude, with `status` kept as what happened. A post
record never blocks anything; the tool has already run.

A `PostToolUseFailure` record carries the error as a digest in `meta.error`
(the raw value with `--capture-content`) and `is_interrupt` in `meta.hook`
when the payload had it. A missing `error` is recorded as the digest of
`null`, a missing `tool_response` leaves `result_digest` null, and both are
named in `meta.hook.dropped`.

A pre record with no post record can mean any of: the call was blocked; the
user or a deny rule refused it at the permission step (Claude Code fires
`PreToolUse` but no post event then); the running tool was cancelled; the
Claude Code version does not emit `PostToolUseFailure`; or the post hook
could not write. The journal cannot tell these apart.

## Blocking, exactly

The hook blocks by exiting 2 with the reason on stderr. It never writes to
stdout and never prints a JSON decision. Claude Code honours exit 2 on
`PreToolUse` whatever stdout holds, and it stops the call before its own
permission rules are evaluated, so the block applies even when an allow rule
would have let the call through, in every permission mode (the payload's
`permission_mode` says which, `bypassPermissions` included).

The hook never emits `permissionDecision: "allow"`. Exit 0 with empty stdout
is "no opinion": Claude Code's own prompt, allow rules and deny rules apply as
if the hook were not there. The hook only narrows.

Exit 1 is a non-blocking error in Claude Code, so the call would proceed. The
hook never exits 1. Every failure of its own, a bad flag included, is exit 2.

On `PostToolUse` and `PostToolUseFailure`, exit 2 shows the stderr line to
Claude; the tool has already run. The hook uses that to say so when a block
rule matches the executed call or the rules could not be loaded.

Claude never sees stderr from a hook that exits 0, so an alert is silent in
the session. It is in the journal as `policy.action: alert`.

## When it refuses to continue

Once the flags parse, every exit 2 prints exactly one line on stderr, and
nothing is printed on exit 0. (A flag argparse rejects prints its usage text
and also exits 2.) The lines:

- `blocked by aileron rule <id> (<title>); recorded as seq <n> in <log>`. A
  block rule matched on `PreToolUse`. The event is on disk before Claude Code
  hears about it, which is why the line can cite its `seq`.
- `aileron: <tool> already ran but matches block rule <id> (<title>); the
  PreToolUse hook did not stop it; recorded as seq <n> in <log>`. A block rule
  matched the input that ran. Look at the pre record's digest.
- `aileron: journal <log> could not be written (<error>); refusing to let
  <tool> run unrecorded`. Lock, open, replay or append failed on `PreToolUse`.
  Nothing was recorded and the call is blocked. On a post event the same line
  ends `<tool> already ran and is not recorded, fix the journal before
  continuing`. A lock wait past 10 seconds reads `(TimeoutError: lock
  <log>.lock held by another writer for 10.0s)`. There is no bypass flag or
  variable in Aileron; the hook records every call Claude Code sends it.
  Claude Code decides what it sends: removing the hook from settings,
  `disableAllHooks`, or a `--bare` session all run unrecorded, and the
  bundled rule `aileron-181` alerts only on the first of these (edits to
  `.claude/settings.json`).
- `aileron: rules <path> could not be loaded (<error>); refusing to let <tool>
  run unpoliced; recorded as seq <n> in <log>`. A missing path, an unreadable
  file, invalid YAML, a path that holds no rules (`no rules found`), or a
  rule that raises while it is evaluated (`rule evaluation failed: ...`).
  The call is still journaled, with
  `policy: {"rule_id": "aileron-hook-config", "action": "block"}` and, on
  `PreToolUse`, `status: blocked`. On a post event the line says `<tool>
  already ran unpoliced` and `status` is what happened.
- `aileron: hook input rejected (<reason>); refusing to continue`. stdin was
  not a payload the hook accepts (below). Nothing is recorded.
- `aileron: no journal path: pass --log or set AILERON_LOG; refusing to
  continue`, or `aileron: --agent: must be 1 to 128 printable characters ...`
  (likewise `--framework`, `AILERON_AGENT` and `AILERON_FRAMEWORK`).
  Configuration; nothing is recorded, and you see it on the first call.
- `aileron: hook failed (<type>: <error>); refusing to continue`. An exception
  the hook did not expect. Nothing is recorded.

Input the hook refuses, on every event, with nothing journaled: empty stdin;
more than 16 MiB (`input larger than 16777216 bytes`, decided before any
parsing); not UTF-8; not JSON; `NaN` or `Infinity`, or a number such as
`1e999` that overflows to infinity; a duplicate key at any depth; containers
nested more than 256 deep; a top level that is not an object;
`hook_event_name` missing or not one of the three; a `session_id` that is not
1 to 128 printable characters with no surrounding whitespace; a `tool_name`
that is not 1 to 256 printable characters; a missing `tool_input` key
(`null` is a value and is accepted). Claude Code's own serializer produces
none of these, so a refusal means corruption or forgery, and the hook does
not guess which `command` ran.

## Rules

`--rules` takes a file or a directory and is read on every call; without it
calls are recorded and never blocked. It must yield at least one rule: a
directory with no `.yml` or `.yaml` file directly in it (subdirectories are
not read) is refused like a broken one, since asking for enforcement and
getting none should not be silent. `aileron init` seeds `./rules`. Rules see
the full call: in memory `tool.arguments` is the whole `tool_input`, on
`PostToolUse` `result` is the whole `tool_response`, and on
`PostToolUseFailure` `meta.error` is the raw error. `--capture-content`
changes what is stored, not what is enforced.

Claude Code's tool names differ from the ones the bundled pack was written
against. `aileron-001` matches `tool.name: shell` exactly, which is why the
paste-in rule exists. Two bundled rules already work here: `aileron-160`
matches `Bash` through `tool.name_regex` and blocks a shell command that
deletes or rewrites the journal, its checkpoints or the signing key;
`aileron-181` has no tool-name clause and alerts when any tool touches
`.claude/settings.json`, `.claude/hooks`, an MCP config file or an
`.aileron/` path.

Fields worth matching on, all with the ordinary dotted-key matchers:

```yaml
id: local-003
title: Explore subagents may not run shell commands
severity: high
match:
  type: tool_call
  tool.name: Bash
  meta.hook.agent_type: Explore
action: block
```

- `meta.transport: claude-code-hook` picks out hook events.
- `tool.name_regex: '^mcp__github__'` picks out one MCP server's tools, and
  `meta.hook.mcp_server.source: project` picks out servers a repository
  configured.
- `meta.hook.permission_mode: bypassPermissions` picks out calls made while
  nothing else was asking.

A `block` verdict on `PreToolUse` is a blocked call. An `alert` is recorded
and the call proceeds. Rules are pattern matching: a call that matches
nothing is allowed and journaled, and that record is the floor.

## Identity

`session_id` is Claude Code's, always taken from the payload, so events join
to Claude Code's own transcript for that session. There is no `--session-id`
flag and the hook ignores `AILERON_SESSION_ID`: a variable exported for a
proxy must not merge every Claude Code session into one.

`agent.name` and `agent.framework` are yours: `--agent` and `--framework`, or
`AILERON_AGENT` and `AILERON_FRAMEWORK`, both defaulting to `claude-code`.
The rule is the proxy's: 1 to 128 printable characters with no surrounding
whitespace, a flag wins over the environment, and an empty variable counts as
unset. Subagents keep the same `agent.name`; what Claude Code calls the
subagent lands in `meta.hook.agent_type` and `meta.hook.agent_id`, where
rules can see it. `agent.version` is `null`.

## Many hooks at once

Claude Code runs matching hooks in parallel, and `PostToolUse` fires
concurrently when Claude makes parallel tool calls, so several hook processes
can reach one journal at the same moment. Each one reads the chain tip and
appends under an exclusive advisory lock on `<journal>.lock`. Without the lock
two writers could read the same tip and write two events with the same
`prev_hash`, and `verify` would report an honest journal as tampered. The
lock is `flock` on POSIX and `msvcrt.locking` on Windows, retried every 10 ms
for up to 10 seconds; a longer wait is a journal failure, exit 2, and on
`PreToolUse` a blocked call.
The operating system releases the lock when the process exits, so a killed
hook leaves no stale lock, and the lock file is never deleted.

One journal, one kind of writer. The proxy and the SDK hold no lock, so do
not point them at the hook's journal.

Cost per call: interpreter start, rule load, one pass of the rules, and a
replay of the journal to find the tip, which grows with the journal. Measured
once on an idle macOS laptop with Python 3.15, against a journal of 10,000
digest-only events (5.2 MiB): `run_hook` in process took about 30 ms with no
rules and about 47 ms with the 32 bundled rules, and a whole hook process,
interpreter start included, about 120 ms and 190 ms. Nothing is optimised
here yet; see the last section.

## Privacy

On disk by default: tool name, the two digests, session and tool-use ids,
`cwd`, permission mode, subagent id and type, MCP server name and source, the
error digest, timestamps and latency. Not on disk: `tool_input` (for `Write`
that is a whole file), `tool_response` (for `Read`, likewise) and the error
text. `--capture-content` stores those three as sent.

`cwd` is recorded, capped at 1024 characters, because a `Bash` command is
unreadable without it. `transcript_path`, `prompt_id` and every other payload
field are ignored; the first two point into your home directory and none of
them says what the agent touched. An optional `meta.hook` field of the wrong
type or over its cap is left out and named in `meta.hook.dropped` rather than
refused, since none of them is an enforcement input. `meta` is never stripped
in digest-only mode, which is why nothing uncapped may enter it.

No network, no telemetry.

## Honest limits

- **The hook is as strong as Claude Code's hook contract.** It blocks by exit
  2, which Claude Code honours before its permission rules. But Claude Code
  decides what a crashed or timed-out hook means: without
  `"onFailure": "block"` (Claude Code 2.1.295 or later) the call goes ahead. A
  rule regex that never returns cannot be interrupted from inside the hook;
  the timeout is Claude Code's.
- **Files pulled in with `@` fire no tool hook.** Claude Code inserts them
  while building the prompt, so no `PreToolUse` runs, not even one matching
  `Read`. With `CLAUDE_CODE_DISABLE_FILE_MENTIONS=1` (2.1.299 or later) Claude
  Code hands over the paths with a note to read them with its tools, and a
  read made that way goes through the hook.
- **A mod can override the hook.** A mod handling `tool.check` answers after
  the rules and the `PreToolUse` hooks, and can approve a call the hook
  blocked unless the hook is in managed settings.
- **Hooks wait for workspace trust.** In an interactive session no settings
  file hook runs until the trust dialog is accepted. A `-p` or SDK session
  treats the folder as trusted and runs committed hooks, which also means a
  repository's committed hooks run in a folder you never trusted.
- **Another hook can rewrite the input after the gate.** A sibling
  `PreToolUse` hook's `updatedInput` replaces what runs. The post record
  carries the digest of what ran and the rules run again on it, so the case
  leaves evidence; it is not prevented.
- **The hook runs as the agent's OS user.** Deleting the journal, truncating
  it or removing the hook from settings is detectable (the chain, signed
  checkpoints, rules `aileron-160` and `aileron-181`), not preventable.
- **Windows is untested.** The lock's Windows branch is written as specified
  but CI has no Windows runner, and neither Windows paths in the snippet nor
  the `PowerShell` tool name in the paste-in rule have been tried against a
  real session. On a platform where neither lock module imports, the hook
  refuses rather than appending unlocked.
- **Replay grows with the journal.** Every call reads the whole journal to
  find the tip. Start a fresh journal now and then (sign a checkpoint, then
  move the old journal and its `.checkpoints.jsonl` aside together), or wait
  for the tail-seek below.

## Not in this release

Each of these is small and separate, and none is here yet:

- Pairing pre and post events in `aileron report`; rows are per event.
- A `Stop` hook that scans the working tree at the end of a turn.
- Reading `transcript_path`.
- Packaging the hook as a Claude Code plugin.
- Widening the bundled `aileron-001` to Claude Code's tool names; the paste-in
  rule covers it.
- A tail-seek in `ChainLog` so a hook call stops reading the whole journal.

## Uninstall

Remove the three entries from `settings.json`. The journal stays where it is
and still verifies. If you want the tip pinned before you stop writing, sign
a checkpoint first: `aileron sign-checkpoint aileron.chain.jsonl`.

---

*Sources: `src/aileron/hook.py` and `src/aileron/cli.py` for the hook,
`src/aileron/chainlog.py` for `exclusive_lock`, `tests/test_hook.py` for the
contract, and the Claude Code hooks and permissions references as read on
2026-10-19. Claude Code behaviour is quoted from those pages; Aileron
behaviour is what the code does.*
