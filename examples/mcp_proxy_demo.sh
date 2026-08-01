#!/usr/bin/env bash
# Demo: Aileron MCP stdio proxy intercepting tool calls to a fake MCP server.
#
# What this shows:
#   1. The proxy sits between an MCP client and server, transparent to both.
#   2. Every tools/call becomes a hash-chained tool_call event.
#   3. A policy rule can BLOCK a call before the child server ever sees it.
#   4. The journal verifies offline afterwards.
#
# Run from the repo root:
#   PYTHONPATH=src bash examples/mcp_proxy_demo.sh
#
# Real-world usage is identical except the child command, e.g.:
#   aileron proxy --log run.chain.jsonl --rules rules/examples -- \
#       npx -y @modelcontextprotocol/server-filesystem /tmp

set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
LOG="$WORKDIR/proxy-demo.chain.jsonl"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="$REPO_ROOT/src/aileron/rules/examples"

# Use the installed `aileron` CLI if present; otherwise run from the source
# tree (PYTHONPATH=src). Both paths are identical.
if command -v aileron >/dev/null 2>&1; then
    AILERON=(aileron)
else
    AILERON=(python3 -m aileron.cli)
    export PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
fi

# ---------------------------------------------------------------------------
# 1. A fake MCP server (stdlib Python, newline-delimited JSON-RPC 2.0).
#    It answers initialize/tools/list and echoes tools/call arguments.
#    It exits cleanly on stdin EOF so the proxy can drain responses.
# ---------------------------------------------------------------------------
cat > "$WORKDIR/fake_mcp_server.py" <<'PY'
import json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        out = {"jsonrpc": "2.0", "id": mid,
               "result": {"protocolVersion": "2024-11-05",
                          "serverInfo": {"name": "fake-mcp", "version": "0.0.1"},
                          "capabilities": {"tools": {}}}}
    elif method == "tools/list":
        out = {"jsonrpc": "2.0", "id": mid,
               "result": {"tools": [{"name": "read_file"}, {"name": "shell"}]}}
    elif method == "tools/call":
        params = msg.get("params", {})
        text = f"fake-mcp executed {params.get('name')} with {params.get('arguments')}"
        out = {"jsonrpc": "2.0", "id": mid,
               "result": {"content": [{"type": "text", "text": text}]}}
    else:
        # Notifications (no id) get no response; unknown requests get an error.
        if mid is None:
            continue
        out = {"jsonrpc": "2.0", "id": mid,
               "error": {"code": -32601, "message": f"no such method: {method}"}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
PY

echo "==> 2. Piping MCP traffic through the aileron proxy"
#    Default digest-only mode: content-matching rules
#    (tool.arguments_contains, e.g. destructive-shell.yml's "rm -rf") see the
#    arguments in memory at decision time, while the journal on disk stores
#    only digests. Add --capture-content only if you want raw arguments
#    persisted for forensics.
{
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    # A benign tool call -> logged, forwarded, status=ok.
    printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hostname"}}}'
    # A destructive tool call -> BLOCKED by rule aileron-001: the client gets
    # a JSON-RPC -32000 error and the fake server NEVER receives this request.
    printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"rm -rf / --no-preserve-root"}}}'
} | "${AILERON[@]}" proxy \
        --log "$LOG" --rules "$RULES" -- \
        python3 "$WORKDIR/fake_mcp_server.py" > "$WORKDIR/responses.jsonl"

echo "==> 3. Responses the client received (note id=4 is an error):"
cat "$WORKDIR/responses.jsonl"

echo "==> 4. Verify the tamper-evident journal offline:"
"${AILERON[@]}" verify "$LOG"

echo "==> 5. What was recorded (type / tool / status / rule):"
python3 - "$LOG" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    ev = json.loads(line)
    if ev.get("type") == "tool_call":
        policy = (ev.get("policy") or {}).get("rule_id", "-")
        print(f"  seq={ev['seq']} tool={ev['tool']['name']:<10} "
              f"status={ev['status']:<8} rule={policy}")
PY

echo "==> Done. The blocked shell call exists in the journal as evidence,"
echo "    but never reached the server process."
