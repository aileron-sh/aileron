# Detection-based alerting vs. policy rules

Policy rules (`policy.py`) are **static**: a human writes a Sigma-like YAML
rule (`match` clauses + `action`) and every event is evaluated against it.
Rules are precise and can **block** (deny the tool call outright) or
**alert**, but they only catch what you anticipated — e.g.
`destructive-shell.yml` blocks known-bad shell patterns.

Anomaly detection (`detect.py`, `Baseline`) is **learned**: it builds a
rolling behavioral baseline from observed `tool_call` events and flags
deviations *before* learning from the new event:

- `first_seen_tool:<name>` — the agent used a tool it has never used before.
- `rate_spike:<tool>` — the trailing-60s call rate for a tool exceeds 3x its
  stored baseline average (needs >= 5 prior observations, so sparse tools do
  not produce noise). A slow loop of `web_search` calls suddenly bursting to
  dozens per minute is the classic example: no single call matches a rule,
  but the *behavior* is anomalous.
- `novel_sequence:<a>-><b>` — a tool transition never observed in any session.

Because a learned baseline cannot distinguish "unusual but legitimate" from
"malicious", detection flags are always emitted as **alerts** (`alert`
events), never blocks. Use rules for hard enforcement of known-bad patterns;
use detection to surface novel behavior that no rule anticipated. The two
compose: an event can be allowed by the rule engine and still raise anomaly
alerts for review in the incident report.
