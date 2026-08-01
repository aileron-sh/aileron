"""Single-file HTML incident-replay report for aileron event chains.

Renders a self-contained report: verification badge, filterable timeline
table, inline CSS only, no external assets, vanilla-JS filter.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from . import __version__

_CSS = """
:root {
  --cream: #faf6ef;
  --cream-2: #f3ecdf;
  --charcoal: #33302b;
  --charcoal-2: #5b564e;
  --amber: #b07d2b;
  --amber-soft: #e8d9bd;
  --line: #ddd3c2;
  --bad: #a4553f;
  --good: #6d7f4f;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem;
  background: var(--cream); color: var(--charcoal);
  font-family: Georgia, 'Times New Roman', serif;
  line-height: 1.45;
}
header { border-bottom: 2px solid var(--charcoal); padding-bottom: 1rem; margin-bottom: 1.5rem; }
h1 { font-size: 1.5rem; margin: 0 0 .5rem 0; letter-spacing: .02em; }
.badge {
  display: inline-block; padding: .35rem .8rem; border-radius: 3px;
  font-family: 'Courier New', monospace; font-size: .85rem; font-weight: bold;
  border: 1px solid var(--charcoal);
}
.badge.verified { background: var(--amber-soft); color: var(--charcoal); }
.badge.tampered { background: var(--bad); color: var(--cream); border-color: var(--bad); }
.meta-line { color: var(--charcoal-2); font-size: .85rem; margin-top: .5rem; }
.filter-bar { margin-bottom: 1rem; }
.filter-bar input {
  width: 100%; max-width: 32rem; padding: .5rem .7rem;
  border: 1px solid var(--line); border-radius: 3px;
  background: #fffdf8; color: var(--charcoal); font-size: .9rem;
}
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
thead th {
  text-align: left; padding: .5rem .6rem; background: var(--charcoal);
  color: var(--cream); font-weight: normal; letter-spacing: .04em;
  position: sticky; top: 0;
}
tbody td { padding: .45rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:nth-child(even) { background: var(--cream-2); }
tbody tr:hover { background: var(--amber-soft); }
td.mono { font-family: 'Courier New', monospace; font-size: .8rem; }
.pill {
  display: inline-block; padding: .1rem .5rem; border-radius: 8px;
  font-size: .75rem; border: 1px solid var(--charcoal-2); color: var(--charcoal-2);
}
.pill.ok { border-color: var(--good); color: var(--good); }
.pill.error, .pill.blocked { border-color: var(--bad); color: var(--bad); font-weight: bold; }
.flags { color: var(--amber); font-size: .78rem; }
footer { margin-top: 2rem; color: var(--charcoal-2); font-size: .75rem; }
"""

_JS = """
function filterRows() {
  var q = document.getElementById('filter').value.toLowerCase();
  var rows = document.querySelectorAll('#timeline tbody tr');
  rows.forEach(function (row) {
    row.style.display = row.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
  });
}
"""


def _get(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute (dataclass) or key (dict) from ``obj``."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _badge(verify_result: Any) -> str:
    """Verification badge HTML: VERIFIED n events / TAMPERED at seq N."""
    ok = bool(_get(verify_result, "ok", False))
    count = _get(verify_result, "count", 0)
    if ok:
        return f'<span class="badge verified">VERIFIED {count} events</span>'
    seq = _get(verify_result, "first_bad_seq")
    where = f" at seq {seq}" if seq is not None else ""
    return f'<span class="badge tampered">TAMPERED{where}</span>'


def _row(event: dict) -> str:
    """One timeline row: ts, seq, type, tool, status, rule, hash prefix, flags."""
    esc = html.escape
    ts = esc(str(event.get("ts") or ""))
    seq = esc(str(event.get("seq") if event.get("seq") is not None else ""))
    etype = esc(str(event.get("type") or ""))
    tool = (event.get("tool") or {}).get("name") or ""
    status = str(event.get("status") or "ok")
    policy = event.get("policy") or {}
    rule = policy.get("rule_id") or ""
    digest = str(event.get("hash") or "")
    hash_prefix = digest[:12]
    meta = event.get("meta") or {}
    flags = meta.get("flags") or []
    if isinstance(flags, str):
        flags = [flags]
    flags_html = "<br>".join(esc(str(f)) for f in flags)
    return (
        "<tr>"
        f'<td class="mono">{ts}</td>'
        f'<td class="mono">{seq}</td>'
        f"<td>{etype}</td>"
        f"<td>{esc(str(tool))}</td>"
        f'<td><span class="pill {esc(status)}">{esc(status)}</span></td>'
        f'<td class="mono">{esc(str(rule))}</td>'
        f'<td class="mono">{esc(hash_prefix)}</td>'
        f'<td class="flags">{flags_html}</td>'
        "</tr>"
    )


def render_html(
    events: list[dict],
    verify_result: Any,
    out_path: str,
    title: str = "Aileron Incident Report",
) -> None:
    """Render a self-contained HTML incident report to ``out_path``.

    ``verify_result`` is a chainlog ``VerifyResult`` (or dict with
    ``ok``/``count``/``first_bad_seq``). The report contains a verification
    badge and a filterable timeline table with columns ts, seq, type, tool,
    status, rule, hash prefix, flags.
    """
    esc = html.escape
    errors = _get(verify_result, "errors", []) or []
    errors_html = "".join(f"<li>{esc(str(e))}</li>" for e in errors)
    errors_block = (
        f'<ul class="meta-line">{errors_html}</ul>' if errors_html else ""
    )
    rows = "\n".join(_row(e) for e in events)
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>{esc(title)}</h1>
  {_badge(verify_result)}
  <div class="meta-line">{len(events)} events loaded</div>
  {errors_block}
</header>
<div class="filter-bar">
  <input id="filter" type="text" placeholder="Filter timeline..."
         onkeyup="filterRows()" autofocus>
</div>
<table id="timeline">
<thead><tr>
  <th>ts</th><th>seq</th><th>type</th><th>tool</th>
  <th>status</th><th>rule</th><th>hash</th><th>flags</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
<footer>Generated by aileron {esc(__version__)} &mdash; flight recorder for AI agents.</footer>
<script>{_JS}</script>
</body>
</html>
"""
    Path(out_path).write_text(document, encoding="utf-8")
