"""Self-contained HTML report generator (Phase 13 — executive reporting).

Renders a scan result (``ScanResult.to_dict()``) into a single HTML file with inline CSS:
summary cards, a deterministic "bottom line", a color-coded findings table, and collapsible
sections by severity. No external assets, no JS frameworks — opens offline.

"Needs human decision" is derived deterministically: a committed secret (rule_id GS001/GS029,
or metadata ``committed``/``needs_decision``) must be ROTATED, because removing it from HEAD
does not purge git history. "Auto-fixed" comes from the optional ``fixed_findings`` (Proof-of-Fix).
"""
from __future__ import annotations

import html
import re
from collections import Counter
from datetime import datetime, timezone

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#2563eb",
    "LOW": "#60a5fa", "INFO": "#6b7280",
}
# Secret rules whose fix requires rotation (code removal is not enough — the value lives
# in git history). Anchored regex: matches exactly GS001/GS029 or a dash-suffixed sub-rule,
# so a hypothetical GS0010/GS029x is NOT matched.
_SECRET_RULE_RE = re.compile(r"^(GS001|GS029)(?:-|$)")


def _sev(f: dict) -> str:
    return str(f.get("severity") or f.get("category") or "INFO").upper()


def is_needs_decision(f: dict) -> bool:
    """Deterministic: a committed secret needs rotation (code removal is not enough)."""
    rid = str(f.get("rule_id", ""))
    md = f.get("metadata") or {}
    return bool(_SECRET_RULE_RE.match(rid)) or bool(md.get("committed") or md.get("needs_decision"))


def render_html(scan, fixed_findings=None, title: str = "GSC Security Review") -> str:
    """Render ``scan`` (dict with ``findings``, or a plain findings list) to HTML."""
    findings = scan.get("findings") if isinstance(scan, dict) else scan
    findings = findings or []
    fixed = fixed_findings or []
    fixed_keys = {f.get("finding_key") for f in fixed if isinstance(f, dict)}

    by_sev = Counter(_sev(f) for f in findings)
    total = len(findings)
    needs = [f for f in findings if is_needs_decision(f)]

    findings_sorted = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(_sev(f), 9), f.get("file_path", ""), f.get("line_number", 0)),
    )

    repo = scan.get("repo", "unknown") if isinstance(scan, dict) else "unknown"
    commit = scan.get("commit", "") if isinstance(scan, dict) else ""
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if by_sev.get(sev):
            cards.append(
                f'<div class="card" style="background:{_SEVERITY_COLOR[sev]}">'
                f'{by_sev[sev]}<span>{sev}</span></div>'
            )
    cards.append(f'<div class="card" style="background:#111827">{total}<span>TOTAL</span></div>')
    if fixed_keys:
        cards.append(f'<div class="card" style="background:#16a34a">{len(fixed_keys)}<span>FIXED</span></div>')
    if needs:
        cards.append(f'<div class="card" style="background:#7c3aed">{len(needs)}<span>NEEDS DECISION</span></div>')

    # Bottom line — deterministic executive summary (no LLM).
    crit = [f for f in findings if _sev(f) == "CRITICAL"]
    if crit:
        top = crit[0].get("title", "")
        bottom = (f"Bottom line: {total} findings — {by_sev.get('CRITICAL', 0)} critical, "
                  f"{by_sev.get('HIGH', 0)} high, {by_sev.get('MEDIUM', 0)} medium. "
                  f"Top critical: {html.escape(str(top))}. ")
    else:
        bottom = (f"Bottom line: {total} findings — no critical. "
                  f"{by_sev.get('HIGH', 0)} high, {by_sev.get('MEDIUM', 0)} medium. ")
    if needs:
        bottom += (f"{len(needs)} finding(s) need a human decision: committed secrets must be "
                   f"rotated, not just removed — they live in git history. ")
    bottom += "Nothing was applied."

    rows = []
    for f in findings_sorted:
        sev = _sev(f)
        loc = f"{f.get('file_path', '')}:{f.get('line_number', '')}"
        if f.get("finding_key") in fixed_keys:
            status = '<span class="tag fixed">FIXED</span>'
        elif is_needs_decision(f):
            status = '<span class="tag decision">ROTATE</span>'
        else:
            status = ""
        rows.append(
            f'<tr><td class="mono">{html.escape(str(f.get("finding_key", "")))}</td>'
            f'<td><span class="sev" style="background:{_SEVERITY_COLOR.get(sev, "#6b7280")}">{sev}</span></td>'
            f'<td>{html.escape(str(f.get("title", "")))}</td>'
            f'<td class="mono">{html.escape(loc)}</td>'
            f'<td class="mono">{html.escape(str(f.get("rule_id", "")))}</td>'
            f'<td>{status}</td></tr>'
        )

    collapsible = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        grp = [f for f in findings_sorted if _sev(f) == sev]
        if not grp:
            continue
        items = "".join(
            f'<li><code>{html.escape(str(f.get("file_path", "")))}:{html.escape(str(f.get("line_number", "")))}</code>'
            f' — {html.escape(str(f.get("title", "")))}</li>'
            for f in grp
        )
        collapsible += (
            f'<details><summary><span class="sev" style="background:{_SEVERITY_COLOR[sev]}">{sev}</span> '
            f'{len(grp)} finding(s)</summary><ul>{items}</ul></details>'
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f3f4f6;color:#111827}}
.wrap{{max-width:1000px;margin:0 auto;padding:24px}}
h1{{font-size:22px;margin:0 0 4px}}
h2{{font-size:16px;margin:20px 0 8px}}
.meta{{color:#6b7280;font-size:13px;margin-bottom:20px}}
.cards{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px}}
.card{{color:#fff;padding:14px 20px;border-radius:8px;min-width:90px;font-size:24px;font-weight:600}}
.card span{{display:block;font-size:12px;opacity:.85;text-transform:uppercase;font-weight:400}}
.bottomline{{background:#dcfce7;border:1px solid #86efac;padding:14px 16px;border-radius:8px;margin-bottom:20px;font-size:14px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th,td{{text-align:left;padding:8px 12px;font-size:13px;border-bottom:1px solid #e5e7eb}}
th{{background:#f9fafb;font-weight:600}}
.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.tag{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}}
.fixed{{background:#16a34a}}
.decision{{background:#7c3aed}}
.mono{{font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px}}
details{{background:#fff;border-radius:8px;margin-bottom:8px;padding:10px 14px}}
summary{{cursor:pointer;font-weight:600}}
ul{{margin:8px 0 0 20px}}
li{{font-size:13px;margin:3px 0}}
</style></head>
<body><div class="wrap">
<h1>{html.escape(title)}</h1>
<div class="meta">{html.escape(str(repo))} {html.escape(str(commit))} · {date} · read-only review, nothing applied</div>
<div class="cards">{''.join(cards)}</div>
<div class="bottomline">{bottom}</div>
<h2>Findings by severity</h2>
{collapsible}
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th><th>Area</th><th>Status</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</div></body></html>"""
