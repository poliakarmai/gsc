#!/usr/bin/env python3
"""OWASP-style scorecard generator — HTML + JSON (v0.31)."""
import json
from typing import Dict
from benchmark.cwe_map import coverage_report, OWASP_CWES
from benchmark.scorer import CweScore, overall_score


def build_scorecard(scores: Dict[str, CweScore], cwe_map: dict) -> dict:
    cov = coverage_report(cwe_map)
    return {
        "tool": "GSC — Git Security Checker",
        "benchmark": "OWASP Benchmark",
        "overall_score": overall_score(scores),
        "coverage": cov,
        "cwe_scores": {cwe: s.to_dict() for cwe, s in sorted(scores.items())},
    }


def scorecard_html(card: dict) -> str:
    rows = []
    for cwe, s in card["cwe_scores"].items():
        desc = OWASP_CWES.get(cwe, "")
        score = s["owasp_score"]
        color = "#4caf50" if score > 0.4 else "#ff9800" if score > 0.0 else "#f44336"
        rows.append(f"""
        <tr>
          <td>{cwe}</td><td>{desc}</td>
          <td>{s['tp']}/{s['tp']+s['fn']}</td>
          <td>{s['fp']}/{s['fp']+s['tn']}</td>
          <td>{s['tpr']:.1%}</td><td>{s['fpr']:.1%}</td>
          <td>{s['precision']:.1%}</td>
          <td style="color:{color};font-weight:bold">{score:+.2f}</td>
        </tr>""")
    uncov = ", ".join(u["cwe"] for u in card["coverage"]["uncovered"])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>GSC OWASP Benchmark Scorecard</title>
<style>
 body{{font-family:sans-serif;margin:2em}}
 table{{border-collapse:collapse;width:100%}}
 td,th{{border:1px solid #ddd;padding:8px;text-align:left}}
 th{{background:#263238;color:#fff}}
 .big{{font-size:2.5em;font-weight:bold}}
</style></head><body>
<h1>🛡️ GSC — OWASP Benchmark Scorecard</h1>
<div class="big">Overall: {card['overall_score']:+.3f}</div>
<p>Coverage: {card['coverage']['coverage_pct']}% OWASP CWEs
   ({len(card['coverage']['covered'])}/{card['coverage']['total_owasp_cwes']})</p>
<table>
<tr><th>CWE</th><th>Category</th><th>TP</th><th>FP</th>
    <th>TPR</th><th>FPR</th><th>Precision</th><th>Score</th></tr>
{''.join(rows)}
</table>
<p><em>Uncovered CWEs (no detector): {uncov or 'none'}</em></p>
</body></html>"""


def save_scorecard(card: dict, out_path: str):
    with open(out_path + ".json", "w") as f:
        json.dump(card, f, indent=2)
    with open(out_path + ".html", "w") as f:
        f.write(scorecard_html(card))
