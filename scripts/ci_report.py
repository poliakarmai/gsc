#!/usr/bin/env python3
"""GSC CI Report — generates GitHub Actions summary + PR comment from scan output."""
import json
import sys
from pathlib import Path

REPORT_PATH = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gsc_report.json"

try:
    data = json.loads(Path(REPORT_PATH).read_text())
except (FileNotFoundError, json.JSONDecodeError):
    print("⚠️ No scan results found")
    sys.exit(0)

# Counts
total = len(data)
critical = sum(1 for f in data if f.get("category") == "CRITICAL")
high = sum(1 for f in data if f.get("category") == "HIGH")
medium = sum(1 for f in data if f.get("category") == "MEDIUM")
low = sum(1 for f in data if f.get("category") == "LOW")
chains = sum(1 for f in data if f.get("metadata", {}).get("chain_key"))

# Score (inverse: fewer findings = higher score)
score = max(0, 100 - critical * 10 - high * 3 - medium * 1)
grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

# Color for badge
if score >= 85:
    color = "brightgreen"
elif score >= 70:
    color = "green"
elif score >= 50:
    color = "yellow"
elif score >= 30:
    color = "orange"
else:
    color = "red"

# ── GitHub Step Summary ─────────────────────────────────────────────────────

print(f"## 🔍 GSC Security Audit — Score: **{score}/100 ({grade})**")
print()
print(f"| Severity | Count |")
print(f"|----------|-------|")
print(f"| 🔴 CRITICAL | {critical} |")
print(f"| 🟠 HIGH | {high} |")
print(f"| 🟡 MEDIUM | {medium} |")
print(f"| 🔵 LOW | {low} |")
print(f"| **Total** | **{total}** |")
if chains:
    print(f"| 🔗 Attack Chains | {chains} |")
print()

if critical > 0:
    print("### 🚨 Critical Findings")
    for f in data[:10]:
        if f.get("category") != "CRITICAL":
            continue
        title = f.get("title", "?")
        file_path = f.get("file_path", "?")
        line = f.get("line_number", f.get("line", "?"))
        poc = f.get("metadata", {}).get("poc", "")
        print(f"- **{title}** — `{file_path}:{line}`")
        if poc:
            print(f"  > PoC: `{poc}`")
    if critical > 10:
        print(f"\n... and {critical - 10} more critical findings")
    print()

if high > 0:
    print("### ⚠️ High Severity")
    for f in data[:5]:
        if f.get("category") != "HIGH":
            continue
        print(f"- **{f.get('title', '?')}** — `{f.get('file_path', '?')}:{f.get('line_number', '?')}`")
    if high > 5:
        print(f"\n... and {high - 5} more high findings")
    print()

print(f"---")
print(f"![GSC Score](https://img.shields.io/badge/GSC-{score}%2F100-{color}?style=flat&logo=shield)")
print(f"*Git Security Checker v1.4.0 — [poliakarmai/gsc](https://github.com/poliakarmai/gsc)*")

# ── Environment variables for GitHub Actions ────────────────────────────────
import os
gh_output = os.environ.get("GITHUB_OUTPUT")
if gh_output:
    with open(gh_output, "a") as f:
        f.write(f"score={score}\n")
        f.write(f"grade={grade}\n")
        f.write(f"color={color}\n")

# Print JSON for PR comment
print("\n<!-- GSC_JSON_START -->")
print(json.dumps({
    "score": score, "grade": grade, "color": color,
    "total": total, "critical": critical, "high": high,
    "medium": medium, "low": low, "chains": chains
}))
print("<!-- GSC_JSON_END -->")
