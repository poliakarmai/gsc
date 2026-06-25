#!/usr/bin/env python3
"""CI report formatter — reads GSC JSON and outputs GitHub Step Summary markdown."""
import json, sys

findings = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else json.loads(sys.stdin.read())

critical = [f for f in findings if f.get("category") == "CRITICAL"]
high = [f for f in findings if f.get("category") == "HIGH"]
medium = [f for f in findings if f.get("category") == "MEDIUM"]
low = [f for f in findings if f.get("category") == "LOW"]

emoji = "🔴" if critical else "🟡" if high else "🟢"
print(f"## {emoji} GSC Audit — {len(findings)} findings")
print(f"| Severity | Count |")
print(f"|----------|-------|")
print(f"| 🔴 CRITICAL | {len(critical)} |")
print(f"| 🟠 HIGH | {len(high)} |")
print(f"| 🟡 MEDIUM | {len(medium)} |")
print(f"| 🟢 LOW | {len(low)} |")

if critical:
    print(f"\n### 🔴 Critical Findings")
    for f in critical[:5]:
        print(f"- **{f['title']}** — `{f.get('file_path','?')}:{f.get('line_number','?')}`")

if high:
    print(f"\n### 🟠 High Findings")
    for f in high[:5]:
        print(f"- **{f['title']}** — `{f.get('file_path','?')}:{f.get('line_number','?')}`")

if len(findings) > 10:
    print(f"\n*... and {len(findings)-10} more findings*")

print(f"\n---\n*GSC — [self-learning audit](https://github.com/poliakarmai/gsc)*")
