#!/usr/bin/env python3
"""Precision замер: 13 calibration-проектов (4 vuln + 9 clean) → TP/FP по детекторам.

Clean-проект: ЛЮБАЯ находка = FP (шум). Группируем FP по rule_id.
Vuln-проект: проверяем recall — ловятся ли expected_vulns (по rule_id маппингу).
"""
import json, subprocess, sys
from pathlib import Path
from collections import Counter

GSC = "/home/openclaw/gsc"
CAL = "/tmp/gsc-calibration"

projects = [
    ("flask-jwt-auth", "vulnerable", ["hardcoded_secret"], "flask-jwt-auth"),
    ("dvpwa",         "vulnerable", ["sql_injection"],   "dvpwa"),
    ("vuln-flask",    "vulnerable", ["sql_injection", "xss"], "Vulnerable-Flask-App"),
    ("pygoat",        "vulnerable", ["sql_injection", "xss", "idor", "command_injection"], "pygoat"),
    ("click",         "clean", [], "click"),
    ("rich",          "clean", [], "rich"),
    ("jinja",         "clean", [], "jinja"),
    ("werkzeug",      "clean", [], "werkzeug"),
    ("markupsafe",    "clean", [], "markupsafe"),
    ("itsdangerous",  "clean", [], "itsdangerous"),
    ("httpx",         "clean", [], "httpx"),
    ("starlette",     "clean", [], "starlette"),
    ("uvicorn",       "clean", [], "uvicorn"),
]

RULE_MAP = {
    "hardcoded_secret":  {"GS001", "GS029"},
    "sql_injection":     {"GS005"},
    "xss":               {"GS020"},
    "idor":              {"GS007"},
    "command_injection": {"GS004"},
}

fp_by_rule = Counter()
clean_total = 0
vuln_total = 0
recall = {}
rows = []

for name, cat, exp_vulns, dirname in projects:
    path = Path(CAL) / dirname
    r = subprocess.run([sys.executable, f"{GSC}/gsc.py", "scan", str(path),
                        "--ci", "--json"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"[FAIL] {name}: scan exit {r.returncode}", file=sys.stderr)
        rows.append((name, cat, -1, {}))
        continue
    data = json.loads(r.stdout)
    items = data.get("findings", data) if isinstance(data, dict) else data
    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    rules = [f.get("rule_id", "?") for f in items]
    n = len(items)
    rc = Counter(rules)
    rows.append((name, cat, n, rc))
    if cat == "clean":
        clean_total += n
        fp_by_rule.update(rules)
    else:
        vuln_total += n
        for ev in exp_vulns:
            exp_rules = RULE_MAP.get(ev, set())
            found = any(r in exp_rules for r in rules)
            recall.setdefault(ev, []).append(found)

print("=== По проектам ===")
for name, cat, n, rc in rows:
    top = ", ".join(f"{r}:{c}" for r, c in rc.most_common(5))
    print(f"  {cat:<10} {name:<18} {n:>4}  {top}")

print("\n=== Clean-проекты: FP по детекторам (всё = шум) ===")
print(f"  Итого FP: {clean_total}")
for r, c in fp_by_rule.most_common():
    print(f"  {r:<14} {c:>4}")

print("\n=== Vuln-проекты: recall (expected_vulns) ===")
print(f"  Итого находок: {vuln_total}")
for ev, founds in recall.items():
    ok = sum(founds)
    print(f"  {ev:<20} {ok}/{len(founds)}  {founds}")

# Precision: на clean-проектах precision по определению 0% (все FP)
print(f"\n=== Сводка ===")
print(f"  Clean FP (шум): {clean_total}")
print(f"  Vuln находки:   {vuln_total}")
