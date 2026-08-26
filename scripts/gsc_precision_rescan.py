#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Precision перезамер из существующих findings БД (0 LLM, 0 scan, мгновенно).

Сопоставляет project basename из findings с ground-truth:
  - benchmark/projects_100_ordered.json (поле `recall`: true=vuln, false=clean)
  - calibration/calibration_dataset.json (поле `category`)

Считает: clean-проекты с ложным CRITICAL/HIGH, recall по vuln, precision CRIT по находкам,
и топ-правила, дающие CRITICAL на clean-проектах.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

DB = Path.home() / ".hermes" / "state" / "gsc_audit.db"
GSC = Path("/home/openclaw/gsc")
ORDERED = GSC / "benchmark" / "projects_100_ordered.json"
CAL_DS = GSC / "calibration" / "calibration_dataset.json"

bench = json.loads(ORDERED.read_text())
name_to_recall = {p["name"]: bool(p.get("recall")) for p in bench}
cal = json.loads(CAL_DS.read_text())
name_to_cat = {p["name"]: p.get("category") for p in cal["projects"]}

conn = sqlite3.connect(str(DB))
rows = conn.execute(
    "SELECT project, category, rule_id FROM findings "
    "WHERE project LIKE '%real_world_100%' OR project LIKE '%gsc-calibration%'"
).fetchall()
conn.close()

proj_sev: dict[str, Counter] = defaultdict(Counter)
proj_crit_rules: dict[str, Counter] = defaultdict(Counter)  # только CRITICAL
proj_crit_count: dict[str, int] = defaultdict(int)           # total CRITICAL per project
for project, cat, rid in rows:
    base = Path(project).name
    proj_sev[base][cat] += 1
    if cat == "CRITICAL":
        proj_crit_rules[base][rid] += 1
        proj_crit_count[base] += 1


def find(base: str):
    for k in proj_sev:
        if k.lower() == base.lower():
            return proj_sev[k], proj_crit_rules[k], proj_crit_count[k]
    return None, None, 0


def run(group: str, names: dict[str, bool]) -> dict:
    clean_crit = clean_high = clean_total = 0
    vuln_ok = vuln_total = 0
    fp_crit_findings = tp_crit_findings = 0
    unmatched = []
    crit_by_rule: Counter = Counter()
    for name, is_vuln in names.items():
        sev, crit_rules, crit_count = find(name)
        if sev is None:
            unmatched.append(name)
            continue
        crit = sev.get("CRITICAL", 0)
        high = sev.get("HIGH", 0)
        if is_vuln:
            vuln_total += 1
            vuln_ok += 1 if (crit + high) > 0 else 0
            tp_crit_findings += crit_count
        else:
            clean_total += 1
            clean_crit += 1 if crit > 0 else 0
            clean_high += 1 if high > 0 else 0
            fp_crit_findings += crit_count
            crit_by_rule.update(crit_rules)
    precision = tp_crit_findings / max(tp_crit_findings + fp_crit_findings, 1)
    return {
        "group": group, "clean_total": clean_total, "clean_crit": clean_crit,
        "clean_high": clean_high, "vuln_total": vuln_total, "vuln_ok": vuln_ok,
        "fp_crit": fp_crit_findings, "tp_crit": tp_crit_findings,
        "precision_crit": precision, "unmatched": unmatched, "crit_by_rule": crit_by_rule,
    }


for r in (
    run("bench_100", name_to_recall),
    run("calibration", {n: (c == "vulnerable") for n, c in name_to_cat.items()}),
):
    print(f"\n=== {r['group']} ===")
    print(f"  Clean проектов:            {r['clean_total']}")
    print(f"  Clean с ложным CRITICAL:   {r['clean_crit']}/{r['clean_total']} "
          f"({r['clean_crit']/max(r['clean_total'],1):.0%})")
    print(f"  Clean с ложным HIGH:       {r['clean_high']}/{r['clean_total']}")
    print(f"  Recall (vuln с CRIT/HIGH): {r['vuln_ok']}/{r['vuln_total']}")
    print(f"  Precision CRIT (по находкам): {r['precision_crit']:.1%} "
          f"(TP={r['tp_crit']}, FP={r['fp_crit']})")
    if r["unmatched"]:
        print(f"  ! unmatched ({len(r['unmatched'])}): {r['unmatched'][:10]}")
    print("  Топ CRITICAL-правила на clean (FP-шум):")
    for rid, c in r["crit_by_rule"].most_common(10):
        print(f"    {rid:<22} {c}")
