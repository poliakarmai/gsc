#!/usr/bin/env python3
"""Замер GSC на PoF-корпусе: detect (нашёл?) → PoC-gen → PoF-verify.

Двухфазный:
  --detect-only  — только скан + детект (быстро, без LLM-PoC).
  (без флага)    — + gsc pof generate для TP-находок (медленно, LLM).

Метрики на vuln-приложениях: TP / FN / MISLABELED + PoF-verified.
На clean: FP / TN.

Запуск: python3 measure_pof.py [--detect-only] [--app id]
"""
import json, subprocess, sys, time
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
GSC = Path.home() / "gsc" / "gsc.py"
PY = sys.executable

# rule_id с deterministic PoC (не требует LLM)
DETERMINISTIC_POC_RULES = {"GS020", "GS025"}


def scan(app_dir) -> list:
    r = subprocess.run([PY, str(GSC), "scan", str(app_dir), "--ci", "--json"],
                       capture_output=True, text=True, timeout=300)
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []
    return d if isinstance(d, list) else d.get("findings", [])


def detect(findings, app):
    """TP / FN / MISLABELED для vuln; FP / TN для clean."""
    if app.get("clean"):
        crit = [f for f in findings if f.get("category") in ("CRITICAL", "HIGH")]
        return ("FP" if crit else "TN"), None, None

    exp_rule = app["expected_rule_id"]
    # 1) правило с префиксом expected (GS037-path_traversal_join → GS037) на app.py
    for f in findings:
        rid = f.get("rule_id") or ""
        if rid.startswith(exp_rule) and "app.py" in (f.get("file_path") or ""):
            return "TP", f, rid
    # 2) любая CRITICAL/HIGH на app.py (гибко — SSTI может быть GS020 или GS037)
    for f in findings:
        if f.get("category") in ("CRITICAL", "HIGH") and "app.py" in (f.get("file_path") or ""):
            return "MISLABELED", f, f.get("rule_id")
    return "FN", None, None


def run_pof(finding_key, scan_path, project_root):
    evidence = CORPUS / "evidence.json"
    try:
        r = subprocess.run(
            [PY, str(GSC), "pof", "generate", finding_key, "--report", str(scan_path),
             "--project-root", str(project_root), "--output", str(evidence)],
            capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"verified": False, "error": "timeout"}
    if evidence.exists():
        try:
            return json.loads(evidence.read_text())
        except json.JSONDecodeError:
            pass
    return {"verified": False, "error": r.stdout[-300:]}


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text())
    apps = manifest["apps"]
    detect_only = "--detect-only" in sys.argv
    only = None
    if "--app" in sys.argv:
        only = sys.argv[sys.argv.index("--app") + 1]
        apps = [a for a in apps if a["id"] == only]

    rows = []
    for app in apps:
        vuln_dir = CORPUS / app["vulnerable_dir"]
        scan_path = CORPUS / "scan_tmp.json"
        findings = scan(vuln_dir)
        scan_path.write_text(json.dumps(findings))

        status, finding, actual_rule = detect(findings, app)
        row = {"id": app["id"], "class": app["class"], "detect": status,
               "expected": app.get("expected_rule_id"), "actual": actual_rule}

        if status == "TP" and finding and finding.get("finding_key") and not detect_only:
            key = finding["finding_key"]
            # PoF только если у класса есть deterministic PoC ИЛИ пробуем всё равно
            ev = run_pof(key, scan_path, vuln_dir)
            row["pof_verified"] = bool(ev.get("verified"))
            row["pof_error"] = (ev.get("error") or "")[:120]
        rows.append(row)
        if finding and finding.get("finding_key"):
            print(f"{status:10} {app['id']:22} expected={app.get('expected_rule_id')} "
                  f"actual={actual_rule} poc={'✅' if row.get('pof_verified') else ('—' if detect_only else '❌')}")
        else:
            print(f"{status:10} {app['id']:22} expected={app.get('expected_rule_id')} actual={actual_rule}")

    report(rows, detect_only)


def report(rows, detect_only):
    from collections import defaultdict
    print("\n" + "=" * 60)
    vuln = [r for r in rows if r["class"] != "clean"]
    clean = [r for r in rows if r["class"] == "clean"]

    tp = sum(1 for r in vuln if r["detect"] in ("TP", "MISLABELED"))
    fn = sum(1 for r in vuln if r["detect"] == "FN")
    mis = sum(1 for r in vuln if r["detect"] == "MISLABELED")
    print(f"DETECT: {tp}/{len(vuln)} найдено (TP={tp-mis}, MISLABELED={mis}, FN={fn})")

    if not detect_only:
        pof = sum(1 for r in vuln if r.get("pof_verified"))
        print(f"PoF verified: {pof}/{len(vuln)}")
        for r in vuln:
            if r["detect"] == "TP" and not r.get("pof_verified"):
                print(f"  ⚠️ {r['id']}: PoF не подтверждён — {r.get('pof_error','')}")

    fp = sum(1 for r in clean if r["detect"] == "FP")
    tn = sum(1 for r in clean if r["detect"] == "TN")
    print(f"CLEAN: FP={fp}, TN={tn} (из {len(clean)})")


if __name__ == "__main__":
    main()
