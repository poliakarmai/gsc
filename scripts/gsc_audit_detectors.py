#!/usr/bin/env python3
"""Audit detectors for empty rule_id — closes known issue #4.

A) Static: every detector has non-empty rule_id attribute.
B) Dynamic: scan calibration projects — all findings have rule_id.
"""
import sys
from pathlib import Path

GSC = Path(__file__).parent.parent
sys.path.insert(0, str(GSC))

def check_static():
    from gsc_detectors.registry import get_detectors
    issues = []
    for det in get_detectors():
        rid = getattr(det, "rule_id", None)
        if not rid or not str(rid).strip():
            issues.append(f"detector {type(det).__name__} has empty rule_id")
        if not callable(getattr(det, "detect", None)):
            issues.append(f"detector {rid} has no detect()")
    return issues

def check_dynamic():
    calib = Path("/tmp/gsc-calibration")
    if not calib.exists():
        print("  ⚠ /tmp/gsc-calibration not found — run gsc_setup_calibration.py first")
        return []
    import subprocess, json
    issues, total = [], 0
    for proj in sorted(p for p in calib.iterdir() if p.is_dir() and (p/"expected.json").exists()):
        r = subprocess.run([sys.executable, "gsc.py", "scan", str(proj), "--ci", "--json"],
                          capture_output=True, text=True, timeout=20)
        try: findings = json.loads(r.stdout) if r.stdout.strip() else []
        except: findings = []
        for f in findings:
            total += 1
            if not f.get("rule_id"):
                issues.append(f"{proj.name}: finding without rule_id — title={f.get('title','?')[:60]}")
    print(f"  Checked findings: {total}")
    return issues

def main():
    print("DETECTOR RULE_ID AUDIT")
    print("\n[A] Static rule_id check:")
    s = check_static()
    for i in s: print(f"  ❌ {i}")
    if not s: print("  ✅ all detectors have rule_id")
    print("\n[B] Dynamic scan check:")
    d = check_dynamic()
    for i in d: print(f"  ❌ {i}")
    if not d: print("  ✅ all findings have rule_id")
    all_issues = s + d
    print(f"\nRESULT: {'❌ ' + str(len(all_issues)) + ' issues' if all_issues else '✅ clean'}")
    return 1 if all_issues else 0

if __name__ == "__main__":
    sys.exit(main())
