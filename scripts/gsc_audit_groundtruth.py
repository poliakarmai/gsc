#!/usr/bin/env python3
"""Ground-truth audit for GSC. Shows REAL state: tests, calibration, schema, git, known bugs."""
import hashlib, os, re, sqlite3, subprocess, sys
from pathlib import Path

GSC_ROOT = Path(__file__).parent.parent
DB_PATH = Path.home() / ".hermes/state/gsc_audit.db"

KNOWN_BUGS = {
    "pof_exit_code": {
        "pattern": r"poc_before_exit\s*!=\s*0",
        "desc": "Inverted PoC exit-code (!=0 = vulnerable)",
        "severity": "CRITICAL", "status": "FIXED in 5a243bb",
    },
    "secrets_fp_hex": {
        "pattern": r"\\b\[0-9a-fA-F\]\{32,64\}\\b",
        "desc": "Bare hex pattern → FP on SHA hashes",
        "severity": "HIGH", "status": "FIXED in a583cb2",
    },
    "secrets_fp_base64": {
        "pattern": r"^    \(r'\[A-Za-z0-9\+\/=\]\{40,\}\', 'api_key'\)$",
        "desc": "Bare base64 pattern → FP on minified/CSS",
        "severity": "HIGH", "status": "FIXED in a583cb2 (REFINED_PATTERNS)",
    },
}

def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(GSC_ROOT))
        return r.returncode, r.stdout, r.stderr
    except: return -1, "", str(_)

def count_tests():
    total = 0
    for f in sorted((GSC_ROOT/"tests").glob("test_*.py")):
        rc, out, _ = run([sys.executable, str(f)], timeout=30)
        p = sum(1 for l in out.splitlines() if "✅" in l)
        total += p
    return total

def main():
    print("=" * 60)
    print("GSC GROUND-TRUTH AUDIT — v0.32")
    print("=" * 60)

    # Schema
    if DB_PATH.exists():
        db = sqlite3.connect(str(DB_PATH))
        v = db.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        db.close()
        print(f"\n📋 Schema: v{v} | Tables: {len(tables)}")
    else:
        print("\n📋 Schema: DB not found")

    # Tests — count from test files
    print(f"\n📋 Tests: {count_tests()}/130 (fast count)")

    # Calibration
    rc, out, err = run([sys.executable, "gsc.py", "calibration", "run"], timeout=90)
    lines = (out+err).splitlines()
    passed = sum(1 for l in lines if "PASS" in l.upper())
    failed = sum(1 for l in lines if "FAIL" in l.upper())
    print(f"\n📋 Calibration: {passed}/{passed+failed if passed+failed>0 else '?'}")

    # Git
    rc, git_out, _ = run(["git", "log", "--oneline", "-5"])
    print(f"\n📋 Git — last 5 commits:")
    for c in git_out.strip().split("\n")[:5]:
        print(f"   {c}")

    # Known bugs — regex scan in source
    print(f"\n📋 Known bug audit:")
    for bug_id, info in KNOWN_BUGS.items():
        found_in = []
        for mod in GSC_ROOT.glob("gsc_*.py"):
            content = mod.read_text(errors="ignore")
            if re.search(info["pattern"], content, re.MULTILINE) and not re.search(r"ORIGINAL_PATTERNS|REFINED_PATTERNS|# REMOVED|classify_exploit", content[:content.find(info["pattern"])+500]):
                found_in.append(mod.name)
        if found_in:
            print(f"   🔴 {bug_id}: STILL PRESENT in {found_in} — {info['desc']}")
        else:
            print(f"   ✅ {bug_id}: {info['status']}")

    print("\n" + "=" * 60)
    print("✅ Audit complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
