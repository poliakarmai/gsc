#!/usr/bin/env python3
"""tests/test_compliance_audit.py — CWE mapping audit (+4, excluding detector count)."""
import sys, os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, '.')

from gsc_compliance import COMPLIANCE_MAP, compliance_for

KNOWN_PREFIXES = {"GS001","GS002","GS003","GS004","GS005","GS007","GS008","GS009",
                  "GS010","GS011","GS012","GS013","GS014","GS015","GS016","GS017",
                  "GS018","GS019","GS020","GS021","GS022","GS023","GS024","GS025",
                  "GS028","GS029","GS030","GS031"}

passed, failed = 0, 0
def run_case(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    for rule_id in COMPLIANCE_MAP:
        prefix = rule_id.split("-")[0]
        assert prefix in KNOWN_PREFIXES, f"Unknown rule_id in COMPLIANCE_MAP: {rule_id}"
run_case('all COMPLIANCE_MAP rules have valid prefix', t1)

def t2():
    gs004 = compliance_for("GS004")
    gs024 = compliance_for("GS024")
    covered = gs004.get("cwe") == "CWE-78" or gs024.get("cwe") == "CWE-78"
    assert covered, "CWE-78 (Command Injection) not covered by any detector"
run_case('CWE-78 covered by GS004 or GS024', t2)

def t3():
    assert compliance_for("GS025-permissive_cors")["cwe"] == "CWE-1188"
    assert compliance_for("GS030-PYSEC-2018-58")["cwe"] == "CWE-1104"
run_case('compliance fallback by prefix for sub-rules', t3)

def t4():
    assert compliance_for("GS999-unknown") == {}
run_case('unknown rule returns empty dict', t4)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
