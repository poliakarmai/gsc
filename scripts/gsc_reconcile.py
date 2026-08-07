#!/usr/bin/env python3
"""GSC Reconciliation — validate docs match reality (v0.39→v1.0)."""
from __future__ import annotations
import re, sqlite3, sys
from pathlib import Path

GSC = Path(__file__).parent.parent
DB = Path.home() / ".hermes/state/gsc_audit.db"

def actual_schema():
    try:
        c = sqlite3.connect(str(DB)); v = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]; c.close()
        return v
    except: return None

def actual_calibration():
    d = GSC / "calibration"
    return len([x for x in d.iterdir() if x.is_dir()]) if d.exists() else None

def actual_detectors():
    sys.path.insert(0, str(GSC))
    try:
        from gsc_detectors import DETECTORS
        return len(DETECTORS), len(DETECTORS) + 1
    except: return None, None

def doc_claims(path: Path):
    if not path.exists(): return {}
    t = path.read_text(errors="ignore")
    return {
        "version":   (m := re.search(r"Версия:\s*v([\d.]+)", t)) and m.group(1),
        "detectors": (m := re.search(r"Детекторов:\s*(\d+)", t)) and int(m.group(1)),
        "tests":     (m := re.search(r"Тестов:\s*(\d+)", t)) and int(m.group(1)),
        "schema":    (m := re.search(r"Schema:\s*(\d+)", t)) and int(m.group(1)),
    }

def main():
    plugin, total = actual_detectors()
    schema = actual_schema()
    calib = actual_calibration()
    a = doc_claims(GSC / "AGENTS.md")

    print("=" * 60)
    print("GSC RECONCILIATION")
    print(f"  Real: detectors={plugin} plugin + GS024, schema=v{schema}, calibration={calib}")
    print(f"  AGENTS.md claims: version=v{a.get('version')}, detectors={a.get('detectors')}, schema={a.get('schema')}, tests={a.get('tests')}")

    issues = []
    if a.get("schema") and a["schema"] != schema: issues.append(f"schema: {a['schema']} vs real {schema}")
    if a.get("detectors") and a["detectors"] not in (plugin, total): issues.append(f"detectors: {a['detectors']} vs real {plugin}/{total}")

    if issues:
        print(f"\n  DISCREPANCIES: {len(issues)}")
        for i in issues: print(f"    - {i}")
        return 1
    print("\n  ALL MATCH")
    return 0

if __name__ == "__main__":
    sys.exit(main())
