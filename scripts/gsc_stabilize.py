#!/usr/bin/env python3
"""GSC Stabilization orchestrator (v0.36)."""
from __future__ import annotations
import json, sqlite3, subprocess, sys, time
from pathlib import Path

GSC = Path(__file__).parent.parent
REPORT = []
def sec(name): print(f"\n{'='*60}\n{name}\n{'='*60}"); REPORT.append({"s":name,"c":[]})
def chk(name, ok, d=""): st="✅" if ok else "❌"; print(f"  {st} {name}"+(" — "+d if d else "")); REPORT[-1]["c"].append({"n":name,"ok":ok,"d":d}); return ok

def run(cmd, t=300):
    try: r=subprocess.run(cmd,capture_output=True,text=True,timeout=t,cwd=str(GSC)); return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired: return -1,"","TIMEOUT"
    except Exception as e: return -1,"",str(e)

# Axis 2: Regression
sec("REGRESSION")
rc,o,e = run([sys.executable,"tests/test_regression.py"])
chk("Regression tests", rc==0, (o+e)[-80:])

# Axis 3: Consistency
sec("CONSISTENCY")
db = Path.home()/".hermes/state/gsc_audit.db"
if db.exists():
    c = sqlite3.connect(str(db))
    ver = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    chk("Schema v28", ver==28, f"actual={ver}")
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    exp = {"findings","sca_cache","epss_cache","federated_global_weights","secret_fingerprints","nuclei_templates"}
    chk("Key tables present", not (exp-tables), f"missing={exp-tables}")
    c.close()

# Axis 4: Performance
sec("PERFORMANCE")
t0 = time.time()
rc,o,e = run([sys.executable,"-m","gsc","external-scan",str(GSC),"--profile","pr-gate"], t=600)
t = time.time()-t0
chk(f"Scan own repo < 180s", t<180, f"{t:.1f}s")

total = sum(len(s["c"]) for s in REPORT)
passed = sum(1 for s in REPORT for c in s["c"] if c["ok"])
print(f"\n{'='*60}\nSTABILIZATION: {passed}/{total}\n{'='*60}")
with open(GSC/"stabilization_report.json","w") as f:
    json.dump({"total":total,"passed":passed,"sections":REPORT},f,indent=2)
print("Report: stabilization_report.json")
sys.exit(0 if passed==total else 1)
