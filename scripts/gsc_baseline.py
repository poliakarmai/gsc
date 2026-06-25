#!/usr/bin/env python3
"""GSC Baseline — mark existing findings as 'baseline' to suppress in future scans."""
import sys, os, json, sqlite3, hashlib
from pathlib import Path
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

def baseline_save(project: str):
    """Save current open findings as baseline."""
    if not os.path.exists(DB):
        print("No GSC database"); return

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM findings WHERE project=? AND status='open'", (project,)).fetchall()
    
    baseline = {
        "version": 1,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "gsc baseline",
        "project": project,
        "findings": []
    }
    
    for r in rows:
        h = hashlib.sha256(f"{r['file_path']}:{r['line_number']}:{r['title']}".encode()).hexdigest()[:12]
        baseline["findings"].append({
            "hash": h,
            "id": r['id'],
            "title": r['title'],
            "file_path": r['file_path'],
            "line_number": r['line_number'],
        })
    
    # Mark as baseline in DB
    for r in rows:
        conn.execute("UPDATE findings SET status='baseline' WHERE id=?", (r['id'],))
    conn.commit()
    
    # Save to file
    baseline_file = Path(project) / ".gsc" / "baseline.json" if Path(project).exists() else Path(f"/tmp/gsc_baseline_{project}.json")
    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_file, "w") as f:
        json.dump(baseline, f, indent=2)
    
    conn.close()
    print(f"✅ Baseline: {len(rows)} findings → {baseline_file}")

def baseline_apply(project: str, baseline_file: str = None):
    """Apply baseline: mark known findings so they don't show in scans."""
    if baseline_file is None:
        baseline_file = Path(project) / ".gsc" / "baseline.json"
    
    if not os.path.exists(baseline_file):
        print(f"No baseline found at {baseline_file}")
        return
    
    with open(baseline_file) as f:
        baseline = json.load(f)
    
    if not os.path.exists(DB):
        print("No GSC database"); return
    
    conn = sqlite3.connect(DB)
    hashes = [f['hash'] for f in baseline['findings']]
    count = 0
    
    for h in hashes:
        # Find matching finding by hash (simplified: match by title+file)
        for f in baseline['findings']:
            if f['hash'] == h:
                conn.execute(
                    "UPDATE findings SET status='baseline' WHERE project=? AND title=? AND file_path=? AND line_number=?",
                    (project, f['title'], f['file_path'], f['line_number'])
                )
                count += conn.changes
    
    conn.commit()
    conn.close()
    print(f"✅ Applied baseline: {count} findings suppressed")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: gsc_baseline.py save <project> | apply <project> [baseline.json]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    project = sys.argv[2] if len(sys.argv) > 2 else "."
    
    if cmd == "save":
        baseline_save(project)
    elif cmd == "apply":
        baseline_apply(project, sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        print(f"Unknown: {cmd}")
