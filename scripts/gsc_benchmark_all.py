#!/usr/bin/env python3
"""Run batches 2..10 sequentially, aggregate all batch reports into a final summary."""
import json, subprocess, sys, time
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

GSC = Path("/home/openclaw/gsc")
START = 2
END = 10

def run_batch(b):
    print(f"\n{'#'*60}\n# BATCH {b}\n{'#'*60}", flush=True)
    r = subprocess.run([sys.executable, str(GSC / "scripts" / "gsc_benchmark_batch.py"), str(b)],
                       capture_output=True, text=True, timeout=1200)
    print(r.stdout, flush=True)
    if r.stderr:
        print(r.stderr, flush=True)

def aggregate():
    rows, per_rule, recall = [], defaultdict(Counter), {}
    for b in range(1, END + 1):
        f = GSC / "benchmark" / f"precision_report_batch{b}.json"
        if not f.exists():
            continue
        d = json.loads(f.read_text())
        for p in d.get("projects", []):
            rows.append(p)
        for rule, sevs in d.get("per_rule", {}).items():
            for s, n in sevs.items():
                per_rule[rule][s] += n
        recall.update(d.get("recall_hits", {}))
    return rows, per_rule, recall

def main():
    for b in range(START, END + 1):
        run_batch(b)

    rows, per_rule, recall = aggregate()
    total = sum(r.get("total", 0) for r in rows)
    crit = sum(r.get("critical", 0) for r in rows)
    high = sum(r.get("high", 0) for r in rows)
    recall_projs = [r for r in rows if r.get("recall")]
    hit = sum(1 for n, v in recall.items() if v["critical"] > 0)

    out = GSC / "benchmark" / "precision_report_ALL_100.json"
    out.write_text(json.dumps({
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "projects": rows, "per_rule": {k: dict(v) for k, v in per_rule.items()},
        "recall_hits": recall,
    }, indent=2))

    print(f"\n{'='*60}\n🏁 FINAL — ALL 100 PROJECTS\n{'='*60}", flush=True)
    print(f"  Projects: {len(rows)} | Findings: {total} | CRITICAL: {crit} | HIGH: {high}")
    print(f"  🎯 Recall: {hit}/{len(recall)} vulnerable projects >=1 CRITICAL")
    print(f"\n  Top 20 rules by CRITICAL+HIGH:")
    for rule, sevs in sorted(per_rule.items(),
                             key=lambda kv: -(kv[1].get("CRITICAL", 0) + kv[1].get("HIGH", 0)))[:20]:
        print(f"      {rule:<28} {sevs.get('CRITICAL', 0):>5} {sevs.get('HIGH', 0):>5}")
    print(f"\n  Saved -> {out}")

if __name__ == "__main__":
    main()
