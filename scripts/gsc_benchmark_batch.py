#!/usr/bin/env python3
"""Scan ONE batch (10 projects) — resumable + incremental save.

Resume: loads an existing partial report, skips projects already done.
Timeout: 1800s per project (large repos with thousands of findings are slow).
"""
import json, subprocess, sys, time
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

GSC = Path("/home/openclaw/gsc")
BENCH = GSC / "benchmark" / "real_world_100"
ORDERED = GSC / "benchmark" / "projects_100_ordered.json"
PER_PROJECT_TIMEOUT = 1800


def scan_batch(batch_num: int):
    rows = json.loads(ORDERED.read_text())
    batch = [r for r in rows if r["batch"] == batch_num]
    out = GSC / "benchmark" / f"precision_report_batch{batch_num}.json"

    # Resume from prior partial report
    results, per_rule, recall_hits, done = [], defaultdict(Counter), {}, set()
    if out.exists():
        prev = json.loads(out.read_text())
        for p in prev.get("projects", []):
            results.append(p)
            if "error" not in p:
                done.add(p["name"])
        for rule, sevs in prev.get("per_rule", {}).items():
            for s, n in sevs.items():
                per_rule[rule][s] += n
        recall_hits.update(prev.get("recall_hits", {}))

    def save():
        out.write_text(json.dumps({
            "batch": batch_num, "scanned_at": datetime.now(timezone.utc).isoformat(),
            "projects": results, "per_rule": {k: dict(v) for k, v in per_rule.items()},
            "recall_hits": recall_hits}, indent=2))

    for r in batch:
        name = r["name"]
        if name in done:
            print(f"⏭️  {name} — уже сделан, пропускаю", flush=True)
            continue
        proj_dir = BENCH / name
        if not proj_dir.exists():
            results.append({**r, "error": "missing"}); save()
            print(f"❌ {name} — missing", flush=True)
            continue
        print(f"🔍 {name} ({r['lang']}, {r['loc']} LOC, {r['stars']}★)...", flush=True)
        t0 = time.time()
        try:
            p = subprocess.run([sys.executable, str(GSC / "gsc.py"), "scan", str(proj_dir),
                                "--ci", "--json"],
                               capture_output=True, text=True, timeout=PER_PROJECT_TIMEOUT,
                               cwd=str(GSC))
        except subprocess.TimeoutExpired:
            results.append({**r, "error": "timeout"}); save()
            print(f"   ⏱️ timeout >{PER_PROJECT_TIMEOUT}s", flush=True)
            continue
        elapsed = round(time.time() - t0, 1)
        if p.returncode != 0:
            results.append({**r, "error": "scan_failed", "elapsed": elapsed}); save()
            print(f"   ❌ failed ({elapsed}s): {p.stderr[:80]}", flush=True)
            continue
        try:
            data = json.loads(p.stdout)
            findings = data if isinstance(data, list) else data.get("findings", [])
        except json.JSONDecodeError:
            findings = []
        sev = Counter()
        for f in findings:
            s = f.get("severity") or f.get("category") or "?"
            sev[s] += 1
            per_rule[f.get("rule_id", "?")][s] += 1
        results.append({**r, "total": len(findings), "critical": sev.get("CRITICAL", 0),
                        "high": sev.get("HIGH", 0), "elapsed": elapsed})
        if r.get("recall"):
            recall_hits[name] = {"critical": sev.get("CRITICAL", 0),
                                 "high": sev.get("HIGH", 0), "total": len(findings)}
        save()
        print(f"   📊 {len(findings)} findings: {sev.get('CRITICAL', 0)} CRIT, "
              f"{sev.get('HIGH', 0)} HIGH ({elapsed}s)", flush=True)

    total = sum(r.get("total", 0) for r in results)
    crit = sum(r.get("critical", 0) for r in results)
    high = sum(r.get("high", 0) for r in results)
    hit = sum(1 for v in recall_hits.values() if v["critical"] > 0)
    print(f"\n📊 BATCH {batch_num} SUMMARY: {len(results)} projects | {total} findings | "
          f"CRIT={crit} HIGH={high} | recall {hit}/{len(recall_hits)}", flush=True)


if __name__ == "__main__":
    scan_batch(int(sys.argv[1]) if len(sys.argv) > 1 else 1)
