#!/usr/bin/env python3
"""
GSC External Benchmark — 100 projects (track 0.14.2).

Clones 100 real open-source projects (90 mixed Python/JS/Go + 10 known-vulnerable
for recall signal), pins revisions, scans, and produces a per-rule report.

Usage:
    python3 scripts/gsc_benchmark_100.py --fetch    # clone 100 + pin HEAD SHA
    python3 scripts/gsc_benchmark_100.py --scan     # scan all, aggregate per-rule
    python3 scripts/gsc_benchmark_100.py --report   # per-rule precision/recall
"""
from __future__ import annotations

import json, subprocess, sys, time, os
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

GSC = Path(__file__).parent.parent
BENCH_DIR = GSC / "benchmark" / "real_world_100"
PROJECTS_FILE = GSC / "benchmark" / "projects_100.json"
PIN_FILE = GSC / "benchmark" / "projects_100_pinned.json"
REPORT_FILE = GSC / "benchmark" / "precision_report_100.json"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_projects() -> list[dict]:
    return json.loads(PROJECTS_FILE.read_text())


def cmd_fetch():
    """Clone all projects (depth 1) and pin HEAD SHA."""
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    pinned = {}
    for proj in load_projects():
        dest = BENCH_DIR / proj["name"]
        if dest.exists():
            sha = _git(dest, "rev-parse", "HEAD")
            pinned[proj["name"]] = sha
            print(f"  ✅ {proj['name']} — exists @ {sha[:8]}")
            continue
        print(f"  📥 {proj['name']} ({proj['lang']})...")
        r = subprocess.run(["git", "clone", "--depth", "1", proj["url"], str(dest)],
                           capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            print(f"    ❌ {r.stderr.strip()[:80]}")
            continue
        sha = _git(dest, "rev-parse", "HEAD")
        pinned[proj["name"]] = sha
        print(f"    ✅ cloned @ {sha[:8]}")
    PIN_FILE.write_text(json.dumps(pinned, indent=2))
    print(f"\nPinned {len(pinned)} revisions → {PIN_FILE.name}")


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def _save_report(results, per_rule, recall_hits):
    """Incrementally persist scan state so a crash/timeout doesn't lose results."""
    REPORT_FILE.write_text(json.dumps({
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "projects": results,
        "per_rule": {k: dict(v) for k, v in per_rule.items()},
        "recall_hits": recall_hits,
    }, indent=2))


def cmd_scan():
    """Scan all cloned projects, aggregate per-rule."""
    pinned = json.loads(PIN_FILE.read_text()) if PIN_FILE.exists() else {}
    results = []
    per_rule = defaultdict(lambda: Counter())  # rule_id -> severity counter
    recall_hits = {}  # recall project -> severity counts

    # Resume: reuse results from a prior (possibly crashed) run.
    done = set()
    if REPORT_FILE.exists():
        prev = json.loads(REPORT_FILE.read_text())
        for p in prev.get("projects", []):
            results.append(p)
            if "error" not in p:
                done.add(p["project"])
        for rule, sevs in prev.get("per_rule", {}).items():
            for sev, n in sevs.items():
                per_rule[rule][sev] += n
        recall_hits.update(prev.get("recall_hits", {}))

    for proj in load_projects():
        if proj["name"] in done:
            continue
        proj_dir = BENCH_DIR / proj["name"]
        if not proj_dir.exists():
            continue
        print(f"\n🔍 {proj['name']} ({proj['lang']})...")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, str(GSC / "gsc.py"), "scan", str(proj_dir),
                                "--ci", "--json"],
                               capture_output=True, text=True, timeout=900, cwd=str(GSC))
        except subprocess.TimeoutExpired:
            results.append({"project": proj["name"], "lang": proj["lang"],
                            "error": "timeout >900s"})
            _save_report(results, per_rule, recall_hits)
            print(f"    ⏱️ timeout — skipped")
            continue
        elapsed = time.time() - t0
        if r.returncode != 0:
            results.append({"project": proj["name"], "lang": proj["lang"],
                            "error": r.stderr[:120]})
            _save_report(results, per_rule, recall_hits)
            print(f"    ❌ scan failed")
            continue
        try:
            data = json.loads(r.stdout)
            findings = data if isinstance(data, list) else data.get("findings", [])
        except json.JSONDecodeError:
            findings = []

        sev_counts = Counter()
        for f in findings:
            sev = f.get("severity") or f.get("category") or "?"
            sev_counts[sev] += 1
            rule = f.get("rule_id", "?")
            per_rule[rule][sev] += 1

        crit = sev_counts.get("CRITICAL", 0)
        high = sev_counts.get("HIGH", 0)
        results.append({
            "project": proj["name"], "lang": proj["lang"],
            "commit": pinned.get(proj["name"], "")[:12],
            "recall": proj.get("recall", False),
            "total": len(findings), "critical": crit, "high": high,
            "elapsed": round(elapsed, 1),
        })
        if proj.get("recall"):
            recall_hits[proj["name"]] = {"critical": crit, "high": high, "total": len(findings)}
        print(f"    📊 {len(findings)} findings: {crit} CRITICAL, {high} HIGH ({elapsed:.1f}s)")
        _save_report(results, per_rule, recall_hits)

    REPORT_FILE.write_text(json.dumps({
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "projects": results,
        "per_rule": {k: dict(v) for k, v in per_rule.items()},
        "recall_hits": recall_hits,
    }, indent=2))
    print(f"\n{'='*60}\n📊 Saved {REPORT_FILE}")
    _print_summary(results)


def _print_summary(results):
    total = sum(r.get("total", 0) for r in results)
    crit = sum(r.get("critical", 0) for r in results)
    high = sum(r.get("high", 0) for r in results)
    recall_projs = [r for r in results if r.get("recall")]
    recall_with_crit = [r for r in recall_projs if r.get("critical", 0) > 0]
    print(f"  Projects: {len(results)} | Findings: {total} | CRITICAL: {crit} | HIGH: {high}")
    print(f"  Recall: {len(recall_with_crit)}/{len(recall_projs)} vulnerable projects had >=1 CRITICAL")


def cmd_report():
    """Per-rule precision/recall from the scan report."""
    if not REPORT_FILE.exists():
        print("❌ No scan results. Run --scan first.")
        return
    report = json.loads(REPORT_FILE.read_text())
    per_rule = report["per_rule"]

    print("\n📈 Per-rule CRITICAL/HIGH distribution (top 25):\n")
    print(f"{'Rule':<28} {'CRIT':>6} {'HIGH':>6} {'Total':>7}")
    print("-" * 50)
    rows = sorted(per_rule.items(), key=lambda kv: -(kv[1].get("CRITICAL", 0) + kv[1].get("HIGH", 0)))
    for rule, sevs in rows[:25]:
        c = sevs.get("CRITICAL", 0)
        h = sevs.get("HIGH", 0)
        t = sum(sevs.values())
        print(f"{rule:<28} {c:>6} {h:>6} {t:>7}")

    # Recall: vulnerable projects with >=1 CRITICAL
    print("\n🎯 Recall signal (known-vulnerable projects):\n")
    rh = report.get("recall_hits", {})
    hit = sum(1 for v in rh.values() if v["critical"] > 0)
    print(f"  {hit}/{len(rh)} vulnerable projects produced >=1 CRITICAL")
    for name, v in rh.items():
        print(f"    {name:<22} {v['critical']} CRITICAL, {v['high']} HIGH")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "--fetch":
        cmd_fetch()
    elif cmd == "--scan":
        cmd_scan()
    elif cmd == "--report":
        cmd_report()
    else:
        print(f"Unknown: {cmd}. Use --fetch, --scan, --report.")
        sys.exit(1)
