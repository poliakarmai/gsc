#!/usr/bin/env python3
"""
GSC Real-World Benchmark — precision/recall on 10 open-source projects.

Clones, scans, and produces a structured report for manual CRITICAL verification.
Goal: replace synthetic calibration with real-world metrics.

Usage:
    python3 scripts/gsc_benchmark_real.py --fetch    # Clone 10 projects
    python3 scripts/gsc_benchmark_real.py --scan     # Scan all projects
    python3 scripts/gsc_benchmark_real.py --report   # Generate precision report
    python3 scripts/gsc_benchmark_real.py --verify   # Interactive CRITICAL verification
"""
from __future__ import annotations

import json, os, subprocess, sys, time, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

GSC = Path(__file__).parent.parent
BENCH_DIR = GSC / "benchmark" / "real_world"
REPORT_PATH = GSC / "benchmark" / "precision_report.json"
DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")

# 10 projects: real code, diverse domains, 10-500 stars
# Mix of: web frameworks, CLI tools, APIs, libraries
PROJECTS = [
    # Web frameworks / APIs
    {"name": "flask-smorest",  "url": "https://github.com/marshmallow-code/flask-smorest.git",  "stars": 600},
    {"name": "fastapi-users",  "url": "https://github.com/fastapi-users/fastapi-users.git",      "stars": 4500},
    {"name": "piccolo-api",    "url": "https://github.com/piccolo-orm/piccolo_api.git",          "stars": 160},
    {"name": "sanic",          "url": "https://github.com/sanic-org/sanic.git",                  "stars": 18000},
    # CLI / Tools
    {"name": "httpie",         "url": "https://github.com/httpie/cli.git",                       "stars": 34000},
    {"name": "thefuck",        "url": "https://github.com/nvbn/thefuck.git",                     "stars": 85000},
    {"name": "youtube-dl",     "url": "https://github.com/ytdl-org/youtube-dl.git",             "stars": 132000},
    # Libraries
    {"name": "pendulum",       "url": "https://github.com/sdispater/pendulum.git",               "stars": 6200},
    {"name": "loguru",         "url": "https://github.com/Delgan/loguru.git",                    "stars": 20000},
    {"name": "rich",           "url": "https://github.com/Textualize/rich.git",                  "stars": 50000},
]


def cmd_fetch():
    """Clone all 10 projects."""
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    for proj in PROJECTS:
        dest = BENCH_DIR / proj["name"]
        if dest.exists():
            print(f"  ✅ {proj['name']} — exists, skipping")
            continue
        print(f"  📥 {proj['name']} ({proj['stars']}⭐)...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", proj["url"], str(dest)],
            capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print(f"    ✅ cloned")
        else:
            print(f"    ❌ {result.stderr[:100]}")


def cmd_scan():
    """Scan all cloned projects with GSC precision-hunt profile."""
    results = []
    for proj in PROJECTS:
        proj_dir = BENCH_DIR / proj["name"]
        if not proj_dir.exists():
            print(f"  ⚠️ {proj['name']} — not cloned, run --fetch first")
            continue

        print(f"\n🔍 {proj['name']} ({proj['stars']}⭐)...")
        t0 = time.time()

        result = subprocess.run(
            [sys.executable, str(GSC / "gsc.py"), "scan", str(proj_dir),
             "--ci", "--json", "--profile", "precision-hunt"],
            capture_output=True, text=True, timeout=600,
            cwd=str(GSC))

        elapsed = time.time() - t0

        if result.returncode != 0:
            print(f"    ❌ scan failed: {result.stderr[:200]}")
            results.append({"project": proj["name"], "stars": proj["stars"],
                          "error": result.stderr[:200], "elapsed": round(elapsed, 1)})
            continue

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"    ❌ invalid JSON output")
            results.append({"project": proj["name"], "stars": proj["stars"],
                          "error": "invalid JSON", "elapsed": round(elapsed, 1)})
            continue

        findings = data.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        high = [f for f in findings if f.get("severity") == "HIGH"]

        print(f"    📊 {len(findings)} findings: {len(critical)} CRITICAL, {len(high)} HIGH ({elapsed:.1f}s)")

        results.append({
            "project": proj["name"], "stars": proj["stars"],
            "total": len(findings),
            "critical": len(critical),
            "high": len(high),
            "elapsed": round(elapsed, 1),
            "findings_file": f"benchmark/real_world/{proj['name']}_scan.json",
        })

        # Save full scan output
        scan_file = BENCH_DIR / f"{proj['name']}_scan.json"
        scan_file.write_text(result.stdout)

    # Save summary
    REPORT_PATH.write_text(json.dumps({
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "projects": results,
        "summary": {
            "total_projects": len(results),
            "total_findings": sum(r.get("total", 0) for r in results),
            "total_critical": sum(r.get("critical", 0) for r in results),
            "total_high": sum(r.get("high", 0) for r in results),
        }
    }, indent=2))

    print(f"\n{'='*60}")
    print(f"📊 Saved: {REPORT_PATH}")
    _print_summary(results)


def cmd_report():
    """Generate precision report from verified findings."""
    if not REPORT_PATH.exists():
        print("❌ No scan results yet. Run --scan first.")
        return

    report = json.loads(REPORT_PATH.read_text())

    # Load DB for verification stats
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    print("\n📈 GSC Precision Report — Real-World Projects\n")
    print(f"Scanned: {report.get('scanned_at', '?')}")
    print(f"Projects: {report['summary']['total_projects']}")
    print(f"Findings: {report['summary']['total_findings']}")
    print(f"CRITICAL: {report['summary']['total_critical']}")
    print(f"HIGH: {report['summary']['total_high']}")

    print(f"\n{'Project':<20} {'⭐':>6} {'Total':>6} {'CRIT':>6} {'HIGH':>6} {'Time':>6}")
    print("-" * 56)
    for r in report["projects"]:
        print(f"{r['project']:<20} {r['stars']:>6} {r.get('total',0):>6} "
              f"{r.get('critical',0):>6} {r.get('high',0):>6} {r.get('elapsed',0):>5}s")

    # CRITICAL findings for manual review
    print(f"\n🔴 CRITICAL findings for manual verification:\n")
    for r in report["projects"]:
        scan_file = BENCH_DIR / f"{r['project']}_scan.json"
        if not scan_file.exists():
            continue
        data = json.loads(scan_file.read_text())
        critical = [f for f in data.get("findings", []) if f.get("severity") == "CRITICAL"]
        if critical:
            print(f"\n── {r['project']} ({r['stars']}⭐) — {len(critical)} CRITICAL ──")
            for i, f in enumerate(critical[:5], 1):
                print(f"  [{i}] {f.get('rule_id','?')}: {f.get('title','?')[:80]}")
                print(f"      File: {f.get('file_path','?')}:{f.get('line_number','?')}")
                snippet = (f.get('detail', '') or '')[:120]
                print(f"      {snippet}")

    # DB-based precision stats
    try:
        tp = db.execute(
            "SELECT COUNT(*) as c FROM findings WHERE revalidation_verdict='TP'"
        ).fetchone()["c"]
        fp = db.execute(
            "SELECT COUNT(*) as c FROM findings WHERE revalidation_verdict='FP'"
        ).fetchone()["c"]
        total_reval = tp + fp
        precision = tp / total_reval if total_reval > 0 else 0
        print(f"\n📊 Self-learning precision: {tp}/{total_reval} = {precision:.1%} (from DB verdicts)")
    except sqlite3.OperationalError:
        pass

    db.close()


def _print_summary(results):
    total = sum(r.get("total", 0) for r in results)
    crit = sum(r.get("critical", 0) for r in results)
    high = sum(r.get("high", 0) for r in results)
    print(f"  Projects: {len(results)} | Findings: {total} | CRITICAL: {crit} | HIGH: {high}")
    print(f"\n💡 Run --report for detailed analysis.")
    print(f"   Run --verify to manually classify CRITICAL findings.")


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
        print(f"Unknown: {cmd}. Use --fetch, --scan, or --report.")
        sys.exit(1)
