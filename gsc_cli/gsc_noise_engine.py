#!/usr/bin/env python3
"""GSC Noise Filter Engine — авто-калибровка FP/TP + авто-деградация правил.

Strategy:
  1. Scan known-clean projects (calibration/repos/clean/)
  2. Count findings per rule_id
  3. Rules with >80% FP rate → auto-degrade: CRITICAL→MEDIUM, HIGH→LOW
  4. Store degradation in patterns DB

Usage:
  python3 gsc_noise_engine.py calibrate              # scan clean projects
  python3 gsc_noise_engine.py report                 # show current noise stats
  python3 gsc_noise_engine.py degrade --dry-run      # preview what would be degraded
  python3 gsc_noise_engine.py degrade                # apply degradations
"""
from __future__ import annotations

import json
import sqlite3
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
CALIBRATION_DIR = Path(__file__).parent / "calibration"
REPOS_DIR = CALIBRATION_DIR / "repos"
CLEAN_DIR = REPOS_DIR / "clean"
VULN_DIR = REPOS_DIR / "vuln"

# Thresholds
FP_THRESHOLD = 0.80   # degrade if >80% of findings are FP
TP_THRESHOLD = 0.30   # reactivate if >30% TP rate
MIN_SAMPLES = 10      # need at least this many findings to judge

SEVERITY_DEGRADE = {
    "CRITICAL": "MEDIUM",
    "HIGH": "LOW",
    "MEDIUM": "LOW",
    "LOW": "INFO",
}


# Phase 11 — adaptive self-learning threshold (median + k*MAD) instead of a hardcoded 0.80.
# The threshold follows the distribution of per-rule FP rates, so it self-scales when the
# calibration set (or overall precision) shifts, and is robust to a few pathological rules.
def _median(values) -> float:
    return statistics.median(values) if values else 0.0


def _mad(values, median: float) -> float:
    """Median Absolute Deviation — robust spread."""
    return statistics.median([abs(v - median) for v in values]) if values else 0.0


def adaptive_threshold(fp_rates, k: float = 2.0) -> float:
    """Adaptive FP threshold = median + k*MAD, clipped to [0.5, 0.95].

    Falls back to FP_THRESHOLD when there are too few rates (<3) to compute a spread.
    Note (bimodal population): if pathological rules dominate (>~50% of the rates), the
    median drifts into that group and the threshold can rise; the 0.95 ceiling still
    bounds the worst case. For GSC's calibration set (a handful of noisy rules among many
    clean ones) this is the common, well-behaved case.
    """
    if len(fp_rates) < 3:
        return FP_THRESHOLD
    med = _median(fp_rates)
    spread = _mad(fp_rates, med)
    raw = med + k * spread
    return min(0.95, max(0.5, raw))


def scan_project(project_path: Path) -> list[dict]:
    """Scan a project and return findings as list of dicts."""
    gsc_py = Path(__file__).parent / "gsc.py"
    result = subprocess.run(
        [sys.executable, str(gsc_py), "scan", str(project_path), "--deep", "--ci"],
        capture_output=True, text=True, timeout=120
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def count_by_rule(findings: list[dict]) -> dict[str, int]:
    """Count findings per rule_id."""
    counts: dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id", "unknown")
        counts[rid] = counts.get(rid, 0) + 1
    return counts


def calibrate() -> dict[str, dict]:
    """
    Scan all calibration projects and compute FP rates.
    Clean projects: all findings = FP.
    Vuln projects: findings matching expected vulns = TP, rest = FP.
    """
    results = {}

    # Scan clean projects
    if CLEAN_DIR.exists():
        for proj in CLEAN_DIR.iterdir():
            if proj.is_dir():
                print(f"Scanning clean: {proj.name}...")
                findings = scan_project(proj)
                counts = count_by_rule(findings)
                for rid, cnt in counts.items():
                    if rid not in results:
                        results[rid] = {"fp": 0, "tp": 0, "total": 0}
                    results[rid]["fp"] += cnt
                    results[rid]["total"] += cnt

    # Scan vuln projects (with ground truth)
    expected_file = CALIBRATION_DIR / "calibration_dataset.json"
    if expected_file.exists() and VULN_DIR.exists():
        expected = json.loads(expected_file.read_text())
        for proj in VULN_DIR.iterdir():
            if proj.is_dir():
                print(f"Scanning vuln: {proj.name}...")
                findings = scan_project(proj)
                exp_rules = set(expected.get(proj.name, {}).get("expected_rules", []))
                for f in findings:
                    rid = f.get("rule_id", "unknown")
                    if rid not in results:
                        results[rid] = {"fp": 0, "tp": 0, "total": 0}
                    results[rid]["total"] += 1
                    if rid in exp_rules:
                        results[rid]["tp"] += 1
                    else:
                        results[rid]["fp"] += 1

    # Compute FP rates, then an adaptive "noisy" threshold (Phase 11: median + k*MAD)
    # instead of a hardcoded 0.80 — self-scaling to the calibration set, robust to outliers.
    for _, stats in results.items():
        stats["fp_rate"] = stats["fp"] / max(stats["total"], 1)

    fp_rates = [s["fp_rate"] for s in results.values() if s["total"] >= MIN_SAMPLES]
    threshold = adaptive_threshold(fp_rates)
    for _, stats in results.items():
        stats["noisy"] = (stats["fp_rate"] > threshold and stats["total"] >= MIN_SAMPLES)

    results["_threshold"] = threshold  # metadata (not a rule)
    return results


def degrade_rules(results: dict, dry_run: bool = False) -> list[str]:
    """Apply severity degradation for noisy rules."""
    conn = sqlite3.connect(str(DB_PATH))
    degraded = []

    for rid, stats in results.items():
        if rid == "_threshold":
            continue
        if not stats.get("noisy"):
            continue

        fp_rate = stats["fp_rate"]
        old_sev = _get_rule_severity(conn, rid)
        if not old_sev or old_sev == "INFO":
            continue

        new_sev = SEVERITY_DEGRADE.get(old_sev)
        if not new_sev or new_sev == old_sev:
            continue

        if dry_run:
            print(f"  [DRY-RUN] {rid}: {old_sev} → {new_sev} (FP={fp_rate:.0%}, n={stats['total']})")
        else:
            _update_severity(conn, rid, new_sev)
            print(f"  [APPLIED] {rid}: {old_sev} → {new_sev} (FP={fp_rate:.0%}, n={stats['total']})")
        degraded.append(rid)

    conn.commit()
    conn.close()
    return degraded


def _get_rule_severity(conn: sqlite3.Connection, rule_id: str) -> str | None:
    """Get current severity from patterns DB."""
    row = conn.execute(
        "SELECT category FROM patterns WHERE title LIKE ? OR id IN "
        "(SELECT id FROM patterns WHERE ? LIKE '%' || id || '%') LIMIT 1",
        (f"%{rule_id}%", rule_id)
    ).fetchone()
    return row[0] if row else None


def _update_severity(conn: sqlite3.Connection, rule_id: str, new_sev: str):
    """Update severity in patterns DB."""
    conn.execute(
        "UPDATE patterns SET category=? WHERE title LIKE ?",
        (new_sev, f"%{rule_id}%")
    )


def db_noise_analysis() -> dict[str, dict]:
    """Quick noise analysis from existing audit DB."""
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute(
        "SELECT COALESCE(p.title, 'GS000-LEGACY') as rule_title, f.category, COUNT(*) as cnt "
        "FROM findings f LEFT JOIN patterns p ON f.pattern_id = p.id "
        "GROUP BY rule_title, f.category ORDER BY cnt DESC"
    ).fetchall()
    conn.close()

    if not rows:
        return {}

    results: dict[str, dict] = {}
    for rid, cat, cnt in rows:
        if rid not in results:
            results[rid] = {"fp": 0, "tp": 0, "total": 0}
        results[rid]["total"] += cnt
        results[rid]["category"] = cat

    for _, stats in results.items():
        total = stats["total"]
        stats["fp_rate"] = 0.5
        stats["noisy"] = total >= MIN_SAMPLES
    return results


def report(results: dict | None = None):
    """Print noise report."""
    if results is None:
        results = calibrate()

    noisy = {rid: s for rid, s in results.items() if rid != "_threshold" and s.get("noisy")}
    clean = {rid: s for rid, s in results.items() if rid != "_threshold" and not s.get("noisy") and s["total"] >= MIN_SAMPLES}

    print(f"\n{'='*60}")
    print(f"GSC Noise Report — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}")
    print(f"Total rules with data: {len([r for r in results if r != '_threshold'])}")
    print(f"Adaptive FP threshold:  {results.get('_threshold', FP_THRESHOLD):.0%} (median + 2·MAD)")
    print(f"Noisy (>threshold):    {len(noisy)}")
    print(f"Clean (≤threshold):    {len(clean)}")

    if noisy:
        print("\n🔴 Noisy rules (candidates for degradation):")
        for rid, s in sorted(noisy.items(), key=lambda x: x[1]["fp_rate"], reverse=True):
            print(f"  {rid:>20s}  FP={s['fp_rate']:.0%}  n={s['total']}")

    if clean:
        print("\n🟢 Clean rules:")
        for rid, s in sorted(clean.items(), key=lambda x: x[1]["fp_rate"]):
            print(f"  {rid:>20s}  FP={s['fp_rate']:.0%}  n={s['total']}")

    return results


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    if cmd == "calibrate":
        results = calibrate()
        report(results)
        # Save results
        CALIBRATION_DIR.mkdir(parents=True, exist_ok=True)
        (CALIBRATION_DIR / "noise_report.json").write_text(
            json.dumps(results, indent=2, default=str)
        )
        print(f"\nSaved to {CALIBRATION_DIR / 'noise_report.json'}")

    elif cmd == "report":
        report_file = CALIBRATION_DIR / "noise_report.json"
        if report_file.exists():
            results = json.loads(report_file.read_text())
            report(results)
        else:
            # Fallback: analyze from DB directly
            results = db_noise_analysis()
            if results:
                report(results)
            else:
                print("No report found. Run 'calibrate' first.")

    elif cmd == "degrade":
        report_file = CALIBRATION_DIR / "noise_report.json"
        if not report_file.exists():
            print("No report found. Run 'calibrate' first.")
            return
        results = json.loads(report_file.read_text())
        report(results)
        print(f"\n{'DRY-RUN' if dry_run else 'APPLYING'} degradation...")
        degrade_rules(results, dry_run=dry_run)

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
