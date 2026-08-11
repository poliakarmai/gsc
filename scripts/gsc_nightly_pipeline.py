#!/usr/bin/env python3
"""
GSC Nightly Pipeline — orchestrator for all 6 self-learning steps.

Idempotent, logs each step, aborts on critical failure.
Run: cron 04:00 MSK or manually `python3 scripts/gsc_nightly_pipeline.py`.

Steps:
  1. Self-learning revalidate
  2. NVD + GitHub patterns
  3. Bounty Collector (GHSA + VRT + negatives)
  4. Auto-Detector gate (check → validate → shadow activation)
  5. Batch Revalidate (with bounty context)
  6. Federated Submit (critical — abort on failure)
"""
from __future__ import annotations

import json, os, subprocess, sys, time, sqlite3
from datetime import datetime, timezone
from pathlib import Path

GSC = Path(__file__).parent.parent
LOG_DIR = GSC / "logs"
LOG_FILE = LOG_DIR / "nightly_pipeline.log"
DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")


def _log(msg: str, level: str = "INFO"):
    ts = datetime.now(timezone.utc).isoformat()
    line = f"[{ts}] [{level}] {msg}"
    LOG_DIR.mkdir(exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    print(line)


def _run(cmd: list, timeout: int = 600) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=str(GSC))
        return p.returncode, p.stdout[-2000:], p.stderr[-1000:]
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


# ═══════════════════════════════════════════════════════════════════════════════
# Steps
# ═══════════════════════════════════════════════════════════════════════════════

def step_self_learning():
    """Step 1: Revalidate GSC on itself."""
    return _run([sys.executable, "gsc.py", "revalidate", ".", "--json"])


def step_nvd_github():
    """Step 2: Collect patterns from NVD + GitHub."""
    rc1, _, _ = _run([sys.executable, "gsc_collect_light.py", "nvd"], timeout=120)
    rc2, _, _ = _run([sys.executable, "gsc_collect_light.py", "github"], timeout=120)
    return (0 if rc1 == 0 and rc2 == 0 else 1), "", ""


def step_bounty_collect():
    """Step 3: Bounty Collector — GHSA + VRT + negatives."""
    return _run([sys.executable, "gsc_collect_bounty.py", "all"], timeout=300)


def step_auto_detector():
    """Step 4: Auto-Detector — check ready combos, run gate, register shadow."""
    rc, out, err = _run(
        [sys.executable, "scripts/gsc_auto_detector.py", "--run-gate"], timeout=120)
    return rc, out, err


def step_batch_revalidate():
    """Step 5: Batch Revalidate with bounty context."""
    return _run(
        [sys.executable, "scripts/batch_revalidate.py", "--fetch", "500", "--context"],
        timeout=600)


def step_federated_submit():
    """Step 6: Federated Submit (CRITICAL)."""
    return _run([sys.executable, "scripts/federated_submit.py"], timeout=120)


STEPS = [
    ("self_learning",    step_self_learning,    False),
    ("nvd_github",       step_nvd_github,       False),
    ("bounty_collect",   step_bounty_collect,   False),
    ("auto_detector",    step_auto_detector,    False),
    ("batch_revalidate", step_batch_revalidate, False),
    ("federated_submit", step_federated_submit, True),   # critical
]


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    _log("=== NIGHTLY PIPELINE START ===")
    results = {}

    for name, step_fn, critical in STEPS:
        _log(f"STEP {name}...")
        t0 = time.time()
        rc, out, err = step_fn()
        elapsed = time.time() - t0
        status = "OK" if rc == 0 else "FAIL"
        results[name] = {"rc": rc, "elapsed": round(elapsed, 1), "status": status}
        _log(f"  {status} ({elapsed:.1f}s)")

        if rc != 0:
            _log(f"  stderr: {err[:300]}", "ERROR")
            if critical:
                _log(f"CRITICAL step {name} failed — aborting pipeline", "ERROR")
                break

    # Save report
    _save_report(results)

    failed = [k for k, v in results.items() if v["status"] == "FAIL"]
    _log(f"=== PIPELINE END: {len(results)-len(failed)}/{len(results)} OK ===")

    # 🆕 Health snapshot
    _save_health_snapshot(results)

    return 1 if failed else 0


def _save_report(results: dict):
    stamp = datetime.now().strftime("%Y%m%d")
    path = LOG_DIR / f"nightly_{stamp}.json"
    path.write_text(json.dumps(results, indent=2, default=str))
    _log(f"  Report: {path}")


def _save_health_snapshot(results: dict):
    """Save health metrics for pipeline_health.py."""
    db = sqlite3.connect(DB)
    try:
        bounty = db.execute("SELECT COUNT(*) FROM bounty_examples").fetchone()[0]
        negatives = db.execute("SELECT COUNT(*) FROM negative_examples").fetchone()[0]
        shadow = db.execute(
            "SELECT COUNT(*) FROM detector_status WHERE status='shadow'"
        ).fetchone()[0]
        full_from_shadow = db.execute(
            "SELECT COUNT(*) FROM detector_status WHERE status='full' AND rule_id LIKE 'GSAUTO%'"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        bounty = negatives = shadow = full_from_shadow = 0
    finally:
        db.close()

    health = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bounty_total": bounty,
        "negatives_total": negatives,
        "shadow_detectors": shadow,
        "promoted_detectors": full_from_shadow,
        "pipeline": {k: v["status"] for k, v in results.items()},
    }
    path = LOG_DIR / f"health_{datetime.now().strftime('%Y%m%d')}.json"
    path.write_text(json.dumps(health, indent=2))
    _log(f"  Health: {path}")


if __name__ == "__main__":
    sys.exit(main())
