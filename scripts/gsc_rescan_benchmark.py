#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-scan calibration + benchmark projects to refresh DB findings after detector changes.

Deterministic (regex-only, no LLM): uses `gsc.py scan <abs> --ci`, which runs
echelons 1-3 without --deep/--llm (LLM verification is opt-in via those flags).

Usage:
    python3 scripts/gsc_rescan_benchmark.py            # full re-scan (resumable)
    python3 scripts/gsc_rescan_benchmark.py --reset    # delete old findings + state, start fresh
    python3 scripts/gsc_rescan_benchmark.py --limit 3  # scan only first N (smoke test)
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

GSC = Path("/home/openclaw/gsc")
DB = Path.home() / ".hermes/state/gsc_audit.db"
STATE = GSC / "benchmark" / "rescan_state.json"
CAL_DATASET = GSC / "calibration" / "calibration_dataset.json"
CAL_DIR = Path("/tmp/gsc-calibration")
BENCH_DIR = GSC / "benchmark" / "real_world_100"
ORDERED = GSC / "benchmark" / "projects_100_ordered.json"

PER_PROJECT_TIMEOUT = 1800  # seconds (large repos are slow)


def load_targets() -> list[tuple[str, Path, bool]]:
    targets: list[tuple[str, Path, bool]] = []
    cal = json.loads(CAL_DATASET.read_text())
    for p in cal["projects"]:
        targets.append((p["name"], CAL_DIR / p["name"], p.get("category") == "vulnerable"))
    bench = json.loads(ORDERED.read_text())
    for p in bench:
        targets.append((p["name"], BENCH_DIR / p["name"], bool(p.get("recall"))))
    return targets


def main() -> int:
    args = sys.argv[1:]
    reset = "--reset" in args
    limit = None
    if "--limit" in args:
        limit = int(args[args.index("--limit") + 1])

    targets = load_targets()
    if limit:
        targets = targets[:limit]

    done: set[str] = set()
    if STATE.exists() and not reset:
        done = set(json.loads(STATE.read_text()).get("done", []))

    if reset or not STATE.exists():
        bak = DB.with_suffix(f".db.bak-rescan-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(DB, bak)
        print(f"backup -> {bak}", flush=True)
        db = sqlite3.connect(str(DB))
        n = db.execute(
            "DELETE FROM findings WHERE project LIKE '%gsc-calibration%' "
            "OR project LIKE '%real_world_100%'"
        ).rowcount
        db.commit()
        db.close()
        print(f"deleted {n} old benchmark/calibration findings", flush=True)

    total = len(targets)
    t_start = time.time()
    ok = fail = skip = 0
    for i, (name, path, _recall) in enumerate(targets, 1):
        if name in done:
            skip += 1
            continue
        if not path.exists():
            print(f"[{i}/{total}] MISSING {name}", flush=True)
            fail += 1
            continue
        t0 = time.time()
        try:
            r = subprocess.run(
                [sys.executable, str(GSC / "gsc.py"), "scan", str(path), "--ci"],
                capture_output=True, text=True, timeout=PER_PROJECT_TIMEOUT, cwd=str(GSC),
            )
        except subprocess.TimeoutExpired:
            print(f"[{i}/{total}] TIMEOUT {name}", flush=True)
            fail += 1
            done.add(name)
            STATE.write_text(json.dumps(
                {"done": sorted(done), "updated": datetime.now(timezone.utc).isoformat()}))
            continue
        el = round(time.time() - t0, 1)
        if r.returncode == 0:
            ok += 1
        else:
            fail += 1
            print(f"[{i}/{total}] FAIL {name} ({el}s): {r.stderr.strip()[:100]}", flush=True)
            done.add(name)
            STATE.write_text(json.dumps(
                {"done": sorted(done), "updated": datetime.now(timezone.utc).isoformat()}))
            continue
        print(f"[{i}/{total}] OK {name} ({el}s)", flush=True)
        done.add(name)
        STATE.write_text(json.dumps(
            {"done": sorted(done), "updated": datetime.now(timezone.utc).isoformat()}))

    el_total = round(time.time() - t_start, 1)
    print(f"\nRESCAN DONE: {len(done)}/{total} | ok={ok} fail={fail} skip={skip} "
          f"({el_total}s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
