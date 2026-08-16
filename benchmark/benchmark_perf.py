#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC performance benchmarks — synthetic repos at 10K / 100K / 1M LOC.

Measures wall-clock scan time, peak RSS (via RUSAGE_CHILDREN), and findings
count for each size. Baseline = static scan only (``--ci --json``, no
``--deep`` / LLM), so the numbers reflect the deterministic engine cost.

Usage:
  python3 benchmark/benchmark_perf.py                 # 10K, 100K, 1M (default)
  python3 benchmark/benchmark_perf.py --sizes 10k      # quick smoke (one size)
  python3 benchmark/benchmark_perf.py --out perf.md    # also write a report
"""

from __future__ import annotations

import argparse
import json
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GSC = str(Path(__file__).resolve().parent.parent / "gsc.py")
PER_FILE = 2000          # lines per generated module
VULN_EVERY = 500         # sprinkle one vulnerable fn every N functions

SIZE_MAP = {"10k": 10_000, "100k": 100_000, "1m": 1_000_000}


def generate_repo(root: Path, total_lines: int) -> int:
    """Generate synthetic Python modules totalling ~total_lines LOC."""
    n_files = max(1, total_lines // PER_FILE)
    root.mkdir(parents=True, exist_ok=True)
    n_funcs = (PER_FILE - 8) // 3
    written = 0
    for fi in range(n_files):
        buf = ["import os\nimport json\n\n\n"]
        for i in range(n_funcs):
            idx = fi * n_funcs + i
            buf.append(f"def f_{idx}(x):\n    y = x * {idx % 7 + 2}\n    return y\n\n")
            if idx % VULN_EVERY == 0:
                # hardcoded secret + SQL string concat — real scan signal
                buf.append(
                    f"def vuln_{idx}(uid):\n"
                    f"    password = 'SuperSecret{idx}!'\n"
                    f"    query = 'SELECT * FROM users WHERE id=' + str(uid)\n"
                    f"    return password, query\n\n"
                )
        text = "".join(buf)
        (root / f"mod_{fi:04d}.py").write_text(text)
        written += text.count("\n")
    return written


def measure(repo: Path) -> dict:
    """Run gsc.py scan and return duration, peak RSS, and findings count."""
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, GSC, "scan", str(repo), "--ci", "--json"],
        capture_output=True, text=True, timeout=1800,
    )
    dur = time.perf_counter() - t0
    peak_mb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024.0
    findings = -1
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                findings = len(data)
            elif isinstance(data, dict):
                findings = len(data.get("findings", []))
        except Exception:
            findings = -1
    return {
        "duration_s": round(dur, 2),
        "peak_rss_mb": round(peak_mb, 1),
        "findings": findings,
        "returncode": proc.returncode,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10k,100k,1m",
                    help="comma list of sizes: 10k,100k,1m")
    ap.add_argument("--out", default=None, help="write markdown report to path")
    args = ap.parse_args()

    sizes = [s.strip() for s in args.sizes.split(",") if s.strip()]
    rows = []
    tmp = Path(tempfile.mkdtemp(prefix="gsc-perf-"))
    try:
        for s in sizes:
            total = SIZE_MAP.get(s)
            if total is None:
                print(f"[skip] unknown size '{s}'", file=sys.stderr)
                continue
            repo = tmp / s
            gen_lines = generate_repo(repo, total)
            r = measure(repo)
            r["size"], r["loc"] = s, gen_lines
            rows.append(r)
            print(
                f"[done] {s:>5}  loc={r['loc']:>8}  time={r['duration_s']:>8}s  "
                f"rss={r['peak_rss_mb']:>8}MB  findings={r['findings']:>6}",
                file=sys.stderr,
            )
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    md = ["| LOC | Time (s) | Peak RSS (MB) | Findings |",
          "|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['loc']:,} | {r['duration_s']} | {r['peak_rss_mb']} | {r['findings']} |")
    report = "\n".join(md)
    print(report)
    if args.out:
        Path(args.out).write_text("# GSC Performance Benchmarks\n\n" + report + "\n")
        print(f"\nReport written to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
