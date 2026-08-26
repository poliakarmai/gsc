#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
Micro-benchmark for patch performance: measures CPU and memory before and after
applying a patch in a sandbox environment.

Usage:
    python3 scripts/gsc_perf_benchmark.py --patch-json <path_to_fix_evidence.json>
    python3 scripts/gsc_perf_benchmark.py --original-file <path_to_original.py> --patch-file <path_to_patch.json>

The patch file contains a list of edit instructions similar to FixEvidence.patch.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Constants for performance thresholds
CPU_REGRESSION_THRESHOLD_MS = 5.0  # milliseconds
MEMORY_REGRESSION_THRESHOLD_KB = 1024.0  # 1 MB in KB

# Import FixSandbox from gsc_cli.gsc_proofoffix
# This requires a PYTHONPATH setup or direct import path adjustment
try:
    # Attempt direct import first for local execution
    from gsc_cli.gsc_proofoffix import FixSandbox, PatchApplyError
except ImportError:
    # Fallback for script execution when gsc_cli might not be in path
    _gsc_path = Path(__file__).parent.parent
    if str(_gsc_path) not in sys.path:
        sys.path.insert(0, str(_gsc_path))
    from gsc_cli.gsc_proofoffix import FixSandbox, PatchApplyError


def measure_perf(
    func: Callable[[], Any], iterations: int = 1000
) -> Dict[str, float]:
    """Measures CPU time (user + system) and peak memory for a function."""
    rusage_start = resource.getrusage(resource.RUSAGE_SELF)
    start_time = time.perf_counter()

    for _ in range(iterations):
        func()

    end_time = time.perf_counter()
    rusage_end = resource.getrusage(resource.RUSAGE_SELF)

    cpu_time_ms = (
        (rusage_end.ru_utime - rusage_start.ru_utime)
        + (rusage_end.ru_stime - rusage_start.ru_stime)
    ) * 1000.0
    
    # maxrss is in kilobytes on Linux
    peak_memory_kb = rusage_end.ru_maxrss - rusage_start.ru_maxrss

    return {"cpu_time_ms": cpu_time_ms, "peak_memory_kb": peak_memory_kb}


def apply_patch_in_sandbox(
    original_content: str, patch_instructions: List[Dict]
) -> str:
    """Applies patch instructions to a file in a sandbox and returns the content."""
    # Create a dummy file path for FixSandbox, as it expects one
    dummy_file_path = "temp_file.py"
    sandbox = FixSandbox(dummy_file_path, original_content)
    try:
        patched_content = sandbox.apply_edits(patch_instructions)
        return patched_content
    finally:
        sandbox.cleanup()


def run_benchmark(
    original_file_path: Path, patch_instructions: List[Dict], iterations: int = 100
) -> Dict[str, Any]:
    """Runs the performance benchmark for a given patch."""
    original_content = original_file_path.read_text(encoding="utf-8")

    def run_original():
        # This will simulate reading the original file content
        original_file_path.read_text(encoding="utf-8")

    def run_patched():
        # This will simulate applying the patch and then reading the content
        # We create a new sandbox for each iteration to avoid state pollution
        apply_patch_in_sandbox(original_content, patch_instructions)

    # Measure performance before patch
    perf_before = measure_perf(run_original, iterations=iterations)
    # Measure performance after patch
    perf_after = measure_perf(run_patched, iterations=iterations)

    cpu_delta_ms = perf_after["cpu_time_ms"] - perf_before["cpu_time_ms"]
    mem_delta_kb = perf_after["peak_memory_kb"] - perf_before["peak_memory_kb"]

    verdict = "safe"
    if mem_delta_kb > MEMORY_REGRESSION_THRESHOLD_KB:
        verdict = "regression"
    elif cpu_delta_ms > CPU_REGRESSION_THRESHOLD_MS:
        verdict = "safe but slow"

    return {
        "cpu_delta_ms": round(cpu_delta_ms, 3),
        "mem_delta_kb": round(mem_delta_kb, 3),
        "verdict": verdict,
        "perf_before": perf_before,
        "perf_after": perf_after,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Micro-benchmark for patch performance.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--patch-json",
        type=Path,
        help="Path to a FixEvidence JSON file containing 'patch' instructions.",
    )
    parser.add_argument(
        "--original-file",
        type=Path,
        help="Path to the original file to which the patch will be applied. "
        "Required if --patch-json is not used.",
    )
    parser.add_argument(
        "--patch-file",
        type=Path,
        help="Path to a JSON file containing only the patch instructions (list of dicts). "
        "Required if --patch-json is not used.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Number of iterations for performance measurement (default: 100).",
    )

    args = parser.parse_args()

    patch_instructions: List[Dict] = []
    original_file_path: Optional[Path] = None

    if args.patch_json:
        try:
            from gsc_proofoffix import FixEvidence
            evidence_data = json.loads(args.patch_json.read_text())
            # We only need the patch instructions and file_path from FixEvidence
            # Using __dataclass_fields__ to avoid unexpected keys
            fields = {f.name for f in FixEvidence.__dataclass_fields__.values()}
            ev = FixEvidence(**{k: v for k, v in evidence_data.items() if k in fields})

            patch_instructions = ev.patch
            original_file_path = Path(ev.file_path)

        except ImportError:
            print("Error: gsc_proofoffix not found. Please ensure it's in PYTHONPATH.", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error reading FixEvidence JSON: {e}", file=sys.stderr)
            return 1
    elif args.original_file and args.patch_file:
        original_file_path = args.original_file
        try:
            patch_instructions = json.loads(args.patch_file.read_text())
        except Exception as e:
            print(f"Error reading patch file: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1

    if not original_file_path or not original_file_path.exists():
        print(f"Error: Original file '{original_file_path}' not found.", file=sys.stderr)
        return 1
    if not patch_instructions:
        print("Error: No patch instructions found.", file=sys.stderr)
        return 1

    print(f"Benchmarking patch for {original_file_path} with {len(patch_instructions)} edits...")
    result = run_benchmark(original_file_path, patch_instructions, args.iterations)

    print(f"CPU Delta: {result['cpu_delta_ms']:.3f} ms")
    print(f"Memory Delta: {result['mem_delta_kb']:.3f} KB")
    print(f"Verdict: {result['verdict']}")
    print(f"Performance before: {result['perf_before']}")
    print(f"Performance after: {result['perf_after']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
