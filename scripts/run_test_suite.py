#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC-005: full test gate — pytest tests + custom-runner smoke tests.

``pytest`` only collects ``def test_*`` functions, but GSC has ~24 custom-runner
test files (test_cloud_s1, test_exclusive_pof, test_enterprise, ...) whose
``t()`` / ``run_case()`` assertions execute as module-level code and are
invisible to pytest. A green pytest therefore masks a red custom-runner suite.
This gate runs BOTH so the release signal is honest.

Usage: python3 scripts/run_test_suite.py
"""
import glob
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _is_custom_runner(path: str) -> bool:
    txt = Path(path).read_text(encoding="utf-8", errors="ignore")
    return "def test_" not in txt and "__main__" in txt


def main() -> int:
    failures = []

    # 1) pytest-style tests
    print("── pytest (def test_*) ──")
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q"],
        cwd=str(ROOT),
    )
    if r.returncode != 0:
        failures.append("pytest")

    # 2) custom-runner suites (module-level t()/run_case() assertions)
    print("\n── custom-runner suites ──")
    files = sorted(
        glob.glob(str(ROOT / "tests" / "*.py"))
        + glob.glob(str(ROOT / "enterprise" / "tests" / "*.py"))
    )
    for f in files:
        if not _is_custom_runner(f):
            continue
        name = os.path.relpath(f, ROOT)
        r = subprocess.run(
            [sys.executable, f],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=600,
        )
        status = "OK" if r.returncode == 0 else "FAIL"
        print(f"  [{status}] {name}")
        if r.returncode != 0:
            failures.append(name)
            print((r.stdout or "")[-900:])
            print((r.stderr or "")[-400:])

    print("\n" + "=" * 60)
    if failures:
        print(f"❌ FAILED ({len(failures)}): {', '.join(failures)}")
        return 1
    print("✅ ALL TEST SUITES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
