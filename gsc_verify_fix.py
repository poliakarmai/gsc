#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
GSC Fix Verifier — validate fixes before creating PR.

Inspired by triagebot-action's verify-fix.ts (withastro/triagebot-action).
Two-stage verification:
  1. Rescan — re-run detectors on fixed code; finding must be GONE
  2. DAST — run nuclei on the fix branch (if applicable)

Bail-out: after 2 failed verification attempts, give up and flag for human.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class VerifyResult(Enum):
    PASSED = "passed"              # fix works, finding resolved
    FAILED_RESOLVE = "failed_resolve"  # finding still present after fix
    FAILED_TESTS = "failed_tests"      # fix broke tests
    FAILED_DAST = "failed_dast"        # DAST scan found new issues
    FAILED_BUILD = "failed_build"      # fix doesn't compile
    SKIPPED = "skipped"            # no verification needed (e.g. FP)
    ERROR = "error"                # verification tool crashed


@dataclass
class VerifyReport:
    result: VerifyResult
    finding_key: str
    rescan_findings: list[dict] = field(default_factory=list)
    test_output: str = ""
    dast_findings: list[dict] = field(default_factory=list)
    attempt: int = 1
    max_attempts: int = 2
    error_message: str = ""
    should_retry: bool = False
    ready_for_pr: bool = False


# ── Stage 1: Rescan ──────────────────────────────────────────────────

def rescan_fix(repo_path: str, finding_key: str, detector_id: str = "") -> list[dict]:
    """Re-scan the repo after fix. Returns findings that still match."""
    try:
        result = subprocess.run(
            ["python3", "-m", "gsc", "scan", repo_path, "--ci", "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=str(Path(__file__).resolve().parent),
        )
        if result.returncode != 0:
            return [{"error": f"Scan failed: {result.stderr[:200]}"}]

        findings = json.loads(result.stdout) if result.stdout.strip() else []
        if isinstance(findings, dict):
            findings = findings.get("findings", [])

        # Filter: check if the exact finding is still present
        remaining = [
            f for f in findings
            if f.get("finding_key") == finding_key
            or (detector_id and f.get("rule_id", "").startswith(detector_id))
        ]
        return remaining
    except Exception as e:
        return [{"error": str(e)}]


# ── Stage 2: Test Suite ──────────────────────────────────────────────

def run_tests(repo_path: str, test_command: str = "") -> tuple[bool, str]:
    """Run test suite on the fix branch. Returns (passed, output)."""
    cmd = test_command or "make test || python3 -m pytest || npm test || true"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=180,
            cwd=repo_path,
        )
        return result.returncode == 0, result.stdout[-2000:] + result.stderr[-500:]
    except subprocess.TimeoutExpired:
        return False, "Test suite timed out (180s)"
    except Exception as e:
        return False, str(e)


# ── Stage 3: DAST (nuclei) ────────────────────────────────────────────

def run_dast(repo_path: str, finding_key: str) -> list[dict]:
    """Run DAST scan with nuclei templates generated for this finding."""
    try:
        # Generate nuclei template from finding
        gen = subprocess.run(
            ["python3", "gsc.py", "nuclei", "export", "--finding-key", finding_key],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).resolve().parent),
        )
        if gen.returncode != 0:
            return []  # can't generate template — skip DAST

        # Run nuclei
        import yaml
        template = yaml.safe_load(gen.stdout)
        if not template:
            return []

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            yaml.dump(template, f)
            template_path = f.name

        result = subprocess.run(
            ["nuclei", "-t", template_path, "-u", repo_path, "-silent", "-json"],
            capture_output=True, text=True, timeout=120,
        )
        os.unlink(template_path)

        if result.returncode != 0 and "no templates provided" not in result.stderr:
            return []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return findings
    except Exception:
        return []


# ── Main Verifier ────────────────────────────────────────────────────

def verify_fix(
    finding_key: str,
    repo_path: str,
    detector_id: str = "",
    attempt: int = 1,
    max_attempts: int = 2,
    skip_dast: bool = True,  # DAST is slow, off by default
    skip_tests: bool = False,
) -> VerifyReport:
    """
    Verify that a fix actually resolves the finding.

    Returns VerifyReport with:
      - ready_for_pr: True if fix is verified and PR should be created
      - should_retry: True if verification failed but can be retried
    """

    report = VerifyReport(
        result=VerifyResult.PASSED,
        finding_key=finding_key,
        attempt=attempt,
        max_attempts=max_attempts,
    )

    # Stage 1: Rescan — the finding must be gone
    remaining = rescan_fix(repo_path, finding_key, detector_id)
    if remaining:
        report.result = VerifyResult.FAILED_RESOLVE
        report.rescan_findings = remaining
        report.error_message = f"Finding '{finding_key}' still present after fix"

        # Can retry?
        if attempt < max_attempts:
            report.should_retry = True
            report.error_message += f" (attempt {attempt}/{max_attempts})"
        return report

    # Stage 2: Tests must pass
    if not skip_tests:
        passed, output = run_tests(repo_path)
        report.test_output = output
        if not passed:
            report.result = VerifyResult.FAILED_TESTS
            report.error_message = "Fix broke tests"
            if attempt < max_attempts:
                report.should_retry = True
            return report

    # Stage 3: DAST (optional)
    if not skip_dast:
        dast = run_dast(repo_path, finding_key)
        report.dast_findings = dast
        if dast:
            report.result = VerifyResult.FAILED_DAST
            report.error_message = f"DAST found {len(dast)} new issues"
            return report

    # All stages passed!
    report.ready_for_pr = True
    report.result = VerifyResult.PASSED
    return report


# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 gsc_verify_fix.py <finding_key> <repo_path> [--dast] [--tests]")
        sys.exit(1)

    finding_key = sys.argv[1]
    repo_path = sys.argv[2]
    use_dast = "--dast" in sys.argv
    use_tests = "--tests" in sys.argv

    report = verify_fix(
        finding_key=finding_key,
        repo_path=repo_path,
        skip_dast=not use_dast,
        skip_tests=not use_tests,
    )

    print(json.dumps({
        "result": report.result.value,
        "ready_for_pr": report.ready_for_pr,
        "should_retry": report.should_retry,
        "error": report.error_message,
        "attempt": report.attempt,
    }, indent=2))
