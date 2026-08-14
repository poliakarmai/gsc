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


class StageOutcome(Enum):
    """GSC roadmap 3.5: трёхзначная семантика стадии верификации."""
    NOT_RUN = "not_run"   # tool unavailable / не пытались запустить
    PASSED = "passed"     # запущено, успех
    FAILED = "failed"     # запущено, провал


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
    # GSC-003: this verifier proves "finding gone" (rescan), NOT that the fix
    # actually closes the vulnerability. Exploit-level proof lives in
    # gsc_proofoffix / gsc_pof_sandbox ("verified" = before/after exploit).
    evidence: str = "rescan"
    tests_skipped: bool = False
    dast_skipped: bool = False
    # GSC roadmap 3.5: раздельные исходы для tests и DAST (NOT_RUN/PASSED/FAILED)
    tests_outcome: StageOutcome = StageOutcome.NOT_RUN
    dast_outcome: StageOutcome = StageOutcome.NOT_RUN


def _ready_for_pr(tests_positive: bool, dast_positive: bool) -> tuple[bool, str]:
    """GSC-003 + roadmap 3.5: PR только при положительном сигнале верификации.

    Positive signal = tests PASSED ИЛИ dast PASSED (реально запущены и успешны).
    rescan-only или NOT_RUN — не доказательство: детектор может пропустить
    всё ещё эксплуатируемое изменение. Returns (ready, reason).
    """
    if not tests_positive and not dast_positive:
        return False, ("no positive verification signal — tests and DAST were "
                       "skipped or NOT_RUN (rescan alone doesn't prove the fix "
                       "closes the vulnerability)")
    return True, ""


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

def _no_test_runner(stderr: str) -> bool:
    """True если ни один runner не был найден (NOT_RUN), а не упали тесты."""
    markers = ("command not found", "no rule to make target", "is not recognized",
               "cannot run program", "no such file", "not found")
    low = stderr.lower()
    return any(m in low for m in markers)


def run_tests(repo_path: str, test_command: str = "") -> tuple[StageOutcome, str]:
    """Run test suite on the fix branch. Returns (outcome, output).

    GSC-002: без завершающего `|| true` — намеренно падающий test suite даёт
    FAILED, а не ложный success. Порядок fallback: make test → pytest → npm test.

    GSC roadmap 3.5: различаем NOT_RUN (ни один runner не доступен) / PASSED /
    FAILED — «не запускались» не смешивается с «запустились и упали».
    """
    cmd = test_command or "make test || python3 -m pytest || npm test"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=180,
            cwd=repo_path,
        )
    except subprocess.TimeoutExpired:
        return StageOutcome.FAILED, "Test suite timed out (180s)"
    except Exception as e:
        return StageOutcome.NOT_RUN, str(e)
    output = result.stdout[-2000:] + result.stderr[-500:]
    if result.returncode == 0:
        return StageOutcome.PASSED, output
    if _no_test_runner(result.stderr):
        return StageOutcome.NOT_RUN, output
    return StageOutcome.FAILED, output


# ── Stage 3: DAST (nuclei) ────────────────────────────────────────────

def run_dast(repo_path: str, finding_key: str) -> tuple[StageOutcome, list[dict]]:
    """Run DAST scan with nuclei templates. Returns (outcome, findings).

    GSC roadmap 3.5: различаем NOT_RUN (nuclei не установлен / template не
    сгенерировался) / PASSED (nuclei отработал, 0 новых issues) / FAILED (issues).
    """
    import shutil
    if shutil.which("nuclei") is None:
        return StageOutcome.NOT_RUN, []
    try:
        # Generate nuclei template from finding
        gen = subprocess.run(
            ["python3", "gsc.py", "nuclei", "export", "--finding-key", finding_key],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).resolve().parent),
        )
        if gen.returncode != 0:
            return StageOutcome.NOT_RUN, []  # can't generate template — skip DAST

        # Run nuclei
        import yaml
        template = yaml.safe_load(gen.stdout)
        if not template:
            return StageOutcome.NOT_RUN, []

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            yaml.dump(template, f)
            template_path = f.name

        result = subprocess.run(
            ["nuclei", "-t", template_path, "-u", repo_path, "-silent", "-json"],
            capture_output=True, text=True, timeout=120,
        )
        os.unlink(template_path)

        if result.returncode != 0 and "no templates provided" not in result.stderr:
            return StageOutcome.NOT_RUN, []

        findings = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return (StageOutcome.FAILED if findings else StageOutcome.PASSED), findings
    except Exception:
        return StageOutcome.NOT_RUN, []


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
    report.tests_skipped = skip_tests
    report.dast_skipped = skip_dast

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
        outcome, output = run_tests(repo_path)
        report.test_output = output
        report.tests_outcome = outcome
        if outcome == StageOutcome.FAILED:
            report.result = VerifyResult.FAILED_TESTS
            report.error_message = "Fix broke tests"
            if attempt < max_attempts:
                report.should_retry = True
            return report
        # NOT_RUN не блокирует здесь, но и не даёт positive signal (см. _ready_for_pr)

    # Stage 3: DAST (optional)
    if not skip_dast:
        outcome, dast = run_dast(repo_path, finding_key)
        report.dast_findings = dast
        report.dast_outcome = outcome
        if outcome == StageOutcome.FAILED:
            report.result = VerifyResult.FAILED_DAST
            report.error_message = f"DAST found {len(dast)} new issues"
            return report

    # GSC-003 + roadmap 3.5: PR требует положительный сигнал верификации.
    tests_positive = (not skip_tests) and report.tests_outcome == StageOutcome.PASSED
    dast_positive = (not skip_dast) and report.dast_outcome == StageOutcome.PASSED
    report.ready_for_pr, pr_reason = _ready_for_pr(tests_positive, dast_positive)
    if pr_reason:
        report.error_message = pr_reason
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
        "tests_outcome": report.tests_outcome.value,
        "dast_outcome": report.dast_outcome.value,
    }, indent=2))
