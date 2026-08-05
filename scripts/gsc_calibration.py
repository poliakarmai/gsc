#!/usr/bin/env python3
"""
GSC Calibration Runner v0.14
gsc calibration run --dataset calibration/calibration_dataset.json --fail-on-regression
"""

import os, sys, json, subprocess
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field

GSC_EXTERNAL = Path(__file__).resolve().parent / "gsc_external.py"
CALIB_DIR = Path(__file__).resolve().parent / "calibration"


@dataclass
class CalibrationReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    clean_total: int = 0
    clean_passed: int = 0
    vuln_total: int = 0
    vuln_passed: int = 0
    blocking_fps: int = 0
    missed_expected: int = 0
    redaction_leaks: int = 0
    sarif_invalid: int = 0
    duration_seconds: float = 0
    results: list[dict] = field(default_factory=list)


def load_expected(project_name: str) -> dict:
    """Load expected findings for a calibration project."""
    expected_file = CALIB_DIR / "expected" / f"{project_name}.json"
    if expected_file.exists():
        return json.loads(expected_file.read_text())
    return {}


def check_sarif_valid(sarif_path: Path) -> bool:
    """Basic SARIF schema check."""
    try:
        data = json.loads(sarif_path.read_text())
        return "runs" in data and "$schema" in data
    except Exception:
        return False


def check_redaction_leaks(scan_json: Path) -> int:
    """Count raw secrets in scan data. Returns number of leaks found."""
    leaks = 0
    try:
        text = scan_json.read_text()
        # Check for common secret patterns
        import re
        patterns = [
            r'sk-[a-zA-Z0-9]{20,}',          # API keys
            r'AKIA[A-Z0-9]{16}',              # AWS
            r'-----BEGIN.*PRIVATE KEY-----',  # Private keys
            r'(?:password|secret)\s*[=:]\s*["\'][^\s"\']{8,}["\']',  # hardcoded creds
        ]
        for pat in patterns:
            matches = re.findall(pat, text, re.IGNORECASE)
            if matches:
                # Check if already redacted
                for m in matches:
                    if "REDACTED" not in m:
                        leaks += 1
    except Exception:
        pass
    return leaks


def run_calibration(dataset_path: str = None, fail_on_regression: bool = False,
                    format: str = "json") -> int:
    """
    Run calibration against dataset.
    Returns exit code (0=pass, 1=regression).
    """
    ds_path = Path(dataset_path) if dataset_path else CALIB_DIR / "calibration_dataset.json"
    if not ds_path.exists():
        print(f"❌ Dataset not found: {ds_path}")
        return 2

    dataset = json.loads(ds_path.read_text())
    started = datetime.now(timezone.utc)

    report = CalibrationReport()
    report.results = []

    projects = []
    for category in ["vulnerable", "clean"]:
        for p in dataset.get(category, []):
            projects.append((p, category))

    report.total = len(projects)

    for i, (proj, category) in enumerate(projects):
        name = proj.get("name", f"project-{i}")
        url = proj.get("url", "")
        expected_data = load_expected(name) or proj.get("expected", {})

        print(f"\n[{i+1}/{len(projects)}] {name} ({category})...", end=" ", flush=True)

        result_entry = {
            "project": name,
            "type": category,
            "status": "PASS",
            "blocking": 0,
            "confirmed": 0,
            "expected_found": 0,
            "expected_missed": 0,
            "errors": [],
        }

        # Run scan
        scan_ok = False
        out_dir = None
        try:
            target = url if url else f"/tmp/gsc-calibration/{name}"
            if not Path(target).exists() and url:
                subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none",
                               url, target], timeout=60)

            r = subprocess.run(
                [sys.executable, str(GSC_EXTERNAL), "scan", target,
                 "--profile", "developer-review",
                 "--format", "markdown"],
                capture_output=True, text=True, timeout=180
            )

            # Find generated report
            from gsc_external import EXTERNAL_DIR
            reports = sorted(Path(EXTERNAL_DIR).glob(f"{name}/*/scan.json"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                out_dir = reports[0].parent
                scan_data = json.loads(reports[0].read_text())
                scan_ok = True

                result_entry["blocking"] = scan_data.get("findings_blocking", 0)
                result_entry["confirmed"] = scan_data.get("findings_confirmed", 0)
                result_entry["likely"] = scan_data.get("findings_likely", 0)

                # Check expected findings
                expected_findings = expected_data.get("expected_findings", [])
                for exp in expected_findings:
                    found = False
                    for f in scan_data.get("findings", []):
                        if isinstance(exp, str) and exp in (f.get("rule_id", "") + f.get("title", "")):
                            found = True
                        elif isinstance(exp, dict) and exp.get("rule_id") == f.get("rule_id"):
                            if f.get("confidence_score", 0) >= exp.get("min_confidence", 0):
                                found = True
                    if found:
                        result_entry["expected_found"] += 1
                    else:
                        result_entry["expected_missed"] += 1

                # Check redaction
                leaks = check_redaction_leaks(reports[0])
                if leaks:
                    result_entry["errors"].append(f"{leaks} redaction leaks")
                    report.redaction_leaks += leaks

                # Check SARIF
                sarif_file = out_dir / "report.sarif.json"
                if not sarif_file.exists() or not check_sarif_valid(sarif_file):
                    result_entry["errors"].append("SARIF invalid or missing")
                    report.sarif_invalid += 1

        except Exception as e:
            result_entry["errors"].append(f"Scan error: {str(e)[:100]}")

        # Pass/fail logic
        if category == "clean":
            report.clean_total += 1
            max_blocking = expected_data.get("max_blocking", 0)
            max_conf_high = expected_data.get("max_confirmed_high", 0)
            if result_entry["blocking"] > max_blocking:
                result_entry["status"] = "FAIL"
                result_entry["errors"].append(
                    f"Blocking: {result_entry['blocking']} (max {max_blocking})")
                report.blocking_fps += result_entry["blocking"]
            elif result_entry["errors"]:
                result_entry["status"] = "FAIL"
            else:
                report.clean_passed += 1

        elif category == "vulnerable":
            report.vuln_total += 1
            expect_blocking = expected_data.get("expect_blocking", False)
            if expect_blocking and result_entry["blocking"] == 0:
                result_entry["status"] = "FAIL"
                result_entry["errors"].append("Expected blocking findings but got none")
            if result_entry["expected_missed"] > 0:
                result_entry["status"] = "FAIL"
                report.missed_expected += result_entry["expected_missed"]
            if result_entry["status"] == "PASS":
                report.vuln_passed += 1

        if result_entry["status"] == "PASS" and not result_entry["errors"]:
            report.passed += 1
            print("✅ PASS")
        else:
            report.failed += 1
            print(f"❌ FAIL: {'; '.join(result_entry['errors'])}")

        report.results.append(result_entry)

    report.duration_seconds = (datetime.now(timezone.utc) - started).total_seconds()

    # Save report
    out_dir = CALIB_DIR / "reports" / datetime.now().strftime("%Y-%m-%d_%H%M")
    out_dir.mkdir(parents=True, exist_ok=True)

    report_data = {
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "clean": {"total": report.clean_total, "passed": report.clean_passed},
        "vuln": {"total": report.vuln_total, "passed": report.vuln_passed},
        "blocking_false_positives": report.blocking_fps,
        "missed_expected": report.missed_expected,
        "redaction_leaks": report.redaction_leaks,
        "sarif_invalid": report.sarif_invalid,
        "duration_seconds": report.duration_seconds,
        "results": report.results,
    }
    (out_dir / "calibration_report.json").write_text(json.dumps(report_data, indent=2))
    print(f"\n📄 Report: {out_dir}/calibration_report.json")

    # Summary
    print(f"\n{'='*50}")
    print(f"Calibration: {report.passed}/{report.total} passed")
    print(f"  Clean: {report.clean_passed}/{report.clean_total}")
    print(f"  Vuln:  {report.vuln_passed}/{report.vuln_total}")
    print(f"  Blocking FPs: {report.blocking_fps}")
    print(f"  Missed: {report.missed_expected}")
    print(f"  Redaction leaks: {report.redaction_leaks}")
    print(f"  Duration: {report.duration_seconds:.0f}s")

    if fail_on_regression and report.failed > 0:
        print(f"\n❌ REGRESSION: {report.failed} project(s) failed")
        return 1
    return 0


def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC Calibration Runner v0.14")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run calibration")
    run.add_argument("--dataset", default=str(CALIB_DIR / "calibration_dataset.json"))
    run.add_argument("--format", default="json")
    run.add_argument("--fail-on-regression", action="store_true")

    check = sub.add_parser("check", help="Quick check — do clean projects produce blocking?")
    check.add_argument("--dataset", default=str(CALIB_DIR / "calibration_dataset.json"))

    args = p.parse_args()

    if args.command in ("run", "check"):
        fail = getattr(args, 'fail_on_regression', args.command == "check")
        sys.exit(run_calibration(args.dataset, fail, getattr(args, 'format', 'json')))


if __name__ == "__main__":
    main()
