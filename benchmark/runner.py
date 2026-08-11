#!/usr/bin/env python3
"""OWASP Benchmark runner — detector executor (v0.31, fixed for Benchmark Test naming)."""
from pathlib import Path
from typing import List
from benchmark.adapter import TestCase


def _base_rule(rule_id: str) -> str:
    return rule_id.split("-")[0]


def scan_test_case(detectors, test_case: TestCase) -> List[dict]:
    """Run all detectors on one test case via DetectorEntry.detect(ctx).
    
    OWASP Benchmark files are named BenchmarkTest*.java — they match the
    '*Test.java' glob that AuditContext uses to skip test files.
    We bypass this by populating ctx.files directly and using
    read_file which doesn't filter.
    """
    from gsc_detectors import AuditContext

    fp = Path(test_case.file_path)
    # Create context with benchmark-mode bypass
    ctx = AuditContext(project=test_case.test_id, path=fp.parent)
    # Pre-populate files — detectors use get_source_files() which would
    # filter BenchmarkTest*.java as test files via TEST_GLOBS.
    # The GS005 detect() iterates ctx.get_source_files() internally.
    # Fix: set ctx.files and override get_source_files behavior.
    ctx.files = [fp]
    ctx._benchmark_mode = True
    # Override get_source_files to skip test-file filter for benchmark
    _orig_get_source_files = ctx.get_source_files
    ctx.get_source_files = lambda *a, **kw: ctx.files
    try:
        ctx.file_contents[str(fp)] = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass

    findings = []
    for det in detectors:
        if getattr(det, "requires_llm", False):
            continue
        try:
            hits = det.detect(ctx)
            if hits:
                findings.extend(hits)
        except Exception:
            continue
    return findings


def is_detected(findings: List[dict], target_rules: List[str]) -> bool:
    """Test case 'detected' if any finding matches target rules."""
    for f in findings:
        if _base_rule(f.get("rule_id", "")) in target_rules:
            return True
    return False
