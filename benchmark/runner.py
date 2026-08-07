#!/usr/bin/env python3
"""OWASP Benchmark runner — detector executor (v0.31)."""
from pathlib import Path
from typing import List
from benchmark.adapter import TestCase


def _base_rule(rule_id: str) -> str:
    return rule_id.split("-")[0]


def scan_test_case(detectors, test_case: TestCase) -> List[dict]:
    """Run all regex detectors on one test case."""
    try:
        content = Path(test_case.file_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    findings = []
    for detector in detectors:
        if getattr(detector, "requires_llm", False):
            continue
        try:
            hits = detector.detect(test_case.file_path, content, "java")
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
