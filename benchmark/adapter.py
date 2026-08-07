#!/usr/bin/env python3
"""OWASP Benchmark adapter — CSV parser + test case loader (v0.31)."""
import csv, re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class TestCase:
    test_id: str
    file_path: str
    cwe: str
    is_vulnerable: bool


def parse_expected_csv(csv_path: str) -> Dict[str, Tuple[bool, str]]:
    """Parse OWASP expected results: {test_id: (is_vulnerable, cwe)}."""
    expected = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            test_id = row[0].strip()
            if not test_id.startswith("BenchmarkTest"):
                continue
            is_vuln = None
            cwe_num = None
            for cell in row[1:]:
                c = cell.strip().lower()
                if c in ("true", "false") and is_vuln is None:
                    is_vuln = (c == "true")
                elif c.isdigit() and cwe_num is None and 1 <= int(c) <= 1000:
                    cwe_num = c
            if is_vuln is not None and cwe_num is not None:
                expected[test_id] = (is_vuln, f"CWE-{cwe_num}")
    return expected


def parse_owasp_benchmark(benchmark_root: str, expected_csv: str) -> List[TestCase]:
    """Collect TestCases from benchmark + expected labels."""
    expected = parse_expected_csv(expected_csv)
    root = Path(benchmark_root)
    test_dir = root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    candidates = list(test_dir.glob("BenchmarkTest*.java")) if test_dir.exists() else \
                 list(root.rglob("BenchmarkTest*.java"))

    test_cases = []
    for java_file in candidates:
        test_id = java_file.stem
        if test_id not in expected:
            continue
        is_vuln, cwe = expected[test_id]
        test_cases.append(TestCase(
            test_id=test_id, file_path=str(java_file),
            cwe=cwe, is_vulnerable=is_vuln))
    return test_cases
