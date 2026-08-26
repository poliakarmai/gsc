#!/usr/bin/env python3
"""Tests for scripts/gsc_perf_benchmark.py — patch micro-benchmark."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
)

from gsc_perf_benchmark import (  # noqa: E402
    measure_perf,
    run_benchmark,
    CPU_REGRESSION_THRESHOLD_MS,
    MEMORY_REGRESSION_THRESHOLD_KB,
)


def test_measure_perf_returns_metrics():
    result = measure_perf(lambda: None, iterations=5)
    assert "cpu_time_ms" in result
    assert "peak_memory_kb" in result
    assert result["cpu_time_ms"] >= 0


def test_run_benchmark_classifies_verdict():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "sample.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        patch = [{"find": "return 1", "replace": "return 2"}]
        result = run_benchmark(f, patch, iterations=3)
        assert result["verdict"] in ("safe", "safe but slow", "regression")
        assert "cpu_delta_ms" in result
        assert "mem_delta_kb" in result


def test_thresholds_are_positive():
    assert CPU_REGRESSION_THRESHOLD_MS > 0
    assert MEMORY_REGRESSION_THRESHOLD_KB > 0
