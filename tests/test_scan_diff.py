"""Tests for scan-diff (gsc_scan_diff) and JUnit export (gsc.export_junit)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_scan_diff import diff_scans, diff_summary, _identity, _severity


def _f(rule, file, line, title, sev):
    return {"rule_id": rule, "file_path": file, "line_number": line,
            "title": title, "category": sev}


def test_new_and_fixed():
    b = [_f("GS001", "a.py", 1, "secret", "HIGH")]
    c = [_f("GS001", "a.py", 1, "secret", "HIGH"),
         _f("GS020", "b.py", 2, "ssti", "CRITICAL")]
    r = diff_scans(b, c)
    assert len(r["new"]) == 1
    assert len(r["fixed"]) == 0
    assert len(r["unchanged"]) == 1
    assert diff_summary(r) == {"new": 1, "fixed": 0, "severity_changed": 0, "unchanged": 1}


def test_fixed():
    b = [_f("GS001", "a.py", 1, "secret", "HIGH"),
         _f("GS020", "b.py", 2, "ssti", "CRITICAL")]
    c = [_f("GS020", "b.py", 2, "ssti", "CRITICAL")]
    r = diff_scans(b, c)
    assert len(r["fixed"]) == 1
    assert r["fixed"][0]["rule_id"] == "GS001"


def test_severity_changed():
    b = [_f("GS001", "a.py", 1, "s", "LOW")]
    c = [_f("GS001", "a.py", 1, "s", "CRITICAL")]
    r = diff_scans(b, c)
    assert len(r["severity_changed"]) == 1
    assert r["severity_changed"][0]["from_severity"] == "LOW"
    assert r["severity_changed"][0]["to_severity"] == "CRITICAL"


def test_identity_ignores_severity():
    assert _identity(_f("GS001", "a.py", 1, "s", "LOW")) == \
           _identity(_f("GS001", "a.py", 1, "s", "CRITICAL"))


def test_junit_export():
    import gsc
    c = [_f("GS001", "a.py", 1, "secret", "HIGH"),
         _f("GS020", "b.py", 2, "ssti", "CRITICAL")]
    x = gsc.export_junit(c, "demo")
    assert x.startswith("<?xml")
    assert '<testsuite name="GSC-demo" tests="2" failures="2"' in x
    assert "GSC.HIGH" in x and "GSC.CRITICAL" in x
    assert "<failure" in x
