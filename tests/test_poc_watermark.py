"""Tests for PoC watermarking (dual-use mitigation)."""
from gsc_poc_watermark import compute_poc_id, watermark_poc, watermark_findings


def test_compute_poc_id_stable():
    f1 = {"rule_id": "GS005", "file_path": "a.py", "line": 10, "finding_key": "abc"}
    f2 = {"rule_id": "GS005", "file_path": "a.py", "line": 10, "finding_key": "abc"}
    assert compute_poc_id(f1) == compute_poc_id(f2)
    assert len(compute_poc_id(f1)) == 12


def test_compute_poc_id_differs_by_file():
    a = compute_poc_id({"rule_id": "GS005", "file_path": "a.py", "line": 10})
    b = compute_poc_id({"rule_id": "GS005", "file_path": "b.py", "line": 10})
    assert a != b


def test_watermark_poc_adds_banner_and_id():
    f = {"rule_id": "GS005", "file_path": "a.py", "line": 10}
    poc_id = compute_poc_id(f)
    out = watermark_poc("curl -s http://x", f, poc_id)
    assert "AUTHORIZED SECURITY TESTING ONLY" in out
    assert poc_id in out
    assert out.startswith("#")
    assert out.rstrip().endswith("curl -s http://x")


def test_watermark_poc_idempotent():
    f = {"rule_id": "GS005", "file_path": "a.py", "line": 10}
    poc_id = compute_poc_id(f)
    once = watermark_poc("curl -s http://x", f, poc_id)
    twice = watermark_poc(once, f, poc_id)
    assert once == twice


def test_watermark_findings_attaches_metadata():
    findings = [
        {"rule_id": "GS005", "file_path": "a.py", "line": 10,
         "metadata": {"poc": "curl -s http://x"}},
        {"rule_id": "GS020", "file_path": "b.py", "line": 5},  # no poc
    ]
    watermark_findings(findings)
    assert findings[0]["metadata"]["poc_watermark"] is True
    assert "poc_watermark_id" in findings[0]["metadata"]
    assert len(findings[0]["metadata"]["poc_watermark_id"]) == 12
    assert "AUTHORIZED" in findings[0]["metadata"]["poc"]
    # finding without poc stays untouched
    assert "poc_watermark" not in findings[1].get("metadata", {})


def test_watermark_findings_skips_empty_poc():
    findings = [{"rule_id": "GS005", "file_path": "a.py", "line": 1, "metadata": {}}]
    watermark_findings(findings)
    assert "poc_watermark" not in findings[0]["metadata"]
