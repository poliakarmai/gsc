"""Tests for GSC STIX 2.1 export (gsc_stix_export)."""

import json
from pathlib import Path

import pytest

from gsc_cli.gsc_stix_export import export_scan, _stix_id


def _write_report(tmp_path, findings):
    report = tmp_path / "scan.json"
    report.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(report)


def _load_bundle(out_path):
    return json.loads(Path(out_path).read_text(encoding="utf-8"))


def test_bundle_structure(tmp_path):
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "Hardcoded secret", "file_path": "app.py", "line": 10, "detail": "Found: sk-x"},
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW",
         "title": "console.log", "file_path": "app.js", "line": 5, "detail": "console.log(x)"},
    ])
    out = tmp_path / "bundle.json"
    assert export_scan(report, str(out)) == 0
    bundle = _load_bundle(out)
    assert bundle["type"] == "bundle"
    # STIX 2.1: the bundle itself carries no spec_version (a spec_version on the
    # bundle is misdetected as STIX 2.0 by the official parser).
    assert "spec_version" not in bundle
    types = {o["type"] for o in bundle["objects"]}
    assert types >= {"report", "indicator", "vulnerability"}
    for o in bundle["objects"]:
        assert o.get("spec_version") == "2.1"


def test_stix2_parser_accepts_bundle(tmp_path):
    stix2 = pytest.importorskip("stix2")
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "Hardcoded secret", "file_path": "app.py", "line": 10, "detail": "Found: sk-x"},
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW",
         "title": "console.log", "file_path": "app.js", "line": 5, "detail": "console.log(x)"},
    ])
    out = tmp_path / "bundle.json"
    export_scan(report, str(out))
    bundle = _load_bundle(out)
    parsed = stix2.parse(bundle, allow_custom=True)  # auto-detect version
    assert len(parsed.objects) == 3  # report + 2 findings
    for o in parsed.objects:
        assert o.spec_version == "2.1"


def test_secret_becomes_indicator_with_pattern(tmp_path):
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "Hardcoded secret", "file_path": "app.py", "line": 10, "detail": "Found: sk-x"},
    ])
    out = tmp_path / "bundle.json"
    export_scan(report, str(out))
    bundle = _load_bundle(out)
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[file:name = 'app.py']"
    assert ind["pattern_type"] == "stix"
    assert ind["x_gsc_rule_id"] == "GS001"
    assert ind["x_gsc_severity"] == "CRITICAL"


def test_deterministic_stix_id():
    a = _stix_id("vulnerability", "abc123")
    b = _stix_id("vulnerability", "abc123")
    assert a == b
    assert a.startswith("vulnerability--")


def test_severity_filter(tmp_path):
    report = _write_report(tmp_path, [
        {"rule_id": "GS001", "severity": "CRITICAL", "category": "CRITICAL",
         "title": "s", "file_path": "a.py", "detail": "d"},
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW",
         "title": "l", "file_path": "b.js", "detail": "d"},
    ])
    out = tmp_path / "bundle.json"
    export_scan(report, str(out), severity="critical")
    bundle = _load_bundle(out)
    findings = [o for o in bundle["objects"] if o["type"] != "report"]
    assert [f["x_gsc_rule_id"] for f in findings] == ["GS001"]


def test_report_refs_all_findings(tmp_path):
    report = _write_report(tmp_path, [
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW", "title": "t", "file_path": "a.js", "detail": "d"},
        {"rule_id": "GS003", "severity": "LOW", "category": "LOW", "title": "t", "file_path": "b.js", "detail": "d"},
    ])
    out = tmp_path / "bundle.json"
    export_scan(report, str(out))
    bundle = _load_bundle(out)
    report_obj = next(o for o in bundle["objects"] if o["type"] == "report")
    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(report_obj["object_refs"]) == len(vulns) == 2
