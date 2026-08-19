"""Tests for GSC SAST↔DAST correlation engine (Solar appScreener-style)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_correlation import (
    correlate_sast_dast,
    rule_to_class,
    dast_to_class,
)


# ── rule_to_class ────────────────────────────────────────────────────────────

def test_rule_to_class_prefix():
    expected = {
        "GS004": "command_injection",
        "GS005": "sql_injection",
        "GS007": "idor",
        "GS020": "xss",
        "GS021": "ssrf",
        "GS022": "open_redirect",
        "GS024": "sql_injection",
        "YAML-SSTI001": "ssti",
        "YAML-A7E2F001": "command_injection",
    }
    for rid, cls in expected.items():
        assert rule_to_class(rid) == cls, f"{rid} → {cls}"


def test_rule_to_class_keyword_fallback():
    # составные rule_id, где класс виден из самого id
    assert rule_to_class("GS025-command_injection") == "command_injection"


def test_rule_to_class_title_fallback():
    # языковые детекторы GS035–GS039: класс виден только из title
    assert rule_to_class("GS037", "SSTI via render_template_string with user input") == "ssti"
    assert rule_to_class("GS037", "pickle.load() unsafe deserialization") == "deserialization"
    assert rule_to_class("GS035", "XXE via external entity") == "xxe"
    assert rule_to_class("GS036", "path traversal via os.path.join") == "path_traversal"


def test_rule_to_class_unsupported():
    # hardcoded secret / dead code / weak passwords — DAST не подтверждает
    assert rule_to_class("GS001", "hardcoded secret") is None
    assert rule_to_class("GS008", "dead code") is None
    assert rule_to_class("", "") is None


# ── dast_to_class ────────────────────────────────────────────────────────────

def test_dast_to_class_from_template_id():
    assert dast_to_class({"template_id": "CVE-2021-XXXX-sqli"}) == "sql_injection"
    assert dast_to_class({"template_id": "generic-xss"}) == "xss"
    assert dast_to_class({"template_id": "ssrf-aws-metadata"}) == "ssrf"


def test_dast_to_class_from_tags_and_name():
    assert dast_to_class({"template_id": "abc", "name": "Open Redirect"}) == "open_redirect"
    assert dast_to_class({"template_id": "abc", "tags": ["ssti", "rce"]}) == "ssti"


def test_dast_to_class_empty():
    assert dast_to_class({}) is None
    assert dast_to_class(None) is None


# ── correlate_sast_dast ──────────────────────────────────────────────────────

def test_correlate_confirms_matching_class():
    sast = [
        {"rule_id": "GS005", "title": "SQL injection", "file_path": "a.py",
         "finding_key": "k1", "confidence": 0.55, "review_status": "likely"},
        {"rule_id": "GS001", "title": "secret", "file_path": "b.py",
         "finding_key": "k2", "confidence": 0.5, "review_status": "uncertain"},
    ]
    dast = [
        {"template_id": "sqli-login-bypass", "severity": "high",
         "evidence": "error-based SQLi", "matched_at": "http://t/login"},
    ]
    res = correlate_sast_dast(sast, dast)

    f1, f2 = res["findings"]
    # GS005 совпал по классу sql_injection → confirmed + evidence + confidence
    assert f1["review_status"] == "confirmed"
    assert f1["metadata"]["correlated_dast"] is True
    assert f1["metadata"]["dast_template_id"] == "sqli-login-bypass"
    assert f1["metadata"]["dast_evidence"] == "error-based SQLi"
    assert f1["confidence"] >= 0.90
    # GS001 не коррелируется → статус не тронут
    assert f2["review_status"] == "uncertain"
    assert f2["metadata"].get("correlated_dast") is not True

    assert res["summary"]["confirmed_by_dast"] == 1
    assert len(res["summary"]["matched_pairs"]) == 1


def test_correlate_ignores_info_severity_dast():
    sast = [{"rule_id": "GS020", "title": "xss", "file_path": "c.py"}]
    dast = [{"template_id": "xss-reflected", "severity": "info", "evidence": ""}]
    res = correlate_sast_dast(sast, dast)
    assert res["summary"]["confirmed_by_dast"] == 0
    assert res["findings"][0].get("review_status") != "confirmed"


def test_correlate_no_match_leaves_status():
    sast = [{"rule_id": "GS005", "title": "SQLi", "file_path": "a.py",
             "review_status": "likely", "confidence": 0.6}]
    dast = [{"template_id": "xss-whatever", "severity": "high"}]
    res = correlate_sast_dast(sast, dast)
    assert res["summary"]["confirmed_by_dast"] == 0
    assert res["findings"][0]["review_status"] == "likely"


def test_correlate_does_not_mutate_inputs():
    sast = [{"rule_id": "GS005", "title": "SQLi", "file_path": "a.py",
             "metadata": {"poc": "x"}, "confidence": 0.5}]
    dast = [{"template_id": "sqli", "severity": "high", "evidence": "e"}]
    sast_copy = [dict(sast[0]), dict(sast[0].get("metadata", {}))]
    correlate_sast_dast(sast, dast)
    # исходная находка и её metadata не мутированы
    assert sast[0]["metadata"] == {"poc": "x"}
    assert sast[0].get("review_status") is None
    assert sast[0]["confidence"] == 0.5


def test_correlate_title_fallback_for_language_detector():
    sast = [{"rule_id": "GS037", "title": "SSTI via render_template_string",
             "file_path": "app.py", "finding_key": "k"}]
    dast = [{"template_id": "ssti-jinja2", "severity": "critical", "evidence": "49"}]
    res = correlate_sast_dast(sast, dast)
    assert res["summary"]["confirmed_by_dast"] == 1
    assert res["findings"][0]["review_status"] == "confirmed"
    assert res["findings"][0]["metadata"]["dast_evidence"] == "49"
