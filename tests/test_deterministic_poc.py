"""Tests for deterministic PoC coverage across all corpus vulnerability classes."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_poc_deterministic import get_deterministic_poc, attach_deterministic_pocs


def test_rule_id_mapping():
    expected = {
        "GS004": "command_injection",
        "GS005": "sql_injection",
        "GS007": "idor",
        "GS020": "xss",
        "GS021": "ssrf",
        "GS022": "open_redirect",
    }
    for rid, kind in expected.items():
        poc = get_deterministic_poc(rid)
        assert poc is not None, f"{rid} should have a deterministic PoC"
        assert poc.kind == kind, f"{rid} → {poc.kind}, expected {kind}"


def test_gs037_title_fallback():
    cases = {
        "SSTI via render_template_string with user input": "ssti",
        "pickle.load() — unsafe deserialization": "deserialization",
        "XXE via feature_external_ges": "xxe",
        "path traversal via os.path.join": "path_traversal",
    }
    for title, kind in cases.items():
        poc = get_deterministic_poc("GS037", title)
        assert poc is not None, f"GS037 {title} should fall back to a PoC"
        assert poc.kind == kind, f"GS037 {title} → {poc.kind}, expected {kind}"


def test_no_poc_for_unsupported():
    assert get_deterministic_poc("GS001", "hardcoded secret") is None
    assert get_deterministic_poc("GS029", "random thing") is None


def test_attach_all_classes():
    findings = [
        {"rule_id": "GS004", "title": "cmd", "file_path": "a.py"},
        {"rule_id": "GS005", "title": "sqli", "file_path": "b.py"},
        {"rule_id": "GS020", "title": "xss", "file_path": "c.py"},
        {"rule_id": "GS037", "title": "SSTI via render_template_string", "file_path": "d.py"},
        {"rule_id": "GS001", "title": "secret", "file_path": "e.py"},
    ]
    attach_deterministic_pocs(findings)
    attached = [f for f in findings if f.get("metadata", {}).get("poc")]
    assert len(attached) == 4, f"expected 4 PoC-attached findings, got {len(attached)}"
    assert findings[4].get("metadata", {}).get("poc") is None  # GS001 has no deterministic PoC
