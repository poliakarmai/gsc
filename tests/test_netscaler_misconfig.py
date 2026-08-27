# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for YAML-NETSCALER001 — Citrix NetScaler misconfiguration surface."""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_core.gsc_detectors.yaml_rules import netscaler_misconfig as mod
from gsc_core.gsc_detectors.yaml_rules.netscaler_misconfig import (
    RULE_ID,
    ECHELON,
    NOISE_TIER,
    description,
    detector,
    detect,
)


# ── Metadata ────────────────────────────────────────────────────────────────

def test_rule_id_is_netscaler001():
    assert RULE_ID == "YAML-NETSCALER001"


def test_echelon_and_noise_tier():
    assert ECHELON == 2
    assert NOISE_TIER == "precise"


def test_description_mentions_cves():
    assert isinstance(description, str)
    assert "CVE-2026-19490" in description
    assert "CVE-2026-19489" in description
    assert "auth" in description.lower()


def test_detector_metadata():
    assert detector.severity == "HIGH"
    assert 0.0 < detector.confidence <= 1.0
    assert detector.rule_id == RULE_ID
    assert detector.name == "netscaler-misconfig"


def test_patterns_count_at_least_four():
    assert len(detector._compiled) >= 4


def test_every_pattern_has_title():
    for pattern, title in detector._compiled:
        assert title, f"pattern {pattern.pattern!r} is missing a human title"


# ── True positives per config line ──────────────────────────────────────────

def test_saml_action_flags():
    content = "add authentication samlAction SAML_ACTION1\n"
    findings = detect("ns.conf", content, "text")
    assert findings, "expected a finding for SAML action"
    assert findings[0]["rule_id"] == RULE_ID
    assert findings[0]["severity"] == "HIGH"
    assert "SAML action" in findings[0]["title"]


def test_authentication_vserver_flags():
    content = "add authentication vserver auth_vs 0.0.0.0\n"
    findings = detect("ns.conf", content, "text")
    assert findings, "expected a finding for authentication vserver"
    assert "authentication vserver" in findings[0]["title"]


def test_vpn_vserver_flags():
    content = "add vpn vserver vpn1 SSL 1.1.1.1 443\n"
    findings = detect("ns.conf", content, "text")
    assert findings, "expected a finding for VPN vserver"
    assert "VPN vserver" in findings[0]["title"]


def test_sip_alg_lsn_group_flags():
    content = "add lsn group LSN-GROUP-1 -sipalg ENABLED\n"
    findings = detect("ns.conf", content, "text")
    assert findings, "expected a finding for SIP ALG in LSN group"
    assert "SIP ALG" in findings[0]["title"]


def test_bind_vpn_vserver_flags():
    content = "bind vpn vserver vpn1 -policy p1\n"
    findings = detect("ns.conf", content, "text")
    assert findings, "expected a finding for bind vpn vserver"
    assert "VPN vserver" in findings[0]["title"]


# ── Multiple findings / line numbers ────────────────────────────────────────

def test_multiple_findings():
    content = (
        "add authentication samlAction SAML_MULTI\n"
        "add vpn vserver vpn_multi SSL 1.1.1.1 443\n"
    )
    findings = detect("ns.conf", content, "text")
    assert len(findings) == 2
    titles = " ".join(f["title"] for f in findings)
    assert "SAML action" in titles
    assert "VPN vserver" in titles
    assert all(f["rule_id"] == RULE_ID for f in findings)


def test_line_number_is_correct():
    content = (
        "# comment line\n"
        "some other config\n"
        "add authentication samlAction SAML_LINE\n"
    )
    findings = detect("ns.conf", content, "text")
    assert findings
    assert findings[0]["line_number"] == 3
    assert findings[0]["file_path"] == "ns.conf"


def test_finding_shape():
    content = "add vpn vserver vpn1 SSL 1.1.1.1 443\n"
    findings = detect("ns.conf", content, "text")
    f = findings[0]
    assert isinstance(f["line_number"], int) and f["line_number"] >= 1
    assert f["file_path"] == "ns.conf"
    assert f["rule_id"] == RULE_ID
    assert f["title"]
    assert isinstance(f.get("detail") or f.get("snippet") or "", str)


# ── Clean / robustness ──────────────────────────────────────────────────────

def test_unrelated_config_no_finding():
    content = "add lb vserver lb_vs HTTP 1.2.3.4 80\n"
    findings = detect("ns.conf", content, "text")
    assert findings == []


def test_commented_line_not_flagged():
    content = "# add vpn vserver vpn1 SSL 1.1.1.1 443\n"
    findings = detect("ns.conf", content, "text")
    assert findings == []


def test_commented_saml_action_not_flagged():
    content = "# add authentication samlAction SAML_DISABLED\n"
    findings = detect("ns.conf", content, "text")
    assert findings == []


def test_empty_content_no_finding():
    assert detect("ns.conf", "", "text") == []


def test_whitespace_variants_matched():
    # \s+ must tolerate tabs / multiple spaces between tokens
    content = "add\tauthentication    samlAction SAML_WS\n"
    findings = detect("ns.conf", content, "text")
    assert findings
    assert "SAML action" in findings[0]["title"]


# ── Stdlib-only invariant ───────────────────────────────────────────────────

def test_no_external_dependencies():
    src = inspect.getsource(mod)
    forbidden = [
        "import requests", "import urllib", "import socket",
        "import os", "os.environ", "getenv", "open(",
    ]
    for token in forbidden:
        assert token not in src, (
            f"netscaler_misconfig must not touch the outside world; found {token!r}"
        )


def test_detect_signature_parity():
    sig = inspect.signature(detect)
    assert list(sig.parameters) == ["file_path", "content", "language"]
    assert sig.parameters["language"].default == "auto"
