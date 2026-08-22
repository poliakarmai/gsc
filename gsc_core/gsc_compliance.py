#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Compliance Mapping v1.0 (v0.29).

Maps every GSC rule_id to industry standards:
  CWE (MITRE), OWASP Top 10 2021, PCI-DSS v4.0.

Enriched into every finding + SARIF output.
"""

from __future__ import annotations
from typing import Dict

# ── Core mapping table ─────────────────────────────────────
COMPLIANCE_MAP: Dict[str, Dict[str, str]] = {
    # Injection
    "GS001": {"cwe": "CWE-89",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    "GS003": {"cwe": "CWE-215", "owasp": "A05:2021-Misconfig",        "pci": "6.5.10"},
    "GS005": {"cwe": "CWE-89",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    # Access control
    "GS007": {"cwe": "CWE-639", "owasp": "A01:2021-BrokenAccess",     "pci": "6.5.4"},
    "GS019": {"cwe": "CWE-798", "owasp": "A07:2021-Auth",             "pci": "6.5.5"},
    # Secrets / crypto
    "GS014": {"cwe": "CWE-200", "owasp": "A02:2021-CryptoFail",       "pci": "6.5.6"},
    "GS017": {"cwe": "CWE-521", "owasp": "A07:2021-Auth",             "pci": "6.5.5"},
    # SSRF / redirect
    "GS022": {"cwe": "CWE-918", "owasp": "A10:2021-SSRF",             "pci": "6.5.2"},
    "GS021": {"cwe": "CWE-352", "owasp": "A01:2021-BrokenAccess",     "pci": "6.5.4"},
    # Supply chain
    "GS009": {"cwe": "CWE-1104","owasp": "A06:2021-VulnComponents",   "pci": "6.3.2"},
    # AI / LLM
    "GS024": {"cwe": "CWE-77",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    "GS025": {"cwe": "CWE-1188","owasp": "A05:2021-Misconfig",        "pci": "6.5.6"},
    # Invariants / policy
    "GS028": {"cwe": "CWE-693", "owasp": "A05:2021-Misconfig",        "pci": "6.5.10"},
    # SCA / dependencies
    "GS030": {"cwe": "CWE-1104","owasp": "A06:2021-VulnComponents",   "pci": "6.3.2"},
    # Secrets (GS029)
    "GS029": {"cwe": "CWE-798", "owasp": "A02:2021-CryptoFail",       "pci": "6.5.5"},
    # Command injection
    "GS004": {"cwe": "CWE-78",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    # XSS
    "GS020": {"cwe": "CWE-79",  "owasp": "A03:2021-Injection",        "pci": "6.5.7"},
    # General misconfig
    "GS002": {"cwe": "CWE-732", "owasp": "A05:2021-Misconfig",        "pci": "6.5.10"},
    "GS008": {"cwe": "CWE-561", "owasp": "A05:2021-Misconfig",        "pci": "6.5.10"},
    "GS010": {"cwe": "CWE-287", "owasp": "A07:2021-Auth",             "pci": "6.5.5"},
    "GS011": {"cwe": "CWE-347", "owasp": "A07:2021-Auth",             "pci": "6.5.5"},
    "GS012": {"cwe": "CWE-915", "owasp": "A04:2021-InsecureDesign",   "pci": "6.5.10"},
    "GS013": {"cwe": "CWE-77",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    "GS015": {"cwe": "CWE-778", "owasp": "A05:2021-Misconfig",        "pci": "6.5.10"},
    "GS016": {"cwe": "CWE-269", "owasp": "A01:2021-BrokenAccess",     "pci": "6.5.4"},
    "GS018": {"cwe": "CWE-841", "owasp": "A04:2021-InsecureDesign",   "pci": "6.5.10"},
    "GS023": {"cwe": "CWE-367", "owasp": "A04:2021-InsecureDesign",   "pci": "6.5.10"},
    # PII / information disclosure
    "GS040": {"cwe": "CWE-359", "owasp": "A01:2021-BrokenAccess",     "pci": "6.5.4"},
    # Code injection (eval / new Function)
    "GS036": {"cwe": "CWE-95",  "owasp": "A03:2021-Injection",        "pci": "6.5.1"},
    # Unsafe deserialization
    "GS046": {"cwe": "CWE-502", "owasp": "A08:2021-SoftwareDataIntegrityFailures", "pci": "6.5.1"},
}


def _base_rule(rule_id: str) -> str:
    """GS025-permissive_cors → GS025; GS030-PYSEC-2018-58 → GS030."""
    return rule_id.split("-")[0]


def compliance_for(rule_id: str) -> Dict[str, str]:
    """Return {cwe, owasp, pci} for rule_id (with prefix fallback)."""
    if rule_id in COMPLIANCE_MAP:
        return dict(COMPLIANCE_MAP[rule_id])  # return copy
    base = _base_rule(rule_id)
    if base in COMPLIANCE_MAP:
        return dict(COMPLIANCE_MAP[base])
    return {}  # unknown rule — don't fabricate


def enrich_finding(finding: dict) -> dict:
    """Inject compliance into finding.metadata."""
    mapping = compliance_for(finding.get("rule_id", ""))
    if mapping:
        finding.setdefault("metadata", {})["compliance"] = mapping
    return finding


# ── IaC GS031 — CIS Benchmarks ──────────────────────────
COMPLIANCE_MAP.update({
    "GS031-DOCKER-ROOT":       {"cwe": "CWE-250",  "cis": "CIS-Docker-4.1",   "owasp": "A05:2021-Misconfig"},
    "GS031-DOCKER-NO-USER":    {"cwe": "CWE-250",  "cis": "CIS-Docker-4.1",   "owasp": "A05:2021-Misconfig"},
    "GS031-DOCKER-LATEST":     {"cwe": "CWE-1104", "cis": "CIS-Docker-4.7",   "owasp": "A06:2021-VulnComponents"},
    "GS031-DOCKER-SECRET-ENV": {"cwe": "CWE-798",  "cis": "CIS-Docker-5.10",  "owasp": "A02:2021-CryptoFailures"},
    "GS031-K8S-PRIVILEGED":    {"cwe": "CWE-250",  "cis": "CIS-K8s-5.2.1",    "owasp": "A05:2021-Misconfig"},
    "GS031-K8S-CAP-SYS-ADMIN": {"cwe": "CWE-250",  "cis": "CIS-K8s-5.2.1",    "owasp": "A05:2021-Misconfig"},
    "GS031-K8S-HOST-NETWORK":  {"cwe": "CWE-668",  "cis": "CIS-K8s-5.2.4",    "owasp": "A05:2021-Misconfig"},
    "GS031-TF-SG-OPEN":        {"cwe": "CWE-284",  "cis": "CIS-AWS-5.2",      "owasp": "A01:2021-BrokenAccess"},
    "GS031-TF-S3-PUBLIC-ACL":  {"cwe": "CWE-732",  "cis": "CIS-AWS-2.1.1",    "owasp": "A01:2021-BrokenAccess"},
    "GS031-TF-PLAINTEXT-SECRET": {"cwe": "CWE-798","cis": "CIS-AWS-3.1",      "owasp": "A02:2021-CryptoFailures"},
})
