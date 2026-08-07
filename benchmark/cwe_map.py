#!/usr/bin/env python3
"""CWE → GSC rule mapping for OWASP Benchmark (v0.31).

Derived from COMPLIANCE_MAP — single source of truth.
CWE without a detector → honest uncovered gap.
"""
from typing import Dict, List
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_compliance import COMPLIANCE_MAP

OWASP_CWES = {
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-90":  "LDAP Injection",
    "CWE-134": "Format String",
    "CWE-259": "Hardcoded Password",
    "CWE-327": "Broken/Risky Crypto",
    "CWE-501": "Trust Boundary Violation",
    "CWE-614": "Sensitive Cookie w/o Secure Flag",
    "CWE-643": "XPath Injection",
}

EXTRA_CWE_RULES = {
    "CWE-78": ["GS004"],
    "CWE-327": [],
}


def build_cwe_to_rules() -> Dict[str, List[str]]:
    """Reverse COMPLIANCE_MAP: CWE → [base rule_ids]."""
    cwe_map: Dict[str, List[str]] = {}
    for rule_id, comp in COMPLIANCE_MAP.items():
        cwe = comp.get("cwe")
        if cwe:
            base = rule_id.split("-")[0]
            cwe_map.setdefault(cwe, [])
            if base not in cwe_map[cwe]:
                cwe_map[cwe].append(base)
    for cwe, rules in EXTRA_CWE_RULES.items():
        if cwe not in cwe_map and rules:
            cwe_map[cwe] = rules
    return cwe_map


def coverage_report(cwe_map: Dict[str, List[str]]) -> dict:
    """Honest coverage: which OWASP CWEs are covered/not."""
    covered, uncovered = [], []
    for cwe, desc in OWASP_CWES.items():
        if cwe_map.get(cwe):
            covered.append({"cwe": cwe, "desc": desc, "rules": cwe_map[cwe]})
        else:
            uncovered.append({"cwe": cwe, "desc": desc})
    return {
        "total_owasp_cwes": len(OWASP_CWES),
        "covered": covered,
        "uncovered": uncovered,
        "coverage_pct": round(100.0 * len(covered) / len(OWASP_CWES), 1),
    }
