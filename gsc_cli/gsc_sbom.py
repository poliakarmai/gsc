#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC SBOM + VEX v1.0 (v0.33).

Generates Software Bill of Materials (CycloneDX 1.5) from dependency manifests,
enriches with VEX (Vulnerability Exploitability eXchange) via SCA/OSV + EPSS.
Builds on gsc_sca + gsc_epss — high leverage, low new code.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

PURL_PREFIX = {
    "PyPI": "pkg:pypi", "npm": "pkg:npm", "Go": "pkg:golang",
    "crates.io": "pkg:cargo", "Maven": "pkg:maven", "RubyGems": "pkg:gem",
}

VEX_AFFECTED = "affected"
VEX_NOT_AFFECTED = "not_affected"


def make_purl(ecosystem: str, name: str, version: Optional[str]) -> str:
    """Package URL: pkg:pypi/requests@2.25.0."""
    prefix = PURL_PREFIX.get(ecosystem, "pkg:generic")
    if ecosystem == "Go":
        return f"{prefix}/{name}@{version or ''}"
    if ecosystem == "npm" and name.startswith("@"):
        name = name.replace("@", "%40", 1)
    ver = f"@{version}" if version else ""
    return f"{prefix}/{name.lower()}{ver}"


def component_id(purl: str) -> str:
    return hashlib.sha256(purl.encode()).hexdigest()[:16]


def generate_sbom(packages: List, tool_version: str = "0.33", licenses: Optional[Dict] = None) -> dict:
    """CycloneDX 1.5 SBOM from Package list (gsc_sca.Package)."""
    components = []
    seen = set()
    for p in packages:
        purl = make_purl(p.ecosystem, p.name, p.version)
        if purl in seen:
            continue
        seen.add(purl)
        comp = {
            "type": "library", "bom-ref": component_id(purl),
            "name": p.name, "version": p.version or "", "purl": purl,
        }
        if licenses:
            lic = licenses.get(f"{p.ecosystem}:{p.name.lower()}")
            if lic:
                comp["licenses"] = [{"license": {"id": lic}}]
        components.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "GSC", "name": "gsc-sbom", "version": tool_version}],
        },
        "components": components,
    }


def enrich_vex(sbom: dict, sca_findings: List[dict], epss_data: dict) -> dict:
    """Add vulnerabilities (VEX) to SBOM. sca_findings from gsc_sca, epss from gsc_epss."""
    vulns = []
    for f in sca_findings:
        sca = f.get("metadata", {}).get("sca", {})
        cve = sca.get("vuln_id", "")
        package = sca.get("package", "")
        ecosystem = sca.get("ecosystem", "")
        purl = make_purl(ecosystem, package, sca.get("current_version"))
        epss = epss_data.get(cve, {})
        epss_score = epss.get("epss", 0.0)
        priority = "critical" if epss_score >= 0.7 else "high" if epss_score >= 0.3 else "medium"
        vulns.append({
            "id": cve,
            "source": {"name": "OSV", "url": f"https://osv.dev/{cve}"},
            "ratings": [{"severity": f.get("severity", "medium").lower(), "method": "other"}],
            "affects": [{"ref": component_id(purl)}],
            "analysis": {"state": VEX_AFFECTED, "detail": f"EPSS={epss_score:.3f}"},
            "properties": [
                {"name": "gsc:epss", "value": f"{epss_score:.4f}"},
                {"name": "gsc:priority", "value": priority},
                {"name": "gsc:fixed_version", "value": sca.get("fixed_version", "")},
            ],
        })
    sbom["vulnerabilities"] = vulns
    return sbom
