#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""
GSC STIX Export — GSC findings -> STIX 2.1 Bundle.

Exports a GSC scan report as a STIX 2.1 JSON bundle consumable by threat-intel
platforms (MISP, OpenCTI, TheHive, any TAXII/STIX consumer).

Mapping:
  - SAST/SCA/DAST findings              -> `vulnerability` SDO
  - hardcoded secrets / IOCs (GS001/GS029/GS034) -> `indicator` SDO
  - one summary `report` SDO links every finding (object_refs)

Finding identity (finding_key) is preserved as a deterministic STIX id
(uuid5 of the GSC finding_key) and carried in x_gsc_finding_key.

CLI:
  gsc export-stix scan.json -o gsc-bundle.json
  gsc export-stix scan.json --severity critical,high
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))

try:
    from gsc_signature import DEFAULT_REPO_URL
except Exception:  # pragma: no cover
    DEFAULT_REPO_URL = "https://github.com/poliakarmai/gsc"

STIX_SPEC = "2.1"
_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "gsc://poliakarmai/gsc")

# Rules whose findings are threat *indicators* (leaked credentials / secrets),
# not plain software vulnerabilities.
INDICATOR_RULES = {"GS001", "GS029", "GS034", "GIOC"}  # GIOC = ingested external IOC


# ── helpers ─────────────────────────────────────────────────
def _finding_key(finding: Dict) -> str:
    if finding.get("finding_key"):
        return finding["finding_key"]
    raw = (
        f"{finding.get('rule_id', '')}+"
        f"{finding.get('file_path', finding.get('file', ''))}+"
        f"{finding.get('detail', '')[:80]}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _stix_id(obj_type: str, seed: str) -> str:
    return f"{obj_type}--{uuid.uuid5(_UUID_NS, f'gsc://{obj_type}/{seed}')}"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _external_refs(finding: Dict) -> List[Dict]:
    refs: List[Dict] = []
    cwe = finding.get("cwe") or finding.get("cwe_id")
    if cwe:
        cwe_s = str(cwe).upper()
        if not cwe_s.startswith("CWE"):
            cwe_s = f"CWE-{cwe_s}"
        num = cwe_s.replace("CWE-", "")
        refs.append({
            "source_name": "cwe",
            "external_id": cwe_s,
            "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
        })
    cve = finding.get("cve")
    if cve:
        refs.append({
            "source_name": "cve",
            "external_id": str(cve).upper(),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        })
    for r in (finding.get("references") or []):
        if isinstance(r, str):
            refs.append({"source_name": "reference", "url": r})
    refs.append({"source_name": "GSC", "url": DEFAULT_REPO_URL})
    return refs


def _description(finding: Dict) -> str:
    parts = [finding.get("title", "") or finding.get("pattern_title", "")]
    detail = finding.get("detail", "") or finding.get("message", "")
    if detail:
        parts.append(detail)
    fix = finding.get("fix_suggestion", "")
    if fix:
        parts.append(f"Fix: {fix}")
    return "\n".join(p for p in parts if p).strip()


# ── object builders ─────────────────────────────────────────
def _base(obj_type: str, key: str, ts: str, finding: Dict) -> Dict:
    sev = str(finding.get("severity", finding.get("category", "INFO"))).upper()
    cat = str(finding.get("category", "unknown")).upper()
    title = (
        finding.get("title")
        or finding.get("pattern_title")
        or finding.get("message")
        or "Security finding"
    )
    name = f"{finding.get('rule_id', 'GS000')} - {title}"
    labels = ["gsc"]
    if cat:
        labels.append(cat.lower())
    if sev:
        labels.append(sev.lower())
    return {
        "type": obj_type,
        "spec_version": STIX_SPEC,
        "id": _stix_id(obj_type, key),
        "created": ts,
        "modified": ts,
        "name": name,
        "description": _description(finding),
        "labels": labels,
        "external_references": _external_refs(finding),
        "x_gsc_rule_id": finding.get("rule_id", ""),
        "x_gsc_severity": sev,
        "x_gsc_category": cat,
        "x_gsc_file_path": finding.get("file_path", finding.get("file", "")),
        "x_gsc_line": finding.get("line", finding.get("line_number", 0)),
        "x_gsc_finding_key": key,
        "x_gsc_echelon": finding.get("echelon", 0),
    }


def _to_vulnerability(finding: Dict, key: str, ts: str) -> Dict:
    return _base("vulnerability", key, ts, finding)


def _to_indicator(finding: Dict, key: str, ts: str) -> Dict:
    obj = _base("indicator", key, ts, finding)
    pattern = finding.get("stix_pattern") or ""
    if pattern:
        # ingested external IOC: preserve the original STIX pattern
        obj["pattern"] = pattern
        obj["pattern_type"] = "stix"
    else:
        path = finding.get("file_path", finding.get("file", "")) or ""
        fname = Path(path).name if path else "unknown"
        obj["pattern"] = f"[file:name = '{fname}']"
        obj["pattern_type"] = "stix"
    obj["valid_from"] = ts
    # preserve the source STIX id on round-trip (external IOC)
    if finding.get("stix_id"):
        obj["id"] = finding["stix_id"]
    return obj


# ── bundle builder ─────────────────────────────────────────
def build_bundle(findings: List[Dict]) -> Dict:
    """Build a STIX 2.1 bundle from GSC findings (no I/O)."""
    ts = _timestamp()
    objects: List[Dict] = []
    refs: List[str] = []

    for finding in findings:
        key = _finding_key(finding)
        rule = str(finding.get("rule_id", ""))
        obj = _to_indicator(finding, key, ts) if rule in INDICATOR_RULES \
            else _to_vulnerability(finding, key, ts)
        objects.append(obj)
        refs.append(obj["id"])

    sev_counts: Dict[str, int] = {}
    for f_ in findings:
        s = str(f_.get("severity", f_.get("category", "unknown"))).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    summary = ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items()))

    report_obj = {
        "type": "report",
        "spec_version": STIX_SPEC,
        "id": _stix_id("report", "gsc-scan"),
        "created": ts,
        "modified": ts,
        "name": "GSC Scan Report",
        "description": f"{len(findings)} findings ({summary})",
        "published": ts,
        "object_refs": refs,
        "labels": ["gsc"],
        "external_references": [{"source_name": "GSC", "url": DEFAULT_REPO_URL}],
    }
    objects.insert(0, report_obj)

    # STIX 2.1: the bundle itself carries NO spec_version (it lives on each
    # object). A spec_version on the bundle would be misread as STIX 2.0 by
    # the official parser's version detection.
    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"gsc-{ts}"),
        "objects": objects,
    }


# ── export ─────────────────────────────────────────────────
def export_scan(
    report_path: str,
    output_path: str = "gsc-stix-bundle.json",
    severity: Optional[str] = None,
    max_items: Optional[int] = None,
) -> int:
    with open(report_path) as f:
        report = json.load(f)
    findings = report.get("findings", []) if isinstance(report, dict) else report

    if severity:
        wanted = {s.strip().lower() for s in severity.split(",") if s.strip()}
        findings = [
            f_ for f_ in findings
            if str(f_.get("severity", f_.get("category", ""))).lower() in wanted
        ]
    if max_items:
        findings = findings[:max_items]

    bundle = build_bundle(findings)

    out = Path(output_path)
    out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")

    n_vuln = sum(1 for o in bundle["objects"] if o.get("type") == "vulnerability")
    n_ind = sum(1 for o in bundle["objects"] if o.get("type") == "indicator")
    print(f"STIX 2.1 bundle -> {out}")
    print(f"  objects: 1 report + {n_vuln} vulnerability + {n_ind} indicator")
    return 0


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="GSC STIX Export — findings -> STIX 2.1 bundle")
    p.add_argument("report", help="GSC scan report JSON")
    p.add_argument("--output", "-o", default="gsc-stix-bundle.json")
    p.add_argument("--severity", "-s", help="Filter: critical,high,medium,low")
    p.add_argument("--max", type=int, default=None)
    args = p.parse_args()
    sys.exit(export_scan(args.report, args.output, args.severity, args.max))


if __name__ == "__main__":
    main()
