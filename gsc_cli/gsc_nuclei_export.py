#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Nuclei Export v1.0 — PoC → nuclei YAML converter.

Wave 1 of nuclei integration: exports GSC findings as nuclei-compatible
YAML templates for DAST validation on staging/production.

Refined version — curl/Python parsing + SUCCESS_MARKERS + fallbacks.

CLI:
  gsc export-nuclei scan.json -o nuclei-templates/
  nuclei -t nuclei-templates/ -u https://staging.example.com
"""

from __future__ import annotations

import json, re, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except ImportError:
    print("Install: pip install pyyaml"); sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))
from gsc_poc_generator import SUCCESS_MARKERS
from gsc_signature import DEFAULT_REPO_URL


@dataclass
class NucleiTemplate:
    id: str
    name: str
    severity: str
    description: str
    requests: List[Dict]

    def to_yaml(self) -> str:
        template = {
            "id": self.id,
            "info": {
                "name": self.name,
                "author": "gsc-auto",
                "severity": self.severity.lower(),
                "description": self.description,
                "tags": "gsc,sast," + self.severity.lower(),
                "reference": [DEFAULT_REPO_URL],
            },
            "requests": self.requests,
        }
        return yaml.dump(template, default_flow_style=False, allow_unicode=True,
                         sort_keys=False, width=120)


# ── PoC parsers ────────────────────────────────────────────
def _parse_curl_command(poc_code: str) -> Optional[Dict]:
    """Extract HTTP request from curl command."""
    method_match = re.search(r"-X\s+(GET|POST|PUT|DELETE)", poc_code, re.IGNORECASE)
    method = method_match.group(1).upper() if method_match else "GET"
    if " -d " in poc_code or "--data" in poc_code:
        method = "POST"

    url_match = re.search(r"(https?://[^\s'\"]+)", poc_code)
    if not url_match:
        # Try without protocol: curl example.com/api
        url_match = re.search(r"curl\s+['\"]?([a-zA-Z0-9.-]+/[^\s'\"]+)", poc_code)
        if not url_match:
            return None
        url = "http://" + url_match.group(1)
    else:
        url = url_match.group(1)

    # Replace domain with nuclei placeholder
    url = re.sub(r"https?://[^/]+", "{{BaseURL}}", url)

    headers = {}
    for h in re.findall(r'-H\s+["\']([^"\']+)["\']', poc_code):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    data_match = re.search(r"-d\s+'([^']+)'", poc_code) or re.search(r'-d\s+"([^"]+)"', poc_code)
    body = data_match.group(1) if data_match else None

    request = {"method": method, "path": [url]}
    if headers:
        request["headers"] = headers
    if body:
        request["body"] = body
    return request


def _parse_python_requests(poc_code: str) -> Optional[Dict]:
    """Extract HTTP request from Python requests code."""
    method_match = re.search(r"requests\.(get|post|put|delete)\(", poc_code, re.IGNORECASE)
    if not method_match:
        return None
    method = method_match.group(1).upper()

    url_match = re.search(r'["\'](https?://[^"\']+)["\']', poc_code)
    if not url_match:
        return None
    url = url_match.group(1)
    url = re.sub(r"https?://[^/]+", "{{BaseURL}}", url)

    params_match = re.search(r'params=\{([^}]+)\}', poc_code)
    params = params_match.group(1) if params_match else ""

    data_match = re.search(r'json=\{([^}]+)\}', poc_code)
    body = data_match.group(1) if data_match else None

    path = url
    if params and method == "GET":
        param_pairs = re.findall(r'["\']([^"\']+)["\']:\s*["\']([^"\']+)["\']', params)
        if param_pairs:
            query = "&".join(f"{k}={v}" for k, v in param_pairs)
            path = f"{url}?{query}"

    request = {"method": method, "path": [path]}
    if body:
        request["body"] = body
    return request


def _extract_markers(poc_code: str) -> List[str]:
    """Extract SUCCESS_MARKERS from PoC code."""
    markers = []
    for marker in SUCCESS_MARKERS:
        if marker in poc_code.upper():
            markers.append(marker)
    return markers if markers else ["VULNERABLE"]  # fallback


# ── Export ─────────────────────────────────────────────────
def export_finding_to_nuclei(finding: Dict, poc_code: str) -> Optional[NucleiTemplate]:
    """Convert GSC finding + PoC to nuclei template."""
    request = _parse_curl_command(poc_code)
    if not request:
        request = _parse_python_requests(poc_code)
    if not request:
        return None  # unparseable PoC — skip

    markers = _extract_markers(poc_code)
    request["matchers"] = [{
        "type": "word",
        "words": markers,
        "condition": "or",
    }]

    import hashlib
    raw = f"{finding.get('rule_id','')}+{finding.get('file_path',finding.get('file',''))}+{finding.get('detail','')[:80]}"
    finding_key = finding.get("finding_key") or hashlib.sha256(raw.encode()).hexdigest()[:12]

    template = NucleiTemplate(
        id=f"gsc-{finding_key}",
        name=f"{finding.get('rule_id', 'GS000')} - {finding.get('title', 'Security Issue')}",
        severity=finding.get("severity", finding.get("category", "medium")).lower(),
        description=(
            f"GSC detected {finding.get('rule_id', '?')} in "
            f"{finding.get('file_path', finding.get('file', '?'))}:{finding.get('line', finding.get('line_number', '?'))}\n"
            f"Confidence: {finding.get('confidence', 0):.2f}\n"
            f"Auto-generated PoC for nuclei validation."
        ),
        requests=[request],
    )
    return template


def export_scan_to_nuclei(report: Dict) -> List[NucleiTemplate]:
    """Export all findings with PoC from report to nuclei templates."""
    templates = []
    for finding in report.get("findings", []):
        poc = ""
        metadata = finding.get("metadata", {})
        if isinstance(metadata, dict):
            poc = metadata.get("poc", "")
        if not poc:
            continue
        template = export_finding_to_nuclei(finding, poc)
        if template:
            templates.append(template)
    return templates


def export_scan(report_path: str, output_dir: str) -> int:
    """Load report, export templates to directory."""
    with open(report_path) as f:
        report = json.load(f)

    templates = export_scan_to_nuclei(report)
    if not templates:
        print("No findings with PoC to export")
        return 1

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for t in templates:
        path = out / f"{t.id}.yaml"
        path.write_text(t.to_yaml(), encoding="utf-8")
        print(f"  ✅ {t.id} [{t.severity}] {t.name[:50]}")

    print(f"\n✅ {len(templates)} templates exported to {output_dir}/")
    print(f"   Run: nuclei -t {output_dir}/ -u https://staging.example.com")
    return 0


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="GSC Nuclei Export — PoC → nuclei YAML")
    p.add_argument("report", help="GSC scan report JSON")
    p.add_argument("--output", "-o", default="nuclei-templates")
    args = p.parse_args()
    sys.exit(export_scan(args.report, args.output))


if __name__ == "__main__":
    main()
