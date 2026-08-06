#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC Nuclei Export v1.0 — PoC → nuclei YAML converter.

Wave 1 of nuclei integration: exports GSC findings as nuclei-compatible
YAML templates for DAST validation on staging/production.

CLI:
  gsc export-nuclei scan.json --output nuclei-templates/
  gsc export-nuclei scan.json --severity critical,high --max 10

Nuclei run:
  nuclei -t nuclei-templates/ -u https://staging.example.com
"""

from __future__ import annotations

import json
import re
import sys
import yaml
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}


# ── Data structures ────────────────────────────────────────
@dataclass
class NucleiTemplate:
    id: str
    info: dict
    requests: List[dict] = field(default_factory=list)
    network: List[dict] = field(default_factory=list)   # for TCP-based PoCs
    code: List[dict] = field(default_factory=list)       # for script-based PoCs

    def to_yaml(self) -> str:
        # Clean None/empty values
        data = {
            "id": self.id,
            "info": {k: v for k, v in self.info.items() if v},
        }
        if self.requests:
            data["requests"] = self.requests
        if self.network:
            data["network"] = self.network
        if self.code:
            data["code"] = self.code

        # Custom Dumper to avoid anchors/aliases + proper formatting
        class NoAliasDumper(yaml.SafeDumper):
            def ignore_aliases(self, data):
                return True

        return yaml.dump(data, Dumper=NoAliasDumper, sort_keys=False,
                         allow_unicode=True, default_flow_style=False, width=120)


# ── PoC parsers ────────────────────────────────────────────
def _parse_curl(curl_cmd: str) -> Optional[dict]:
    """Parse curl command into nuclei HTTP request template."""
    # Extract URL
    url_match = re.search(r'(?:curl\s+)?[\"\']?(https?://[^\s\"\']+)', curl_cmd)
    if not url_match and "curl" not in curl_cmd.lower():
        return None

    method = "GET"
    if re.search(r'-X\s+(POST|PUT|PATCH|DELETE)', curl_cmd, re.IGNORECASE):
        method = re.search(r'-X\s+(POST|PUT|PATCH|DELETE)', curl_cmd, re.IGNORECASE).group(1).upper()
    elif re.search(r'--data|--data-raw|--data-binary|-d\s', curl_cmd):
        method = "POST"

    # Extract path from URL (for nuclei, BaseURL is separate)
    path = "{{BaseURL}}"
    if url_match:
        full_url = url_match.group(1)
        parsed = re.match(r'https?://[^/]+(/.*)?', full_url)
        if parsed and parsed.group(1):
            path = f"{{{{BaseURL}}}}{parsed.group(1)}"

    # Extract headers
    headers = {}
    for m in re.finditer(r'-H\s+[\"\']?([^:]+):\s*([^\"\']+)', curl_cmd):
        headers[m.group(1).strip()] = m.group(2).strip()

    # Extract body
    body = ""
    body_match = re.search(r'(?:--data|--data-raw|--data-binary|-d)\s+[\"\']?([^\"\']+)', curl_cmd)
    if body_match:
        body = body_match.group(1)

    # Build matchers from expected output
    matchers = _extract_matchers(curl_cmd)

    req = {
        "method": method,
        "path": [path],
    }
    if headers:
        req["headers"] = headers
    if body:
        req["body"] = body
    if matchers:
        req["matchers"] = matchers
    else:
        # Default: status 200
        req["matchers"] = [{"type": "status", "status": [200]}]

    return req


def _parse_python(python_code: str) -> Optional[dict]:
    """Parse Python PoC — export as nuclei 'code' protocol (script-based)."""
    # Extract key URL/payload from Python code
    url_match = re.search(r'[\"\'](https?://[^\"\']+)', python_code)
    method = "GET"
    if re.search(r'requests\.(post|put|patch|delete)', python_code, re.IGNORECASE):
        method = re.search(r'requests\.(post|put|patch|delete)', python_code, re.IGNORECASE).group(1).upper()

    path = "{{BaseURL}}"
    if url_match:
        full_url = url_match.group(1)
        parsed = re.match(r'https?://[^/]+(/.*)?', full_url)
        if parsed and parsed.group(1):
            path = f"{{{{BaseURL}}}}{parsed.group(1)}"

    matchers = _extract_matchers(python_code)

    req = {
        "method": method,
        "path": [path],
    }
    if matchers:
        req["matchers"] = matchers
    else:
        req["matchers"] = [{"type": "status", "status": [200]}]

    return req


def _extract_matchers(code: str) -> List[dict]:
    """Extract nuclei matchers from PoC code's success indicators."""
    matchers = []

    # Look for success markers
    for marker in ("VULNERABLE", "EXPLOITED", "SQLI_SUCCESS", "SUCCESS",
                   "admin", "root:", "password:", "token:", "secret:"):
        if marker.lower() in code.lower():
            matchers.append({"type": "word", "words": [marker]})

    # Look for HTTP status expectations
    status_match = re.search(r'(?:status|code).*?(\d{3})', code, re.IGNORECASE)
    if status_match:
        matchers.append({"type": "status", "status": [int(status_match.group(1))]})

    # Default: expect 200 if nothing else found
    if not matchers:
        matchers.append({"type": "status", "status": [200]})

    # Remove duplicates
    seen = set()
    unique = []
    for m in matchers:
        key = json.dumps(m, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(m)

    return unique[:3]  # Max 3 matcher groups


# ── Main converter ─────────────────────────────────────────
def finding_to_template(finding: dict) -> Optional[NucleiTemplate]:
    """Convert a GSC finding to a nuclei YAML template."""
    rule_id = finding.get("rule_id", "GS000")
    finding_key = finding.get("finding_key", "")
    if not finding_key:
        import hashlib
        raw = f"{rule_id}+{finding.get('file_path','')}+{finding.get('detail','')[:80]}"
        finding_key = hashlib.sha256(raw.encode()).hexdigest()[:12]

    severity = SEVERITY_MAP.get(finding.get("category", "MEDIUM").upper(), "medium")
    title = finding.get("title", rule_id)
    detail = finding.get("detail", "")[:200]
    file_path = finding.get("file_path", "")

    # Get PoC code
    poc_code = ""
    poc_fmt = ""
    metadata = finding.get("metadata", {})
    if isinstance(metadata, dict):
        poc_code = metadata.get("poc", "")
        poc_fmt = metadata.get("poc_format", "")

    info = {
        "name": f"GSC {rule_id}: {title}",
        "author": "gsc-auto",
        "severity": severity,
        "description": (
            f"Auto-generated from GSC finding {finding_key}.\n"
            f"Rule: {rule_id}\n"
            f"File: {file_path}\n"
            f"Details: {detail}\n"
        ),
        "tags": f"gsc,{rule_id.lower()},{severity}",
        "reference": [f"gsc://finding/{finding_key}"],
    }

    template = NucleiTemplate(id=f"gsc-{finding_key}", info=info)

    # Parse PoC into nuclei format
    if poc_code:
        if poc_fmt == "curl" or "curl" in poc_code.lower()[:20]:
            req = _parse_curl(poc_code)
            if req:
                template.requests.append(req)
        elif poc_fmt == "python" or "import" in poc_code.lower()[:30]:
            req = _parse_python(poc_code)
            if req:
                template.requests.append(req)
        else:
            # Generic: try curl first, then python
            req = _parse_curl(poc_code) or _parse_python(poc_code)
            if req:
                template.requests.append(req)

    # If no PoC, generate a default HTTP probe based on the finding
    if not template.requests:
        template.requests.append({
            "method": "GET",
            "path": ["{{BaseURL}}"],
            "matchers": [{"type": "status", "status": [200]}],
        })

    return template


def export_scan(report_path: str, output_dir: str,
                severities: Optional[List[str]] = None,
                max_templates: int = 50) -> List[str]:
    """Export all findings from a scan report to nuclei templates."""
    with open(report_path) as f:
        report = json.load(f)

    findings = report.get("findings", [])
    if severities:
        allowed = set(s.upper() for s in severities)
        findings = [f for f in findings if f.get("category", "").upper() in allowed]

    findings = findings[:max_templates]
    if not findings:
        print("No findings to export.")
        return []

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    exported = []
    for f_ in findings:
        template = finding_to_template(f_)
        if not template:
            continue

        yaml_str = template.to_yaml()
        filename = out_path / f"{template.id}.yaml"
        filename.write_text(yaml_str, encoding="utf-8")

        sev = template.info["severity"]
        print(f"  ✅ {template.id:<20} [{sev:<8}] {template.info['name'][:50]}")
        exported.append(str(filename))

    # Generate README
    readme = out_path / "README.md"
    readme.write_text(
        f"# GSC Nuclei Templates\n\n"
        f"Auto-generated from: `{report_path}`\n"
        f"Date: {datetime.now(timezone.utc).isoformat()}\n"
        f"Templates: {len(exported)}\n\n"
        f"## Usage\n\n"
        f"```bash\n"
        f"nuclei -t {output_dir}/ -u https://staging.example.com\n"
        f"nuclei -t {output_dir}/ -l targets.txt\n"
        f"```\n\n"
        f"## Templates\n\n"
        + "\n".join(f"- `{Path(p).name}`" for p in exported)
    )
    print(f"\n✅ {len(exported)} templates exported to {output_dir}/")
    print(f"   Run: nuclei -t {output_dir}/ -u <target>")
    return exported


# ── Validation ─────────────────────────────────────────────
def validate_template(yaml_path: str) -> bool:
    """Validate a nuclei template — checks YAML parse + required fields."""
    try:
        with open(yaml_path) as f:
            template = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"❌ {yaml_path}: invalid YAML — {e}")
        return False

    if not isinstance(template, dict):
        print(f"❌ {yaml_path}: not a mapping")
        return False

    required = ["id", "info"]
    for key in required:
        if key not in template:
            print(f"❌ {yaml_path}: missing required field '{key}'")
            return False

    # At least one protocol
    has_protocol = any(k in template for k in ("requests", "network", "code",
                                                 "dns", "file", "headless",
                                                 "ssl", "websocket", "whois",
                                                 "flow", "javascript"))
    if not has_protocol:
        print(f"❌ {yaml_path}: no protocol defined (requests/network/code)")
        return False

    return True


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    import argparse
    p = argparse.ArgumentParser(
        description="GSC Nuclei Export — convert GSC findings to nuclei YAML templates")
    p.add_argument("report", help="GSC scan report JSON")
    p.add_argument("--output", "-o", default="nuclei-templates",
                   help="Output directory (default: nuclei-templates/)")
    p.add_argument("--severity", "-s",
                   help="Filter by severity: critical,high,medium,low")
    p.add_argument("--max", type=int, default=50,
                   help="Max templates to export (default: 50)")
    p.add_argument("--validate", action="store_true",
                   help="Validate exported templates")
    args = p.parse_args()

    severities = None
    if args.severity:
        severities = [s.strip().upper() for s in args.severity.split(",")]

    exported = export_scan(args.report, args.output, severities, args.max)

    if args.validate and exported:
        print(f"\n🔍 Validating {len(exported)} templates...")
        valid = sum(1 for p in exported if validate_template(p))
        print(f"   Valid: {valid}/{len(exported)}")


if __name__ == "__main__":
    main()
