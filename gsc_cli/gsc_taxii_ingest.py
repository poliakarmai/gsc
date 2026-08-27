#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""
GSC TAXII Ingest — pull STIX 2.1 objects from a TAXII collection into GSC findings.

GETs objects from a TAXII 2.1 "Get Objects" endpoint
(GET /{api_root}/collections/{id}/objects/), converts STIX indicators and
vulnerabilities into GSC findings, and writes a GSC report JSON (the same
shape `gsc.py scan` produces, so it can be re-exported / correlated).

CLI:
  gsc taxii-ingest https://taxii.example.com/api1/collections/abc/objects/
  gsc taxii-ingest <url> --username u --password p -o findings.json
  gsc taxii-ingest <url> --api-key <token> --match indicator,vulnerability
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


def _auth_header(username, password, api_key):
    if username is not None:
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        return f"Basic {token}"
    if api_key:
        return f"Bearer {api_key}"
    return None


def fetch_objects(
    collection_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    match: Optional[List[str]] = None,
    limit: Optional[int] = None,
    timeout: int = 30,
) -> List[Dict]:
    """GET STIX objects from a TAXII collection. Returns the list of STIX objects."""
    url = collection_url
    params = []
    if match:
        params.append("match[type]=" + ",".join(match))
    if limit is not None:
        params.append(f"limit={limit}")
    if params:
        url += ("&" if "?" in url else "?") + "&".join(params)

    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", TAXII_MEDIA_TYPE)
    auth = _auth_header(username, password, api_key)
    if auth:
        req.add_header("Authorization", auth)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"TAXII GET failed (HTTP {e.code}): {detail[:300]}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"connection error: {getattr(e, 'reason', e)}") from e

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise RuntimeError("TAXII response is not valid JSON") from None
    if not isinstance(data, dict):
        raise RuntimeError("TAXII response is not a JSON object")
    # TAXII Envelope and STIX Bundle both carry "objects"
    return data.get("objects", [])


def _severity_from_cvss(score: float) -> str:
    score = max(0.0, min(10.0, score))
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def stix_to_findings(objects: List[Dict]) -> List[Dict]:
    """Convert STIX 2.1 objects into GSC findings (indicators + vulnerabilities)."""
    findings: List[Dict] = []
    for obj in objects:
        t = obj.get("type")
        if t == "indicator":
            labels = obj.get("labels") or []
            sev = "HIGH" if "malicious-activity" in labels else "MEDIUM"
            findings.append({
                "rule_id": "GIOC",
                "severity": sev,
                "category": "external-intel",
                "title": obj.get("name") or "STIX indicator",
                "detail": obj.get("description") or obj.get("pattern") or "",
                "stix_pattern": obj.get("pattern", ""),
                "file_path": "",
                "line": 0,
                "stix_id": obj.get("id", ""),
                "source": "taxii",
            })
        elif t == "vulnerability":
            score = None
            for ext in obj.get("external_references") or []:
                if not isinstance(ext, dict):
                    continue
                for k in ("x_cvss_score", "cvss_score", "cvss_v3_score"):
                    v = ext.get(k)
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        score = float(v)
                        break
                if score is not None:
                    break
            sev = _severity_from_cvss(score) if score is not None else "MEDIUM"
            cve = next((e.get("external_id") for e in obj.get("external_references") or []
                        if isinstance(e, dict) and e.get("source_name") == "cve"), None)
            findings.append({
                "rule_id": "GVULN",
                "severity": sev,
                "category": "external-intel",
                "title": obj.get("name") or "STIX vulnerability",
                "detail": obj.get("description") or "",
                "file_path": "",
                "line": 0,
                "stix_id": obj.get("id", ""),
                "cve": cve or "",
                "source": "taxii",
            })
        # other STIX types (report, observed-data, malware, ...) are skipped
    return findings


def taxii_ingest(
    collection_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    match: Optional[List[str]] = None,
    limit: Optional[int] = None,
    output: str = "gsc-taxii-findings.json",
) -> int:
    objects = fetch_objects(collection_url, username, password, api_key, match, limit)
    findings = stix_to_findings(objects)
    report = {"findings": findings}
    Path(output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    skipped = len(objects) - len(findings)
    print(f"Fetched {len(objects)} STIX objects -> {len(findings)} GSC findings (skipped {skipped})")
    print(f"Report -> {output}")
    return 0


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="GSC TAXII Ingest — pull STIX 2.1 objects into GSC findings")
    p.add_argument("collection_url", help="TAXII collection objects endpoint (GET .../objects/)")
    p.add_argument("--username", help="HTTP Basic auth username")
    p.add_argument("--password", help="HTTP Basic auth password")
    p.add_argument("--api-key", help="Bearer token / API key")
    p.add_argument("--match", help="Comma list of STIX types to fetch (default: indicator,vulnerability)")
    p.add_argument("--limit", type=int, default=None, help="Max objects to fetch")
    p.add_argument("--output", "-o", default="gsc-taxii-findings.json")
    args = p.parse_args()
    # Credentials may also come via env (avoids putting secrets in argv / cmdline)
    username = args.username or os.environ.get("GSC_TAXII_USERNAME")
    password = args.password or os.environ.get("GSC_TAXII_PASSWORD")
    api_key = args.api_key or os.environ.get("GSC_TAXII_API_KEY")
    match = args.match.split(",") if args.match else ["indicator", "vulnerability"]
    sys.exit(taxii_ingest(args.collection_url, username, password,
                          api_key, match, args.limit, args.output))


if __name__ == "__main__":
    main()
