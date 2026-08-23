#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""
GSC TAXII Export — push GSC findings to a TAXII 2.1 collection.

Builds the same STIX 2.1 bundle as `export-stix`, then POSTs it to a TAXII
2.1 "Add Objects" endpoint (POST /{api_root}/collections/{id}/objects/).

Auth (optional):
  - HTTP Basic  (--username / --password)
  - Bearer token / API key (--api-key)

CLI:
  gsc export-taxii scan.json --collection-url https://taxii.example.com/api1/collections/abc/objects/
  gsc export-taxii scan.json --collection-url ... --username u --password p
  gsc export-taxii scan.json --collection-url ... --api-key <token>
  gsc export-taxii scan.json --collection-url ... --dry-run   # build + save, no push
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))

from gsc_stix_export import build_bundle

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


def _load_findings(report_path: str, severity: Optional[str], max_items: Optional[int]) -> List[Dict]:
    with open(report_path) as f:
        report = json.load(f)
    findings = report.get("findings", []) if isinstance(report, dict) else report
    if severity:
        wanted = {s.strip().lower() for s in severity.split(",") if s.strip()}
        findings = [f_ for f_ in findings
                    if str(f_.get("severity", f_.get("category", ""))).lower() in wanted]
    if max_items:
        findings = findings[:max_items]
    return findings


def push_bundle(
    bundle: Dict,
    collection_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> Dict:
    """POST a STIX 2.1 bundle to a TAXII 2.1 collection. Returns {ok, status_code, detail}."""
    payload = json.dumps(bundle).encode("utf-8")
    req = urllib.request.Request(collection_url, data=payload, method="POST")
    req.add_header("Content-Type", TAXII_MEDIA_TYPE)
    req.add_header("Accept", TAXII_MEDIA_TYPE)
    if username is not None:
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    elif api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status_code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return {"ok": False, "status_code": e.code, "detail": body[:500]}
    except urllib.error.URLError as e:
        return {"ok": False, "status_code": None, "detail": f"connection error: {e.reason}"}

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = {"raw": body[:500]}
    return {"ok": 200 <= status_code < 300, "status_code": status_code, "detail": parsed}


def export_taxii(
    report_path: str,
    collection_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    severity: Optional[str] = None,
    max_items: Optional[int] = None,
    dry_run: bool = False,
    output: Optional[str] = None,
) -> int:
    findings = _load_findings(report_path, severity, max_items)
    if not findings:
        print("No findings to export")
        return 1
    bundle = build_bundle(findings)

    if output:
        Path(output).write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Bundle saved -> {output}")

    n = len(bundle["objects"]) - 1  # minus the report SDO
    if dry_run:
        print(f"[dry-run] would push {n} findings to {collection_url}")
        return 0

    print(f"Pushing {n} findings -> {collection_url}")
    result = push_bundle(bundle, collection_url, username, password, api_key)
    if result.get("ok"):
        detail = result.get("detail", {})
        status = detail.get("status", "complete") if isinstance(detail, dict) else ""
        print(f"  accepted (HTTP {result['status_code']}) status={status}")
        return 0
    print(f"  push failed (HTTP {result.get('status_code')}): {result.get('detail')}")
    return 1


# ── CLI ────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="GSC TAXII Export — push STIX 2.1 bundle to a TAXII collection")
    p.add_argument("report", help="GSC scan report JSON")
    p.add_argument("--collection-url", required=True,
                   help="TAXII collection objects endpoint (POST .../objects/)")
    p.add_argument("--username", help="HTTP Basic auth username")
    p.add_argument("--password", help="HTTP Basic auth password")
    p.add_argument("--api-key", help="Bearer token / API key")
    p.add_argument("--severity", "-s", help="Filter: critical,high,medium,low")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--dry-run", action="store_true", help="Build + save bundle, do not push")
    p.add_argument("--output", "-o", help="Also save the bundle JSON to this path")
    args = p.parse_args()
    sys.exit(export_taxii(
        args.report, args.collection_url, args.username, args.password, args.api_key,
        args.severity, args.max, args.dry_run, args.output,
    ))


if __name__ == "__main__":
    main()
