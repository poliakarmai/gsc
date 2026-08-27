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
import os
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


def _auth_header(username, password, api_key):
    if username is not None:
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        return f"Basic {token}"
    if api_key:
        return f"Bearer {api_key}"
    return None


def _get_json(url: str, username, password, api_key, timeout: int = 30) -> Dict:
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
    return data


def _pick(items: List[str], name: Optional[str], what: str) -> str:
    """Pick a TAXII URL by exact match or by its last path segment (id)."""
    if name:
        name = name.rstrip("/")
        for it in items:
            if name in (it, it.rstrip("/"), it.rstrip("/").rsplit("/", 1)[-1]):
                return it
        raise RuntimeError(f"{what} '{name}' not found among {len(items)} options")
    if not items:
        raise RuntimeError(f"no {what}s available")
    return items[0]


def discover_collection_url(
    discovery_url: str,
    api_root: Optional[str] = None,
    collection: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> str:
    """Resolve a TAXII 2.1 collection objects endpoint via Discovery + API Root."""
    disc = _get_json(discovery_url, username, password, api_key, timeout)
    roots = disc.get("api_roots")
    if not isinstance(roots, list) or not roots:
        raise RuntimeError("no api_roots in TAXII discovery response")
    root_url = _pick(roots, api_root, "API root")

    root = _get_json(root_url, username, password, api_key, timeout)
    collections = root.get("collections")
    if not isinstance(collections, list) or not collections:
        raise RuntimeError("no collections in TAXII API root")
    coll_url = _pick(collections, collection, "collection")

    return coll_url.rstrip("/") + "/objects/"


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
    auth = _auth_header(username, password, api_key)
    if auth:
        req.add_header("Authorization", auth)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            status_code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return {"ok": False, "status_code": e.code, "detail": body[:500]}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"ok": False, "status_code": None, "detail": f"connection error: {getattr(e, 'reason', e)}"}

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
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--collection-url", help="TAXII collection objects endpoint (POST .../objects/)")
    target.add_argument("--discover", metavar="DISCOVERY_URL",
                        help="TAXII Discovery endpoint (GET .../taxii2/); auto-resolve collection")
    p.add_argument("--api-root", help="With --discover: API root id/URL to pick")
    p.add_argument("--collection", help="With --discover: collection id/URL to pick")
    p.add_argument("--username", help="HTTP Basic auth username")
    p.add_argument("--password", help="HTTP Basic auth password")
    p.add_argument("--api-key", help="Bearer token / API key")
    p.add_argument("--severity", "-s", help="Filter: critical,high,medium,low")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--dry-run", action="store_true", help="Build + save bundle, do not push")
    p.add_argument("--output", "-o", help="Also save the bundle JSON to this path")
    args = p.parse_args()

    if not args.discover and (args.api_root or args.collection):
        p.error("--api-root/--collection require --discover")

    # Credentials may also come via env (avoids putting secrets in argv / cmdline)
    username = args.username or os.environ.get("GSC_TAXII_USERNAME")
    password = args.password or os.environ.get("GSC_TAXII_PASSWORD")
    api_key = args.api_key or os.environ.get("GSC_TAXII_API_KEY")

    collection_url = args.collection_url
    if args.discover:
        collection_url = discover_collection_url(
            args.discover, args.api_root, args.collection,
            username, password, api_key,
        )
        print(f"Discovered collection -> {collection_url}")

    sys.exit(export_taxii(
        args.report, collection_url, username, password, api_key,
        args.severity, args.max, args.dry_run, args.output,
    ))


if __name__ == "__main__":
    main()
