#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC CISA KEV Prioritisation v1.0 (v0.32).

Enriches SCA (GS030) findings with CISA Known Exploited Vulnerabilities data.
CISA KEV is the authoritative source for "actively exploited in the wild" CVEs
(stronger signal than EPSS percentile — confirmed by CISA analysts, not statistical).

CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Format: {"catalogVersion": "...", "count": N, "vulnerabilities": [
  {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
   "vulnerabilityName": "...", "dateAdded": "2021-12-10", "shortDescription": "...",
   "requiredAction": "...", "dueDate": "2022-05-01",
   "knownRansomwareCampaignUse": "Known", "notes": "..."}, ...]}
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HTTP_TIMEOUT = 30

# Match CVE-YYYY-NNNN through CVE-YYYY-NNNNNNN (4 to 7 digits, matches MITRE/NVD).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ── Data classes ──────────────────────────────────────────
@dataclass
class KevEntry:
    """Single CISA KEV vulnerability entry (one row from the catalog)."""
    cve_id: str
    vendor_project: str
    product: str
    date_added: str
    due_date: str
    ransomware_known: bool
    required_action: str

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "ransomware_known": self.ransomware_known,
            "required_action": self.required_action,
        }


@dataclass
class KEVCatalog:
    """CISA KEV catalog snapshot. vulnerabilities: cve_id (UPPER) -> KevEntry."""
    catalog_version: str
    count: int
    vulnerabilities: Dict[str, KevEntry] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "catalog_version": self.catalog_version,
            "count": self.count,
            "vulnerabilities": {k: v.to_dict() for k, v in self.vulnerabilities.items()},
        }


# ── Pure parser (no network) ──────────────────────────────
def parse_kev_json(payload: dict) -> KEVCatalog:
    """Parse a CISA KEV JSON payload (dict) into a KEVCatalog.

    Tolerant: missing fields default to "" / False; non-dict input returns
    an empty catalog instead of raising.
    """
    if not isinstance(payload, dict):
        return KEVCatalog(catalog_version="", count=0, vulnerabilities={})

    version = str(payload.get("catalogVersion", "") or "")
    try:
        count = int(payload.get("count", 0) or 0)
    except (TypeError, ValueError):
        count = 0

    vulns: Dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities", []) or []:
        if not isinstance(item, dict):
            continue
        cve_raw = item.get("cveID", "")
        if not isinstance(cve_raw, str):
            cve_raw = str(cve_raw)
        cve = _normalize(cve_raw)
        if not cve:
            continue
        ransomware_raw = item.get("knownRansomwareCampaignUse", "")
        if not isinstance(ransomware_raw, str):
            ransomware_raw = str(ransomware_raw)
        ransomware_known = ransomware_raw.strip().lower() == "known"

        vulns[cve] = KevEntry(
            cve_id=cve,
            vendor_project=str(item.get("vendorProject", "") or ""),
            product=str(item.get("product", "") or ""),
            date_added=str(item.get("dateAdded", "") or ""),
            due_date=str(item.get("dueDate", "") or ""),
            ransomware_known=ransomware_known,
            required_action=str(item.get("requiredAction", "") or ""),
        )
    return KEVCatalog(catalog_version=version, count=count, vulnerabilities=vulns)


# ── KEV Client (network) ──────────────────────────────────
class KevClient:
    """Fetch CISA KEV catalog. Tolerant: any network/parse error returns empty catalog."""

    def __init__(self, timeout: int = HTTP_TIMEOUT) -> None:
        self.timeout = timeout

    def fetch(self) -> KEVCatalog:
        """Download the CISA KEV JSON feed and parse it.

        On any exception (timeout, HTTP error, malformed JSON, schema drift)
        returns an empty KEVCatalog — never raises. Callers can rely on
        ``catalog.vulnerabilities`` being a dict and call ``is_known_exploited``
        safely on the result.
        """
        try:
            with urllib.request.urlopen(KEV_JSON_URL, timeout=self.timeout) as resp:
                raw = resp.read()
            payload = json.loads(raw)
        except Exception:
            return KEVCatalog(catalog_version="", count=0, vulnerabilities={})
        return parse_kev_json(payload)


# ── CVE normalisation ─────────────────────────────────────
def _normalize(cve_id: str) -> str:
    """Normalise a CVE identifier to ``CVE-YYYY-NNNN`` (UPPER).

    Returns UPPER match if ``CVE-\\d{4}-\\d{4,7}`` is found, else ``""``.
    Non-CVE identifiers (GHSA-*, PYSEC-*, OSV-*, plain strings) yield ``""`` —
    they are not KEV-trackable. This is intentional: callers should treat
    empty string as "not a CVE; skip KEV lookup".
    """
    if not isinstance(cve_id, str) or not cve_id:
        return ""
    m = _CVE_RE.search(cve_id)
    if not m:
        return ""
    return m.group(0).upper()


# ── Pure lookup helpers ───────────────────────────────────
def is_known_exploited(cve: str, catalog: KEVCatalog) -> bool:
    """True iff ``cve`` (any case, normalised) is in the CISA KEV catalog.

    Tolerant: None / empty / non-CVE input returns False.
    """
    if not catalog or not catalog.vulnerabilities:
        return False
    if cve is None:
        return False
    normalised = _normalize(cve) if isinstance(cve, str) else ""
    if not normalised:
        # Fall back to upper-cased key lookup for already-normalised inputs.
        if isinstance(cve, str) and cve.upper() in catalog.vulnerabilities:
            return True
        return False
    return normalised in catalog.vulnerabilities


def kev_lookup(cves: List[str], catalog: KEVCatalog) -> Dict[str, KevEntry]:
    """Return a dict {CVE: KevEntry} for the CVEs that exist in the catalog.

    Tolerant: None entries, empty strings, non-CVE identifiers and absent
    catalog all yield an empty dict.
    """
    out: Dict[str, KevEntry] = {}
    if not catalog or not catalog.vulnerabilities or not cves:
        return out
    for cve in cves:
        if not cve or not isinstance(cve, str):
            continue
        normalised = _normalize(cve)
        if not normalised:
            continue
        entry = catalog.vulnerabilities.get(normalised)
        if entry is not None:
            out[normalised] = entry
    return out
