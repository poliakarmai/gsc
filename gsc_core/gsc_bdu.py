#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC FSTEC BDU Catalog v1.0 (v0.32).

Russian analogue of CISA KEV. Parses the FSTEC Russia "Bank of Data of
Information Security Threats" (BDU, https://bdu.fstec.ru) — the official
Russian Federation registry of information-security threats and
vulnerabilities.

Every entry has a BDU identifier in the form ``BDU:YYYY-NNNNN`` (prefix
``BDU``, four-digit year, 1–7 digit ordinal, commonly zero-padded to 5
digits — e.g. ``BDU:2025-00001``). The Russian regulator requires
operators of critical information infrastructure (CII) to map any
detected vulnerability to BDU before reporting; GSC's enrichment
pipeline uses this module to cross-reference SCA findings with the BDU
catalog and surface a "known to FSTEC" signal to Russian customers.

The BDU feed exposes a JSON array of objects (one per record). Field
names are taken from the public export; real-world responses are
schemaless in places (any field may be missing, ``None``, or empty), so
the parser is intentionally tolerant.

Copyright © 2025 Алексей Поляков
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Union

# Default JSON feed URL. The actual endpoint is configured by FSTEC and
# may change; callers may override via the ``url`` argument of
# :class:`BduClient`.
BDU_JSON_URL = "https://bdu.fstec.ru/api/v1/vul"
HTTP_TIMEOUT = 30

# Match CVE-YYYY-NNNN through CVE-YYYY-NNNNNNN (4 to 7 digits, same as
# MITRE/NVD and consistent with gsc_kev._CVE_RE / gsc_exploitdb._CVE_RE).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ── Data class ─────────────────────────────────────────────
@dataclass
class BduEntry:
    """Single BDU FSTEC record.

    All string fields default to ``""`` and ``cve_ids`` to ``[]`` so that
    schemaless / partial records still produce a well-formed object.
    """

    identifier: str = ""
    name: str = ""
    description: str = ""
    vendor: str = ""
    product: str = ""
    vuln_class: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    date: str = ""

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "name": self.name,
            "description": self.description,
            "vendor": self.vendor,
            "product": self.product,
            "vuln_class": self.vuln_class,
            "cve_ids": list(self.cve_ids),
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "date": self.date,
        }


# ── Pure normalisation helpers (no network, no I/O) ────────
def _normalize_identifier(raw) -> Optional[str]:
    """Normalise a BDU identifier to ``BDU:YYYY-NNNNN`` (UPPER, zero-padded).

    Accepts the following inputs and returns a canonical form:

    * ``"BDU:2025-00001"``        → ``"BDU:2025-00001"``  (already canonical)
    * ``"bdu:2025-1"``            → ``"BDU:2025-00001"``  (case + zero-padding)
    * ``"BDU-2025-00001"``        → ``"BDU:2025-00001"``  (hyphens → colons)
    * ``"2025-00042"``            → ``"BDU:2025-00042"``  (prefix added)
    * ``"see record BDU:2025-00099 / log4j"`` → ``"BDU:2025-00099"``
      (embedded match, prefix is required for embedded lookups)
    * ``"CVE-2025-1234"``         → ``None``              (not a BDU ID)
    * ``None`` / ``""``           → ``None``

    Returns ``None`` if the input does not look like a BDU identifier.
    """
    if not isinstance(raw, str) or not raw:
        return None
    s = raw.strip()
    if not s:
        return None

    # Case 1: full-string match WITH explicit ``BDU`` prefix.
    m = re.match(
        r"^BDU[:\-](\d{4})[:\-](\d{1,7})$",
        s,
        re.IGNORECASE,
    )
    if m:
        year = m.group(1)
        ordinal = m.group(2).zfill(5)
        return f"BDU:{year}-{ordinal}"

    # Case 2: full-string match WITHOUT prefix (bare year+ordinal).
    # Anchored both ends so ``"CVE-2025-1234"`` does not slip through.
    m = re.match(r"^(\d{4})[:\-](\d{1,7})$", s)
    if m:
        year = m.group(1)
        ordinal = m.group(2).zfill(5)
        return f"BDU:{year}-{ordinal}"

    # Case 3: embedded match — only honoured when the BDU prefix is
    # explicit, so a bare CVE-style string never collides with BDU.
    m = re.search(r"BDU[:\-](\d{4})[:\-](\d{1,7})", s, re.IGNORECASE)
    if m:
        year = m.group(1)
        ordinal = m.group(2).zfill(5)
        return f"BDU:{year}-{ordinal}"

    return None


def _normalize_cve(raw) -> Optional[str]:
    """Normalise a CVE identifier to ``CVE-YYYY-NNNN`` (UPPER).

    Returns the UPPER regex match if ``CVE-\\d{4}-\\d{4,7}`` is found,
    else ``None``. Non-string input (``None``, ``int``, ...) yields
    ``None`` — callers should treat ``None`` as "not a CVE; skip".
    """
    if not isinstance(raw, str) or not raw:
        return None
    m = _CVE_RE.search(raw)
    if not m:
        return None
    return m.group(0).upper()


def _coerce_str(value) -> str:
    """Best-effort conversion to ``str``; ``None`` and non-strings → ``""``."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _coerce_cve_list(value) -> List[str]:
    """Extract and normalise a list of CVE IDs from a BDU field.

    Tolerates both shapes the FSTEC export may use:
      * a JSON array of strings: ``["CVE-2025-1", "CVE-2025-2"]``;
      * a single comma-separated string: ``"CVE-2025-1, CVE-2025-2"``.

    Anything else (``None``, ``int``, ``dict``, ...) returns ``[]``.
    Duplicates are removed while preserving first-seen order.
    """
    if value is None:
        return []
    if isinstance(value, str):
        candidates = [c.strip() for c in value.split(",")]
    elif isinstance(value, (list, tuple)):
        candidates = []
        for item in value:
            if isinstance(item, str):
                candidates.append(item)
            elif item is not None:
                candidates.append(str(item))
    else:
        # Unexpected type (int / dict / bool / ...) — try one regex pass.
        s = str(value)
        candidates = [s] if s else []

    out: List[str] = []
    seen: set = set()
    for cand in candidates:
        if not cand:
            continue
        normalised = _normalize_cve(cand)
        if not normalised or normalised in seen:
            continue
        seen.add(normalised)
        out.append(normalised)
    return out


def _coerce_cvss_score(value) -> Optional[float]:
    """Convert a CVSS score field to ``float``, or ``None`` on any failure.

    Tolerates: ``"9.8"``, ``9.8``, ``None``, ``""``, ``"N/A"``,
    ``"abc"``, lists, dicts, etc. Never raises.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        # bool is an int subclass — guard against ``True`` → 1.0 silent coercion.
        return None
    if isinstance(value, (int, float)):
        try:
            f = float(value)
        except (TypeError, ValueError):
            return None
        if f != f:  # NaN check
            return None
        return f
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            f = float(s)
        except ValueError:
            return None
        if f != f:  # NaN
            return None
        return f
    # Any other type (list, dict, ...) — give up.
    return None


# ── Pure parser (no network) ───────────────────────────────
def parse_bdu_json(payload: Union[bytes, str, dict, list, None]) -> List[BduEntry]:
    """Parse a BDU FSTEC JSON payload into a list of :class:`BduEntry`.

    Tolerant by design:

    * ``None`` / empty string / non-JSON / JSON that isn't a list
      returns ``[]`` (never raises);
    * already-parsed ``list[dict]`` input is accepted directly without
      re-decoding;
    * for each record: any field may be missing, ``None`` or the wrong
      type — defaults are ``""`` (strings) / ``[]`` (cve_ids) /
      ``None`` (cvss_score);
    * records that are not ``dict`` are silently skipped;
    * the BDU ``identifier`` is normalised through
      :func:`_normalize_identifier`; records whose identifier does not
      look like a BDU ID are skipped (the catalog is meant to be
      keyed by BDU ID — a record without one has no identity).

    The expected record schema (per the FSTEC public export) is::

        {
            "identifier": "BDU:2025-00001",
            "name": "...",
            "description": "...",
            "vendor": "...",
            "product": "...",
            "vulnerability_class": "...",
            "cve_identifiers": ["CVE-2025-12345"],
            "cvss_score": "9.8",
            "cvss_vector": "CVSS:3.1/...",
            "date_discovered": "2025-01-15",
            "date_updated": "...",
            "exploit_availability": "...",
            "identifier_number": "..."
        }

    Only the fields the dataclass cares about are read; the rest is
    ignored.
    """
    # 1) Decode / accept pre-parsed payload.
    if payload is None:
        return []

    if isinstance(payload, (list, dict)):
        data = payload
    elif isinstance(payload, (bytes, bytearray)):
        try:
            data = json.loads(payload.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return []
    elif isinstance(payload, str):
        if not payload.strip():
            return []
        try:
            data = json.loads(payload)
        except ValueError:
            return []
    else:
        return []

    if not isinstance(data, list):
        return []

    entries: List[BduEntry] = []
    for raw in data:
        if not isinstance(raw, dict):
            continue

        identifier = _normalize_identifier(_coerce_str(raw.get("identifier", "")))
        # If neither the ``identifier`` field nor a number-only fallback
        # matches, the record has no identity — skip it.
        if not identifier:
            # Fallback: some exports use ``identifier_number`` or just
            # the year+ordinal in another field. Try a couple of common
            # alternatives before giving up.
            for alt_key in ("identifier_number", "bdu_id", "id"):
                alt_val = raw.get(alt_key)
                if alt_val is None:
                    continue
                identifier = _normalize_identifier(_coerce_str(alt_val))
                if identifier:
                    break
        if not identifier:
            continue

        cve_ids = _coerce_cve_list(raw.get("cve_identifiers"))
        cvss_score = _coerce_cvss_score(raw.get("cvss_score"))

        # ``date`` is best-effort: FSTEC exposes both ``date_discovered``
        # and ``date_updated``. Prefer ``date_discovered`` (the moment the
        # threat was registered), fall back to ``date_updated`` /
        # ``date``.
        date = _coerce_str(raw.get("date_discovered", ""))
        if not date:
            date = _coerce_str(raw.get("date_updated", ""))
        if not date:
            date = _coerce_str(raw.get("date", ""))

        entries.append(
            BduEntry(
                identifier=identifier,
                name=_coerce_str(raw.get("name", "")),
                description=_coerce_str(raw.get("description", "")),
                vendor=_coerce_str(raw.get("vendor", "")),
                product=_coerce_str(raw.get("product", "")),
                vuln_class=_coerce_str(raw.get("vulnerability_class", "")),
                cve_ids=cve_ids,
                cvss_score=cvss_score,
                cvss_vector=_coerce_str(raw.get("cvss_vector", "")),
                date=date,
            )
        )

    return entries


# ── BDU Client (network) ───────────────────────────────────
class BduClient:
    """Fetch the FSTEC BDU JSON catalog.

    Tolerant: any network error, HTTP error, decode error or parse
    failure returns ``[]`` — never raises. Callers can rely on the
    result being a list and pass it directly to
    :func:`is_known_bdu` / :func:`bdu_lookup` / :func:`bdu_lookup_identifier`.
    """

    def __init__(
        self,
        timeout: int = HTTP_TIMEOUT,
        url: str = BDU_JSON_URL,
    ) -> None:
        self.timeout = timeout
        self.url = url

    def fetch(self) -> List[BduEntry]:
        """Download the BDU JSON feed and parse it.

        On any exception (timeout, HTTP error, malformed JSON, schema
        drift) returns an empty list — GSC's enrichment pipeline must
        degrade gracefully when the FSTEC endpoint is unreachable.
        """
        try:
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "GSC/0.32 (+gsc-bdu)"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except Exception:
            return []
        return parse_bdu_json(raw)


# ── Pure lookup helpers ────────────────────────────────────
def is_known_bdu(entries: List[BduEntry], identifier: str) -> bool:
    """True iff a record with this BDU identifier is present in ``entries``.

    The lookup is by :func:`_normalize_identifier` — case-insensitive,
    hyphen/colon agnostic, with ordinal zero-padding. Tolerant:
    ``None`` / empty / non-string input returns ``False``; a
    non-list / ``None`` ``entries`` returns ``False``.
    """
    if not isinstance(entries, list) or not entries:
        return False
    target = _normalize_identifier(identifier)
    if not target:
        return False
    for entry in entries:
        if not isinstance(entry, BduEntry):
            continue
        if entry.identifier == target:
            return True
    return False


def bdu_lookup(entries: List[BduEntry], cve: str) -> List[BduEntry]:
    """Return every record whose ``cve_ids`` contain ``cve``.

    The match is by :func:`_normalize_cve` (case-insensitive). Tolerant:
    ``None`` / non-string / non-CVE input returns ``[]``; non-list /
    ``None`` ``entries`` returns ``[]``. Order of the result preserves
    the order of ``entries``.
    """
    if not isinstance(entries, list) or not entries:
        return []
    target = _normalize_cve(cve)
    if not target:
        return []
    out: List[BduEntry] = []
    for entry in entries:
        if not isinstance(entry, BduEntry):
            continue
        if target in entry.cve_ids:
            out.append(entry)
    return out


def bdu_lookup_identifier(
    entries: List[BduEntry],
    identifier: str,
) -> Optional[BduEntry]:
    """Return the single record with this BDU identifier, or ``None``.

    Bonus helper for the exact-identifier fast path. Tolerant:
    ``None`` / non-string / unparseable input returns ``None``;
    non-list / ``None`` ``entries`` returns ``None``. If multiple
    records match (should not happen in a well-formed catalog but the
    FSTEC export is not strict), the first one wins.
    """
    if not isinstance(entries, list) or not entries:
        return None
    target = _normalize_identifier(identifier)
    if not target:
        return None
    for entry in entries:
        if not isinstance(entry, BduEntry):
            continue
        if entry.identifier == target:
            return entry
    return None
