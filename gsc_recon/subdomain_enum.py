#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""
GSC Subdomain Enumeration v1.0 (v0.32) — passive subdomain discovery.

Part of the new Recon front for GSC (bug bounty surface mapping). Uses
Certificate Transparency logs (crt.sh) to enumerate subdomains without
ever sending traffic to the target — purely passive reconnaissance.

Source:
  - crt.sh JSON API: https://crt.sh/?q=%25.<domain>&output=json
  - Response is a JSON array of certificate records. Each record carries
    ``name_value`` (one or more domains, newline-separated) and
    ``common_name``; wildcard entries look like ``*.example.com``.

The module is stdlib-only (urllib.request, json, re, socket, dataclasses)
and tolerant by design: any network/parse failure returns an empty list —
mirroring the KevClient.fetch contract from gsc_core.gsc_kev.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
HTTP_TIMEOUT = 30

# A bare "*." or "*" alone (with nothing after the dot) is not a useful
# subdomain — we strip the leading wildcard marker. The apex itself
# ("example.com") is matched by the suffix check, not by a wildcard rule.
_WILDCARD_PREFIX = "*."


# ── Data class ────────────────────────────────────────────
@dataclass
class EnumResult:
    """Result of a passive subdomain enumeration run against one apex domain."""
    domain: str
    subdomains: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": list(self.subdomains),
        }


# ── Pure parser (no network) ──────────────────────────────
def parse_crt_sh_json(payload: object, domain: str) -> List[str]:
    """Extract raw domain strings from a crt.sh JSON payload.

    Tolerant: ``None``, non-list input, non-dict records and records
    without a ``name_value`` field are skipped. Each ``name_value`` is
    split on ``"\\n"`` so multi-domain certificate entries are
    flattened into individual host strings. ``common_name`` is NOT
    consumed — crt.sh places the FQDN apex there and adding it would
    pollute the result with duplicates and the bare apex when the
    caller is filtering by suffix anyway.

    Returns a list of raw host strings (not lower-cased, not
    de-duplicated, not suffix-filtered). The ``domain`` argument is
    currently unused at the parser level; it is kept on the signature
    so future heuristics (e.g. TLD-aware splitting) can pivot on the
    apex without breaking callers.
    """
    del domain  # see docstring — reserved for future heuristics

    out: List[str] = []
    if not isinstance(payload, list):
        return out
    for record in payload:
        if not isinstance(record, dict):
            continue
        name_value = record.get("name_value", "")
        if not isinstance(name_value, str):
            # Some malformed rows may have non-strings (None, int). Skip.
            continue
        if not name_value:
            continue
        # crt.sh packs multiple hostnames into one field, "\n"-separated.
        for piece in name_value.split("\n"):
            out.append(piece)
    return out


# ── Pure normalisation (no network) ───────────────────────
def normalize_subdomains(domains: List[str], apex: str) -> List[str]:
    """Lower-case, strip, de-duplicate and suffix-filter a raw domain list.

    Behaviour:
      * ``None`` or non-list input returns ``[]``.
      * Non-string elements are skipped.
      * The leading ``"*"`` wildcard marker is stripped (``"*.example.com"``
        becomes ``"example.com"``); a pure wildcard entry (``"*"`` or
        ``"."``) becomes empty and is dropped.
      * A host is kept iff it equals ``apex`` or ends with ``".{apex}"``.
        This blocks unrelated TLD-suffix collisions (e.g. "notexample.com"
        when the apex is "example.com").
      * Output is sorted, de-duplicated, lower-cased.

    Empty ``apex`` is treated as "no filter": all cleaned, de-duped
    entries are returned. This keeps the function safe for callers that
    pass a user-supplied string which might be blank.
    """
    if not isinstance(domains, list):
        return []
    apex_clean = apex.strip().lower() if isinstance(apex, str) else ""

    seen = set()
    for raw in domains:
        if not isinstance(raw, str):
            continue
        host = raw.strip().lower()
        if not host:
            continue
        if host.startswith(_WILDCARD_PREFIX):
            host = host[len(_WILDCARD_PREFIX):]
        if not host or host == "*":
            continue
        if apex_clean:
            if host != apex_clean and not host.endswith("." + apex_clean):
                continue
        seen.add(host)
    return sorted(seen)


# ── Pure DNS resolution (network) ─────────────────────────
def resolve_host(host: str) -> Optional[str]:
    """Resolve ``host`` to its first A/AAAA address, or ``None`` on failure.

    Uses ``socket.getaddrinfo`` (stdlib only, no dnspython). Tolerant:
    any exception (``socket.gaierror``, ``UnicodeError``, empty input,
    non-string types) returns ``None`` instead of raising. The returned
    string is the ``sockaddr[0]`` of the first resolved address — IPv4
    or IPv6, as a string.
    """
    if not isinstance(host, str) or not host.strip():
        return None
    try:
        infos = socket.getaddrinfo(host.strip(), None)
    except Exception:
        return None
    if not infos:
        return None
    try:
        return infos[0][4][0]
    except (IndexError, TypeError):
        return None


def filter_live(domains: List[str]) -> List[str]:
    """Keep only domains that resolve via ``resolve_host``.

    This performs one DNS query per domain — only invoke it when an
    extra network round-trip is acceptable. ``SubdomainClient.fetch``
    does NOT call this internally (it already spent a network round
    trip on crt.sh); call sites that need a "live hosts" subset should
    invoke it explicitly after ``fetch``.
    """
    if not isinstance(domains, list):
        return []
    live: List[str] = []
    for d in domains:
        if not isinstance(d, str) or not d:
            continue
        if resolve_host(d) is not None:
            live.append(d)
    return live


# ── Subdomain Client (network) ────────────────────────────
class SubdomainClient:
    """Fetch subdomains for a single apex domain from crt.sh.

    Tolerant: any network/parse failure (timeout, HTTP error,
    non-JSON response, schema drift) returns an empty list. The caller
    never has to handle exceptions raised by this class — the contract
    matches ``KevClient.fetch`` in ``gsc_core.gsc_kev``.
    """

    def __init__(self, timeout: int = HTTP_TIMEOUT) -> None:
        self.timeout = timeout

    def fetch(self, domain: str) -> List[str]:
        """Download crt.sh for ``domain`` and return a normalized, sorted list.

        ``domain`` is the apex (e.g. ``"example.com"``) — no protocol
        prefix. The URL template prepends ``%25.`` so crt.sh matches
        any host ending with ``.domain`` (the literal ``%`` percent-
        encodes the dot, so crt.sh treats it as "any subdomain").

        On any failure the function returns ``[]``. The returned list
        is the result of ``normalize_subdomains(parsed, apex)`` —
        lower-cased, de-duplicated, suffix-filtered, sorted.
        """
        if not isinstance(domain, str) or not domain.strip():
            return []
        apex = domain.strip()
        url = CRT_SH_URL.format(domain=apex)
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                raw = resp.read()
            payload = json.loads(raw)
        except Exception:
            return []
        raw_hosts = parse_crt_sh_json(payload, apex)
        return normalize_subdomains(raw_hosts, apex)
