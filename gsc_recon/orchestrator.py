# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Recon orchestrator — the single entry point of the recon layer.

Pipeline: subdomain enumeration → [optional] DNS resolve/enumeration →
[optional] HTTP probing → [optional] tech detection.

The orchestrator is the *only* place that wires modules together — the
modules themselves never import each other. Each stage is opt-in via a
flag; the default is the cheapest passive stage (subdomain enumeration).

The resolve / DNS / HTTP stages run concurrently (stdlib
``concurrent.futures.ThreadPoolExecutor``) while preserving deterministic
output order: results are collected in the original subdomain order, not
in the order workers happen to finish.

Follows ``RECON_CONTRACT.md``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from gsc_recon.dns_enum import DnsClient, DnsRecord
from gsc_recon.http_probe import HttpClient, ProbeResult, normalize_url
from gsc_recon.subdomain_enum import SubdomainClient, filter_live, resolve_host
from gsc_recon.tech_detect import TechMatch, detect_tech


@dataclass
class ReconReport:
    """Aggregated recon result for one apex domain."""

    domain: str
    subdomains: List[str] = field(default_factory=list)
    resolved: Dict[str, str] = field(default_factory=dict)
    dns: Dict[str, List[DnsRecord]] = field(default_factory=dict)
    http: List[ProbeResult] = field(default_factory=list)
    tech: Dict[str, List[TechMatch]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": list(self.subdomains),
            "resolved": dict(self.resolved),
            "dns": {h: [r.to_dict() for r in recs] for h, recs in self.dns.items()},
            "http": [p.to_dict() for p in self.http],
            "tech": {h: [t.to_dict() for t in ms] for h, ms in self.tech.items()},
        }


_DNS_QTYPES = ("A", "CNAME", "MX", "TXT", "NS")


def run_recon(
    domain: str,
    resolve: bool = False,
    live: bool = False,
    dns: bool = False,
    http: bool = False,
    tech: bool = False,
    timeout: int = 30,
    max_workers: int = 10,
    client: Optional[SubdomainClient] = None,
    dns_client: Optional[DnsClient] = None,
    http_client: Optional[HttpClient] = None,
) -> ReconReport:
    """Run the recon pipeline over ``domain``.

    All clients are injectable for tests; otherwise fresh instances are
    created. Network failures are tolerated inside every stage — they yield
    empty results rather than raising. ``tech`` requires ``http`` (tech
    detection runs over the headers collected by the HTTP probe stage).

    The resolve / DNS / HTTP stages run concurrently with ``max_workers``
    threads; output order stays deterministic (original subdomain order).
    """
    cli = client if client is not None else SubdomainClient(timeout=timeout)
    subdomains = cli.fetch(domain)
    if live:
        subdomains = filter_live(subdomains)

    resolved: Dict[str, str] = {}
    if resolve:
        def _resolve_one(host: str):
            try:
                return host, resolve_host(host)
            except Exception:
                return host, None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for host, ip in executor.map(_resolve_one, subdomains):
                if ip:
                    resolved[host] = ip

    dns_records: Dict[str, List[DnsRecord]] = {}
    if dns:
        dc = dns_client if dns_client is not None else DnsClient(timeout=timeout)

        def _query_one(pair):
            host, qtype = pair
            try:
                return host, qtype, dc.query(host, qtype)
            except Exception:
                return host, qtype, []

        tasks = [(s, q) for s in subdomains for q in _DNS_QTYPES]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for host, qtype, recs in executor.map(_query_one, tasks):
                if recs:
                    dns_records.setdefault(host, []).extend(recs)

    http_results: List[ProbeResult] = []
    if http:
        hc = http_client if http_client is not None else HttpClient(timeout=timeout)

        def _probe_one(host: str) -> ProbeResult:
            url = normalize_url(host) or host
            try:
                return hc.probe_hosts([host])[0]
            except Exception as exc:
                return ProbeResult(url=url, valid=False, error=str(exc)[:200])

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            http_results = list(executor.map(_probe_one, subdomains))

    tech_map: Dict[str, List[TechMatch]] = {}
    if tech:
        for pr in http_results:
            if pr.valid and pr.headers:
                matches = detect_tech(pr.headers, "")
                if matches:
                    tech_map[pr.url] = matches

    return ReconReport(
        domain=domain,
        subdomains=subdomains,
        resolved=resolved,
        dns=dns_records,
        http=http_results,
        tech=tech_map,
    )
