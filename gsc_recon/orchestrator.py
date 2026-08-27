# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Recon orchestrator — the single entry point of the recon layer.

Pipeline (v1): subdomain enumeration → [optional] DNS resolution.
HTTP probing + tech detection plug in as later stages; the orchestrator is
the only place that wires modules together — modules never import each other.

Follows ``RECON_CONTRACT.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from gsc_recon.subdomain_enum import SubdomainClient, filter_live, resolve_host


@dataclass
class ReconReport:
    """Aggregated recon result for one apex domain."""

    domain: str
    subdomains: List[str] = field(default_factory=list)
    resolved: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": list(self.subdomains),
            "resolved": dict(self.resolved),
        }


def run_recon(
    domain: str,
    resolve: bool = False,
    live: bool = False,
    timeout: int = 30,
    client: Optional[SubdomainClient] = None,
) -> ReconReport:
    """Enumerate subdomains for ``domain``; optionally resolve to IPs.

    ``live=True`` keeps only subdomains that actually resolve (via
    ``filter_live``). ``resolve=True`` additionally maps each surviving
    subdomain to its IP. ``client`` is injectable for tests.

    Network failures are tolerated inside ``fetch``/``resolve_host`` —
    they yield an empty list/dict rather than raising.
    """
    cli = client if client is not None else SubdomainClient(timeout=timeout)
    subdomains = cli.fetch(domain)
    if live:
        subdomains = filter_live(subdomains)
    resolved: Dict[str, str] = {}
    if resolve:
        for s in subdomains:
            ip = resolve_host(s)
            if ip:
                resolved[s] = ip
    return ReconReport(domain=domain, subdomains=subdomains, resolved=resolved)
