# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""GSC Recon layer — passive reconnaissance (bug bounty / attack surface).

Modules follow ``RECON_CONTRACT.md``: fetch → parse → normalize, stdlib-only,
tolerant to network errors. The pipeline is orchestrated by
``gsc_recon.orchestrator``; individual modules never import each other.
"""

from gsc_recon.dns_enum import (
    DnsClient,
    DnsRecord,
    build_query,
    parse_dns_response,
    resolve_a,
    resolve_aaaa,
    resolve_cname,
    resolve_mx,
    resolve_ns,
    resolve_txt,
)
from gsc_recon.http_probe import (
    HttpClient,
    ProbeResult,
    extract_server,
    is_reachable,
    normalize_url,
)
from gsc_recon.orchestrator import ReconReport, run_recon
from gsc_recon.subdomain_enum import (
    EnumResult,
    SubdomainClient,
    filter_live,
    normalize_subdomains,
    parse_crt_sh_json,
    resolve_host,
)
from gsc_recon.tech_detect import (
    TECH_SIGNATURES,
    TechMatch,
    TechSignature,
    classify_stack,
    detect_tech,
)

__all__ = [
    # dns_enum
    "DnsClient",
    "DnsRecord",
    "build_query",
    "parse_dns_response",
    "resolve_a",
    "resolve_aaaa",
    "resolve_cname",
    "resolve_mx",
    "resolve_ns",
    "resolve_txt",
    # http_probe
    "HttpClient",
    "ProbeResult",
    "extract_server",
    "is_reachable",
    "normalize_url",
    # orchestrator
    "ReconReport",
    "run_recon",
    # subdomain_enum
    "EnumResult",
    "SubdomainClient",
    "filter_live",
    "normalize_subdomains",
    "parse_crt_sh_json",
    "resolve_host",
    # tech_detect
    "TECH_SIGNATURES",
    "TechMatch",
    "TechSignature",
    "classify_stack",
    "detect_tech",
]
