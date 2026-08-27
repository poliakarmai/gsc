# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE
#
# YAML-NETSCALER001 — Citrix NetScaler misconfiguration surface
# Based on: CVE-2026-19490 (auth bypass, AAA / SAML / VPN vservers),
#           CVE-2026-19489 (DoS via SIP ALG in LSN groups).
#
# Surface-flag only: the detector marks configuration lines that
# correspond to known-vulnerable NetScaler features. Whether the
# deployment is actually vulnerable depends on the exact build
# (13.1-63.21, 14.1-73.3) and configuration context. Manual review
# of `ns.conf` is required.

from ..base import RegexDetector

RULE_ID = "YAML-NETSCALER001"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "Citrix NetScaler misconfiguration surface: flags ns.conf lines "
    "associated with known authentication-bypass (CVE-2026-19490) and "
    "SIP ALG denial-of-service (CVE-2026-19489) vulnerabilities. "
    "Surface-flag for review, not a confirmed vulnerability — depends on version."
)

patterns = [
    # 1. SAML IdP action — auth-bypass surface (CVE-2026-19490).
    [r"add\s+authentication\s+samlAction\s+\S+",
     "NetScaler: SAML action configured — auth-bypass surface (CVE-2026-19490, check version)"],

    # 2. Authentication vserver (AAA virtual server).
    [r"add\s+authentication\s+vserver\s+\S+",
     "NetScaler: authentication vserver (AAA) — auth-bypass surface (CVE-2026-19490)"],

    # 3. VPN vserver (SSL VPN / ICA Proxy / CVPN / RDP Proxy).
    [r"add\s+vpn\s+vserver\s+\S+",
     "NetScaler: VPN vserver — auth-bypass surface (CVE-2026-19490)"],

    # 4. LSN group with SIP ALG — DoS surface (CVE-2026-19489).
    [r"add\s+lsn\s+group\s+\S+.*sipalg",
     "NetScaler: LSN group with SIP ALG — DoS surface (CVE-2026-19489)"],

    # 5. bind vpn vserver — attaches policies/groups to a VPN vserver;
    #    another auth-bypass surface marker.
    [r"bind\s+vpn\s+vserver\s+\S+",
     "NetScaler: bind to VPN vserver — review auth-bypass surface (CVE-2026-19490)"],

    # 6. add vpn sessionAction — VPN session policy/action (auth context).
    [r"add\s+vpn\s+sessionAction\s+\S+",
     "NetScaler: VPN session action defined — review auth-bypass surface (CVE-2026-19490)"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="netscaler-misconfig",
    patterns=patterns,
    severity="HIGH",
    confidence=0.85,
    languages=(),
    not_patterns=[
        r"^\s*#",   # commented-out ns.conf line — not an active config
        r"^\s*//",  # alternative comment marker
    ],
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
