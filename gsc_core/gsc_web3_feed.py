# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
Web3/Solidity SCA feed — manual CVE list + Solidity compiler known bugs.

Two data sources that OSV.dev does not (fully) cover:

1. WEB3_MANUAL_CVE_FEED — curated npm CVEs for @openzeppelin/contracts.
   Offline/deterministic fallback so web3 SCA keeps working when OSV is
   unreachable. Every entry is sourced from OSV.dev records (verified
   2026-08-21) — no invented data.

2. SOLC_BUGS — Solidity compiler known bugs from the official
   ethereum/solidity ``docs/bugs.json`` (verified 2026-08-21), plus the
   language-level rule that ``<0.8.0`` leaves arithmetic unchecked (SWC-101).

Only accurate, source-verified data lives here.
"""

from __future__ import annotations

# ── Manual npm web3 CVE feed ────────────────────────────────────────────────
# Each entry: id, aliases, summary, severity, ranges [(introduced, fixed)], fixed.
# Ranges are half-open [introduced, fixed) matching OSV ECOSYSTEM semantics.
# `introduced` of "0" means all versions.

WEB3_MANUAL_CVE_FEED: dict[str, list[dict]] = {
    "npm:@openzeppelin/contracts": [
        {
            "id": "CVE-2021-41264",
            "aliases": ["GHSA-5vp3-v4hc-gx76"],
            "summary": "UUPSUpgradeable: upgradeToAndCall can re-call the initializer",
            "severity": "CRITICAL",
            "ranges": [("4.1.0", "4.3.2")],
            "fixed": "4.3.2",
        },
        {
            "id": "CVE-2021-39167",
            "aliases": ["GHSA-fg47-3c2x-m2wr"],
            "summary": "TimelockController: executor role can bypass delay via schedule",
            "severity": "CRITICAL",
            "ranges": [("4.0.0", "4.3.1"), ("3.3.0", "3.4.2")],
            "fixed": "4.3.1",
        },
        {
            "id": "CVE-2021-46320",
            "aliases": ["GHSA-88g8-f5mf-f5rj", "CVE-2022-39384", "GHSA-9c22-pwxw-p6hx"],
            "summary": "Improper Initialization: initializer reentrancy may double-initialize",
            "severity": "HIGH",
            "ranges": [("0", "4.4.1")],
            "fixed": "4.4.1",
        },
        {
            "id": "CVE-2022-31172",
            "aliases": ["GHSA-4g63-c64m-25w9"],
            "summary": "SignatureChecker may revert on invalid EIP-1271 signers",
            "severity": "HIGH",
            "ranges": [("4.1.0", "4.7.1")],
            "fixed": "4.7.1",
        },
        {
            "id": "CVE-2022-35961",
            "aliases": ["GHSA-4h98-2769-gh6h"],
            "summary": "ECDSA signature malleability in ECDSA.recover",
            "severity": "HIGH",
            "ranges": [("4.1.0", "4.7.3")],
            "fixed": "4.7.3",
        },
        {
            "id": "CVE-2022-31170",
            "aliases": ["GHSA-qh9x-gcfh-pcrw"],
            "summary": "ERC165Checker may revert instead of returning false",
            "severity": "HIGH",
            "ranges": [("4.0.0", "4.7.1")],
            "fixed": "4.7.1",
        },
        {
            "id": "CVE-2022-31198",
            "aliases": ["GHSA-xrc4-737v-9q75"],
            "summary": "GovernorVotesQuorumFraction updates may affect past proposals",
            "severity": "HIGH",
            "ranges": [("4.3.0", "4.7.2")],
            "fixed": "4.7.2",
        },
        {
            "id": "CVE-2023-30542",
            "aliases": ["GHSA-93hq-5wgc-jc82"],
            "summary": "GovernorCompatibilityBravo may trim proposal calldata",
            "severity": "HIGH",
            "ranges": [("4.3.0", "4.8.3")],
            "fixed": "4.8.3",
        },
    ],
}


# ── Solidity compiler known bugs ────────────────────────────────────────────
# Sourced from ethereum/solidity docs/bugs.json (2026-08-21). Half-open
# [introduced, fixed) ranges. The first entry is the language-level rule that
# solc <0.8.0 compiles with unchecked arithmetic by default (SWC-101).

SOLC_BUGS: list[dict] = [
    {
        "name": "UncheckedArithmetic",
        "summary": "Solidity <0.8.0 leaves arithmetic unchecked by default (integer overflow)",
        "severity": "HIGH",
        "introduced": "0.0.1",
        "fixed": "0.8.0",
        "references": ["SWC-101", "https://docs.soliditylang.org/en/latest/080-breaking-changes.html"],
    },
    {
        "name": "TransientStorageClearingHelperCollision",
        "summary": "Transient storage clearing helper name collision",
        "severity": "HIGH",
        "introduced": "0.8.28",
        "fixed": "0.8.34",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
    {
        "name": "HighOrderByteCleanStorage",
        "summary": "High-order byte clean storage corruption",
        "severity": "HIGH",
        "introduced": "0.1.6",
        "fixed": "0.4.4",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
    {
        "name": "AncientCompiler",
        "summary": "Ancient compiler versions are considered unsafe",
        "severity": "HIGH",
        "introduced": "0.0.1",
        "fixed": "0.3.0",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
    {
        "name": "InlineAssemblyMemorySideEffects",
        "summary": "Inline assembly memory side effects ignored by optimizer",
        "severity": "MEDIUM",
        "introduced": "0.8.13",
        "fixed": "0.8.15",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
    {
        "name": "AbiReencodingHeadOverflowWithStaticArrayCleanup",
        "summary": "ABI re-encoding head overflow with static array cleanup",
        "severity": "MEDIUM",
        "introduced": "0.5.8",
        "fixed": "0.8.16",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
    {
        "name": "KeccakCaching",
        "summary": "Keccak caching collision in the optimizer",
        "severity": "MEDIUM",
        "introduced": "0.0.1",
        "fixed": "0.8.3",
        "references": ["https://docs.soliditylang.org/en/latest/bugs.html"],
    },
]


def parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable tuple of ints.

    Padded to 4 components so tuple comparison follows semver semantics:
    missing trailing components are zero (``1.2`` == ``1.2.0``).
    """
    parts = []
    for part in (v or "").replace("v", "").split("."):
        m = ""
        for ch in part:
            if ch.isdigit():
                m += ch
            else:
                break
        parts.append(int(m) if m else 0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def version_in_range(version: str, introduced: str, fixed: str) -> bool:
    """True when `version` is in the half-open range [introduced, fixed)."""
    v = parse_version(version)
    lo = parse_version(introduced) if introduced else ()
    if lo and v < lo:
        return False
    if fixed:
        if v >= parse_version(fixed):
            return False
    return True


def manual_vulns(ecosystem: str, name: str, version: str) -> list[dict]:
    """Return OSV-compatible vuln dicts from the manual feed for a package."""
    key = f"{ecosystem}:{name}"
    out = []
    for entry in WEB3_MANUAL_CVE_FEED.get(key, []):
        if any(version_in_range(version, lo, hi) for lo, hi in entry["ranges"]):
            out.append({
                "id": entry["id"],
                "aliases": entry["aliases"],
                "summary": entry["summary"],
                "database_specific": {"severity": entry["severity"]},
                "affected": [{
                    "package": {"name": name},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": lo, "fixed": hi}
                                   for lo, hi in entry["ranges"]],
                    }],
                }],
                "source": "gsc-manual-feed",
            })
    return out


def solc_vulns(version: str) -> list[dict]:
    """Return OSV-compatible vuln dicts for a given solc version."""
    out = []
    for bug in SOLC_BUGS:
        if version_in_range(version, bug["introduced"], bug["fixed"]):
            out.append({
                "id": f"SOLC-BUG-{bug['name']}",
                "aliases": [],
                "summary": f"{bug['name']}: {bug['summary']}",
                "database_specific": {"severity": bug["severity"]},
                "affected": [{
                    "package": {"name": "solc"},
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": bug["introduced"],
                                    "fixed": bug["fixed"]}],
                    }],
                }],
                "source": "solc-known-bugs",
            })
    return out
