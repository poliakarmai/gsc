# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS043 — Honeypot / rug-pull detector.

Heuristic scan of ``.sol`` source for mechanics commonly found in
honeypot tokens and rug-pull scams:

  - Owner-controlled trading enable/disable switch (buyers can never sell)
  - Blacklist mechanism that blocks specific addresses from selling
  - Unrestricted (unguarded) mint capability — infinite supply / rug vector
  - Owner-controlled fee/tax setters without a visible cap

The Solidity lexical mask is reused from GS042 so comments/strings never fire.
"""

from __future__ import annotations

import re

from . import AuditContext, Finding
from .gs042_solidity import solidity_code_mask

RULE_ID = "GS043"
ECHELON = 2
NOISE_TIER = "sensitive"
description = (
    "Honeypot / rug-pull — trading switch, blacklist, unrestricted mint, "
    "owner-controlled fee"
)

_EXTS = (".sol",)

# ── Rules ───────────────────────────────────────────────────────────────────

# Owner-controlled trading on/off switch (the definitive honeypot mechanic)
_TRADING_TOGGLE_RE = re.compile(
    r"(?i)\b(?:enableTrading|disableTrading|setTradingEnabled|setTradingStatus|"
    r"setTradeEnabled|setTradingActive|toggleTrading|pauseTrading|resumeTrading|"
    r"setTradingOpen)\s*\("
)

# Blacklist that can block specific addresses from selling
_BLACKLIST_RE = re.compile(
    r"(?i)\b(?:blacklist|isBlacklisted|blackListed|blackList|_blacklist|"
    r"_isBlacklisted|blacklistAddress|removeFromBlacklist|addToBlacklist)\b"
)

# Public/external mint function (rug vector if unguarded)
_MINT_FN_RE = re.compile(
    r"(?i)\bfunction\s+\w*mint\w*\s*\([^)]*\)\s*(?:public|external)\b"
)

# Owner-controlled fee/tax setter (can be raised toward 100% = rug)
_FEE_SETTER_RE = re.compile(
    r"(?i)\b(?:setFee|setFees|setTax|setTaxRate|setBuyFee|setSellFee|"
    r"setBuyTax|setSellTax|setTransferTax|updateFee|updateTax|setFeeRate)\s*\("
)

# Access-control guard (reused semantics from GS042)
_GUARD_RE = re.compile(
    r"(?i)(?:onlyOwner|onlyRole|onlyAdmin|onlyAuthorized|onlyVault|onlyGovernance|"
    r"isOwner|isAdmin|isAuthorized|"
    r"require\s*\(\s*(?:_\s*)?msg\.sender|"
    r"assert\s*\(\s*(?:_\s*)?msg\.sender|"
    r"\bif\s*\(\s*(?:_\s*)?msg\.sender)"
)

_MINT_WINDOW = 50


def _mk(rel_path: str, line_no: int, title: str, severity: str, detail: str,
        fix: str, refs: list[str]) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        category=severity,
        title=title,
        file_path=rel_path,
        line=line_no,
        detail=detail,
        fix_suggestion=fix,
        references=refs,
    )


def detect(ctx: AuditContext) -> list[Finding]:
    if RULE_ID in ctx.skipped_detectors:
        return []

    findings: list[Finding] = []

    for fp in ctx.get_files(extensions=_EXTS):
        if ctx.is_test_file(fp):
            continue
        try:
            content = ctx.read_file(fp)
        except Exception:
            continue
        if not content:
            continue
        rel = str(fp.relative_to(ctx.path))
        mask = solidity_code_mask(content)
        lines = content.split("\n")
        emitted: set[str] = set()  # honeypot rules are presence-based: one per file

        def _line_no(pos: int, content=content) -> int:
            return content[:pos].count("\n") + 1

        def _once(title: str, emitted=emitted) -> bool:
            if title in emitted:
                return False
            emitted.add(title)
            return True

        # 1. trading toggle (honeypot)
        for m in _TRADING_TOGGLE_RE.finditer(content):
            if not mask[m.start()] or not _once("trading switch"):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()),
                "Owner-controlled trading switch (honeypot indicator)",
                "HIGH",
                "trading can be enabled/disabled by the owner — buyers may be "
                "unable to sell after launch",
                "Remove the trading switch, or keep trading permanently enabled.",
                ["Honeypot token scam (sell restriction)", "CWE-841"],
            ))

        # 2. blacklist (honeypot)
        for m in _BLACKLIST_RE.finditer(content):
            if not mask[m.start()] or not _once("blacklist"):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()),
                "Blacklist mechanism can block selling (honeypot indicator)",
                "HIGH",
                "addresses can be blacklisted, letting the owner block holders "
                "from selling",
                "Remove the blacklist, or restrict it to documented compliance "
                "use with a clear policy.",
                ["Honeypot token scam (blacklist sell restriction)", "CWE-284"],
            ))

        # 3. unrestricted mint (rug vector)
        for m in _MINT_FN_RE.finditer(content):
            if not mask[m.start()] or not _once("unrestricted mint"):
                continue
            line_no = _line_no(m.start())
            line_idx = line_no - 1
            body = "\n".join(lines[line_idx:line_idx + _MINT_WINDOW])
            if _GUARD_RE.search(body):
                emitted.discard("unrestricted mint")
                continue  # guarded mint — legit
            findings.append(_mk(
                rel, line_no, "Unrestricted mint capability (rug vector)",
                "HIGH",
                "a public/external mint function has no access control — anyone "
                "can mint tokens and inflate/dump the supply",
                "Guard mint behind onlyOwner / a role, or enforce a hard supply cap.",
                ["CWE-284 (Improper Access Control)", "SWC-106"],
            ))

        # 4. fee/tax setter (rug indicator)
        for m in _FEE_SETTER_RE.finditer(content):
            if not mask[m.start()] or not _once("fee setter"):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()),
                "Owner-controlled fee/tax setter (rug indicator)",
                "MEDIUM",
                "buy/sell fee is owner-settable with no visible upper bound — "
                "can be raised to confiscate transfers",
                "Cap the fee at a low, documented maximum and enforce it in code.",
                ["Rug pull (owner-controlled fee)", "CWE-284"],
            ))

    return findings
