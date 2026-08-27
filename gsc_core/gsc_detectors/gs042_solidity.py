# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS042 — Solidity SAST.

Static analysis of ``.sol`` smart-contract source for well-known
vulnerability classes, mapped to the SWC registry:

  - Reentrancy via low-level ``.call{value:}`` (SWC-107)
  - ``tx.origin`` authorization (SWC-115)
  - ``delegatecall`` (SWC-112)
  - ``selfdestruct`` without access control (SWC-106)
  - ``unchecked`` arithmetic blocks (SWC-101)
  - unchecked ``.send()`` return value (SWC-104)
  - direct DEX price reads — oracle manipulation (CWE-841)

All matches are filtered through a Solidity-aware lexical mask so comments
(``//``, ``/* */``, NatSpec) and string literals never produce findings.
The mask helper is reused by GS043 (honeypot).
"""

from __future__ import annotations

import re

from . import AuditContext, Finding

RULE_ID = "GS042"
ECHELON = 2
NOISE_TIER = "sensitive"
description = (
    "Solidity SAST — reentrancy, tx.origin, delegatecall, selfdestruct, "
    "unchecked arithmetic, unchecked call return, oracle manipulation"
)

_EXTS = (".sol",)

# ── Lexical mask (shared with GS043) ────────────────────────────────────────


def solidity_code_mask(content: str) -> list[bool]:
    """Per-character mask: True where real code, False in comments/strings."""
    n = len(content)
    mask = [True] * n
    i = 0
    while i < n:
        c = content[i]
        if content.startswith("//", i):
            j = content.find("\n", i)
            end = n if j == -1 else j
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if content.startswith("/*", i):
            j = content.find("*/", i + 2)
            end = n if j == -1 else j + 2
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n:
                if content[j] == "\\":
                    j += 2
                    continue
                if content[j] == c:
                    j += 1
                    break
                j += 1
            end = min(j, n)
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        i += 1
    return mask


# ── Rules ───────────────────────────────────────────────────────────────────

REENTRANCY_RE = re.compile(r"\.call\s*\{[^}]*\bvalue\s*:|\.call\.value\s*\(")
TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")
DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(")
SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")
UNCHECKED_RE = re.compile(r"\bunchecked\s*\{")
SEND_UNCHECKED_RE = re.compile(r"\.send\s*\(")
ORACLE_RE = re.compile(
    r"\b(?:getReserves|getAmountsOut|getAmountsIn|slot0)\s*\("
)

# Access-control signals looked up in the window above a selfdestruct call.
_GUARD_RE = re.compile(
    r"(?i)(?:onlyOwner|onlyRole|onlyAdmin|onlyAuthorized|onlyVault|onlyGovernance|"
    r"isOwner|isAdmin|isAuthorized|"
    r"require\s*\(\s*(?:_\s*)?msg\.sender|"
    r"assert\s*\(\s*(?:_\s*)?msg\.sender|"
    r"\bif\s*\(\s*(?:_\s*)?msg\.sender)"
)

_GUARD_WINDOW = 50


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

        def _line_no(pos: int, content=content) -> int:
            return content[:pos].count("\n") + 1

        def _emit(m: re.Match, title: str, severity: str, detail: str,
                  fix: str, refs: list[str], rel=rel, mask=mask) -> None:
            if not mask[m.start()]:
                return
            findings.append(_mk(rel, _line_no(m.start()), title, severity,
                                detail, fix, refs))

        # 1. reentrancy via low-level .call{value:} (SWC-107)
        for m in REENTRANCY_RE.finditer(content):
            _emit(m, "Reentrancy via low-level external call", "HIGH",
                  "low-level .call forwards all remaining gas and re-enters the "
                  "contract before state is settled",
                  "Apply checks-effects-interactions, or use OpenZeppelin "
                  "ReentrancyGuard.",
                  ["SWC-107 (Reentrancy)", "CWE-841"])

        # 2. tx.origin authorization (SWC-115)
        for m in TX_ORIGIN_RE.finditer(content):
            _emit(m, "tx.origin used for authorization", "HIGH",
                  "tx.origin can be phished (an attacker contract makes the victim "
                  "EOA call a malicious contract that then calls this one)",
                  "Use msg.sender instead of tx.origin for authentication.",
                  ["SWC-115 (Authorization through tx.origin)", "CWE-477"])

        # 3. delegatecall (SWC-112)
        for m in DELEGATECALL_RE.finditer(content):
            _emit(m, "delegatecall to external address", "HIGH",
                  "delegatecall executes target code in this contract's storage "
                  "context — a malicious/user-controlled target can hijack storage",
                  "Only delegatecall to trusted, immutable addresses; never let "
                  "the target be user-supplied.",
                  ["SWC-112 (Delegatecall to Untrusted Callee)", "CWE-829"])

        # 4. selfdestruct without access control (SWC-106)
        for m in SELFDESTRUCT_RE.finditer(content):
            if not mask[m.start()]:
                continue
            line_no = _line_no(m.start())
            line_idx = line_no - 1
            lo = max(0, line_idx - _GUARD_WINDOW)
            window = "\n".join(lines[lo:line_idx + 1])
            if _GUARD_RE.search(window):
                continue  # guarded — not a finding
            findings.append(_mk(
                rel, line_no, "selfdestruct without access control", "HIGH",
                "selfdestruct is reachable without an owner/role check — anyone "
                "can destroy the contract and drain forced funds",
                "Guard selfdestruct behind onlyOwner / a require(msg.sender == owner) check.",
                ["SWC-106 (Unprotected SELFDESTRUCT)", "CWE-284"],
            ))

        # 5. unchecked arithmetic (SWC-101)
        for m in UNCHECKED_RE.finditer(content):
            _emit(m, "unchecked arithmetic block", "MEDIUM",
                  "unchecked block disables overflow/underflow checks — arithmetic "
                  "inside can wrap silently",
                  "Only use unchecked around arithmetic you have proven cannot wrap; "
                  "otherwise keep checked arithmetic.",
                  ["SWC-101 (Integer Overflow and Underflow)", "CWE-682"])

        # 6. unchecked .send() return (SWC-104)
        for m in SEND_UNCHECKED_RE.finditer(content):
            _emit(m, ".send() used (return value may be ignored)", "MEDIUM",
                  ".send() forwards a fixed 2300 gas and its bool return is often "
                  "ignored — a failed transfer silently does nothing",
                  "Prefer .call{value:} with an explicit success check, or use "
                  "address.sendValue / OpenZeppelin Address utils.",
                  ["SWC-104 (Unchecked Call Return Value)", "CWE-252"])

        # 7. direct DEX price read (oracle manipulation)
        for m in ORACLE_RE.finditer(content):
            _emit(m, "Direct DEX price read (oracle manipulation)", "MEDIUM",
                  "spot price is read straight from a DEX pair (getReserves / "
                  "getAmountsOut / slot0) and can be manipulated with a flash loan",
                  "Use a time-weighted average price (TWAP) or a decentralized "
                  "oracle (Chainlink) instead of raw spot price.",
                  ["CWE-841 (Improper Enforcement of Behavioral Workflow)",
                   "SWC-123 (Requirement Violation)"],
                  )

    return findings
