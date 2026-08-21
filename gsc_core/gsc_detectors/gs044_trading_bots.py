# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS044 — Trading bot audit.

Detects security defects in cryptocurrency trading-bot code:

  - Replay-prone request signing: hardcoded nonce, timestamp used as nonce,
    recvWindow explicitly disabled.
  - Unvalidated order parameters taken straight from untrusted input
    (input(), sys.argv, HTTP request) without sanity checks.
  - Non-atomic check-then-act races on shared position/balance state
    (no lock around read-modify-write).
  - Unauthenticated webhook/RPC endpoints that can place trades.

Exchange API keys are intentionally NOT handled here — GS041 already
covers leaked exchange credentials, so this detector does not duplicate it.

All matches are filtered through a lexical code mask so that comments,
string literals and docstrings never produce findings.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS044"
ECHELON = 2
NOISE_TIER = "sensitive"
description = (
    "Trading bot security — replay-prone signing, unvalidated orders, "
    "check-then-act races, unauthenticated trading endpoints"
)

# File extensions this detector inspects.
_EXTS = (".py", ".js", ".jsx", ".ts", ".mjs", ".cjs")

# Trading-context keywords: a file is only inspected for signing/order defects
# if it is clearly a trading bot, not e.g. an e-commerce "create_order".
_TRADING_CONTEXT = (
    "trading", "exchange", "ccxt", "binance", "bybit", "okx", "okex",
    "coinbase", "kraken", "huobi", "gateio", "gate.io", "kucoin", "deribit",
    "bitmex", "order_book", "orderbook", "ticker", "candle", "ohlcv",
    "leverage", "stop_loss", "stop-loss", "take_profit", "take-profit",
    "futures", "margin", "pnl", "spot trade", "cryptocurrency", "altcoin",
)

# Order-placement calls (snake_case + camelCase, case-insensitive). The
# trailing `\s*\(` requires an invocation, so `import place_order` or a bare
# reference does not count.
_ORDER_CALL_RE = re.compile(
    r"(?i)\b(?:create|place|submit|execute|post)_?"
    r"(?:market|limit)?_?"
    r"(?:buy|sell)?_?"
    r"order\w*\s*\("
)

# ── Rule 1: replay-prone signing ────────────────────────────────────────────

TS_AS_NONCE_RE = re.compile(
    r"(?i)\bnonce\s*[:=]\s*"
    r"(?:int\s*\(\s*)?(?:time\.time\s*\(|datetime\.now\s*\(|"
    r"Date\.now\s*\(|performance\.now\s*\(|gettimeofday)"
)

NONCE_HARDCODED_RE = re.compile(
    r"(?i)\bnonce\s*[:=]\s*[\"']?\d{1,10}[\"']?\s*(?:#.*)?$",
    re.MULTILINE,
)

RECVWINDOW_ZERO_RE = re.compile(r"(?i)\brecv_?[Ww]indow\s*[:=]\s*0\b")


# ── Rule 2: unvalidated order parameters ────────────────────────────────────

_UNTRUSTED_SOURCE = (
    r"input\s*\(|sys\.argv|request\.(?:args|form|json|values|get_json)|"
    r"req\.(?:query|body|params)"
)
_UNVALIDATED_QTY_RE = re.compile(
    r"(?i)\b(?:qty|quantity|amount|size|volume|price)\s*=\s*"
    r"(?:float|int|Decimal|Number)\s*\(\s*(?:" + _UNTRUSTED_SOURCE + r")"
)


# ── Rule 3: check-then-act race ─────────────────────────────────────────────

_SHARED_STATE_RE = re.compile(
    r"(?i)\b(?:positions|open_positions|get_position|get_positions|"
    r"balance|equity|get_balance|margin_balance|available_balance|"
    r"self\.position|current_position)\b"
)
_LOCK_RE = re.compile(
    r"(?i)\b(?:threading\.)?(?:Lock|RLock|Semaphore)\s*\(|"
    r"asyncio\.Lock\s*\(|"
    r"with\s+self\.(?:lock|mutex)\b|"
    r"\.acquire\s*\(|@synchronized"
)


# ── Rule 4: unauthenticated trading endpoint ────────────────────────────────

_ROUTE_RE = re.compile(
    r"(?i)@(?:app|application|bp|blueprint|router|api|server)\.(?:route|get|post|put|delete|add_url_rule)\s*\(|"
    r"\b(?:app|router|server|api)\.(?:get|post|put|delete)\s*\(\s*[\"']"
)
_AUTH_RE = re.compile(
    r"(?i)@(?:login_required|require_?auth|auth_?required|token_?required|"
    r"jwt_?required|roles_?required|permission_?required|is_authenticated)\b|"
    r"Depends\s*\(\s*(?:get_current|get_user|verify|auth|require|check)|"
    r"passport\.authenticate|verify_?token\s*\(|authorization\s*(?:=|in)|"
    r"\bapi[_-]?key\b"
)

# window (in lines) searched around an order call for route/auth/lock context
_WINDOW = 40

# A line whose text up to the order-call token is a def/class/function/arrow
# declaration — i.e. the token is a *definition*, not an invocation.
_DEF_PREFIX_RE = re.compile(r"(?:async\s+def|def|function|class|=>)\s*$")


def _code_mask(content: str) -> list[bool]:
    """Per-character mask: True where real code, False in comments/strings."""
    n = len(content)
    mask = [True] * n
    i = 0
    while i < n:
        c = content[i]
        if content.startswith(('"""', "'''"), i):
            q = content[i:i + 3]
            j = content.find(q, i + 3)
            end = n if j == -1 else j + 3
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if c == '#':
            j = content.find('\n', i)
            end = n if j == -1 else j
            for k in range(i, end):
                mask[k] = False
            i = end
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n:
                if content[j] == '\\':
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


def _is_definition(content: str, m: re.Match) -> bool:
    """True when the matched order-call token is a definition, not a call."""
    line_start = content.rfind("\n", 0, m.start()) + 1
    prefix = content[line_start:m.start()]
    return bool(_DEF_PREFIX_RE.search(prefix))


def _is_trading(content: str) -> bool:
    low = content.lower()
    return any(k in low for k in _TRADING_CONTEXT)


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


def _window(lines: list[str], line_idx: int, before: int, after: int) -> str:
    lo = max(0, line_idx - before)
    hi = min(len(lines), line_idx + after)
    return "\n".join(lines[lo:hi])


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

        has_order_call = _ORDER_CALL_RE.search(content) is not None
        if not has_order_call and not _is_trading(content):
            # neither an order call nor trading context -> not a trading bot
            continue

        mask = _code_mask(content)
        lines = content.split("\n")

        def _line_no(pos: int) -> int:
            return content[:pos].count("\n") + 1

        def _is_code(m: re.Match) -> bool:
            return mask[m.start()]

        # ── Rule 1a: timestamp used as nonce (replay) ──
        for m in TS_AS_NONCE_RE.finditer(content):
            if not _is_code(m):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()), "Timestamp used as request nonce (replayable)",
                "HIGH",
                "nonce derived from wall-clock time only; requests can be replayed "
                "within the same timestamp window",
                "Use a strictly monotonic nonce (increment a counter per request) "
                "and enable recvWindow.",
                ["CWE-294 (Authentication Bypass by Capture-replay)"],
            ))

        # ── Rule 1b: hardcoded nonce (replay) ──
        for m in NONCE_HARDCODED_RE.finditer(content):
            if not _is_code(m):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()), "Hardcoded nonce (replay attack)",
                "HIGH",
                "nonce is a constant; every signed request reuses the same value",
                "Generate a fresh, monotonic nonce per request.",
                ["CWE-294 (Authentication Bypass by Capture-replay)"],
            ))

        # ── Rule 1c: recvWindow disabled ──
        for m in RECVWINDOW_ZERO_RE.finditer(content):
            if not _is_code(m):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()), "recvWindow disabled (replay window open)",
                "MEDIUM",
                "recvWindow is 0, removing the server-side timestamp validity window",
                "Set a sane recvWindow (e.g. 5000 ms) so stale signed requests are rejected.",
                ["CWE-294 (Authentication Bypass by Capture-replay)"],
            ))

        # ── Rule 2: unvalidated order parameters from untrusted input ──
        for m in _UNVALIDATED_QTY_RE.finditer(content):
            if not _is_code(m):
                continue
            findings.append(_mk(
                rel, _line_no(m.start()),
                "Order size/price from unvalidated external input",
                "HIGH",
                "order quantity/price is parsed directly from untrusted input "
                "(input()/argv/HTTP) with no bounds check — a malformed value can "
                "submit a wrong-sized order",
                "Validate against min/max bounds, precision and sign before placing the order.",
                ["CWE-20 (Improper Input Validation)",
                 "CWE-1284 (Improper Validation of Specified Quantity in Input)"],
            ))

        if not has_order_call:
            continue

        # ── Rules 3 & 4: per order-call context ──
        for m in _ORDER_CALL_RE.finditer(content):
            if not _is_code(m):
                continue
            if _is_definition(content, m):
                continue  # interface/abstract method, not an actual order
            line_no = _line_no(m.start())
            line_idx = line_no - 1
            w = _window(lines, line_idx, _WINDOW, 10)

            # Rule 4: unauthenticated trading endpoint
            if _ROUTE_RE.search(w) and not _AUTH_RE.search(w):
                findings.append(_mk(
                    rel, line_no,
                    "Unauthenticated trading endpoint",
                    "CRITICAL",
                    "an HTTP route places orders with no authentication check — "
                    "any caller can submit trades",
                    "Require authentication/authorization on every order-placing endpoint.",
                    ["CWE-306 (Missing Authentication for Critical Function)"],
                ))

            # Rule 3: check-then-act race on shared state
            if _SHARED_STATE_RE.search(w) and not _LOCK_RE.search(w):
                findings.append(_mk(
                    rel, line_no,
                    "Non-atomic check-then-act on position/balance",
                    "MEDIUM",
                    "shared position/balance state is read and then mutated by an "
                    "order call without locking — concurrent cycles can double-fill",
                    "Guard read-modify-write with a lock (threading.Lock / asyncio.Lock) "
                    "or use an atomic exchange-side conditional order.",
                    ["CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)"],
                ))

    return findings
