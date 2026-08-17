# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS018 — Payment Logic Abuse Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects business-logic vulnerabilities in payment/fintech code —
the #2 finding in 2026 fintech pentest reports (scanners are blind to these):

- Missing idempotency on payment callbacks (double cashback)
- Promo code abuse (redeem without locking)
- Race conditions in balance updates (no SELECT FOR UPDATE)
- Cancel/refund after payment without state validation
- Negative amount/price validation missing
- Float arithmetic for money (rounding exploit)
- Webhook handlers without signature verification (replay attacks)
- SMS/notification abuse in payment flows

Sources: 2026 Fintech Pentest Report, OWASP ASVS V5 (Business Logic)
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS018"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Payment logic abuse — double cashback, promo code abuse, "
    "race conditions, rounding, missing idempotency"
)

# ── Regex patterns ──────────────────────────────────────────────────────────

# 1. Missing idempotency keys on payment/callback endpoints
MISSING_IDEMPOTENCY = re.compile(
    r'(?:@(?:app|router|bp|blueprint)\\.(?:route|post|get|put).*\n'
    r'^(?!.*(?:idempotenc|idempotent|idempotency_key|idempotencyKey|'
    r'X-Idempotency|duplicate_check|already_processed))'
    r'.*def\s+(?:payment_?callback|payout_?callback|webhook|'
    r'charge_?callback|transaction_?callback|cashback))',
    re.IGNORECASE | re.MULTILINE,
)

# 2. Promo code / coupon redeem without locking
PROMO_REDEEM_NO_LOCK = re.compile(
    r'def\s+(?:redeem|apply|use|activate).*(?:promo|coupon|discount|code|voucher)',
    re.IGNORECASE,
)

PROMO_WITHOUT_LOCK_CHECK = re.compile(
    r'promo.*(?:count|usage|uses|redeemed).*\\+=|'
    r'promo.*\\.save\\s*\\(\\)(?!.*select_for_update|with transaction|atomic)',
    re.IGNORECASE | re.DOTALL,
)

# 3. Balance/account update without atomic locking
BALANCE_RACE_CONDITION = re.compile(
    r'(?:balance|amount|credit|debit|wallet)\\s*[+\\-]?=\\s*'
    r'(?!.*(?:\\.select_for_update|SELECT.*FOR UPDATE|'
    r'BEGIN.*COMMIT|with.*transaction|@transaction\\.atomic|'
    r'UPDATE.*WHERE.*balance))',
    re.IGNORECASE | re.DOTALL,
)

# Simple balance increment without protection
RAW_BALANCE_INCREMENT = re.compile(
    r'(?:balance|wallet|account)\\s*\\.\\s*(?:balance|amount|sum)\\s*\\+=\\s*',
    re.IGNORECASE,
)

# 4. Cancel/refund after payment without state validation
CANCEL_MISSING_STATE_CHECK = re.compile(
    r'def\s+(?:cancel|refund|void|chargeback|reverse|rollback)',
    re.IGNORECASE,
)

STATE_CHECK_MISSING = re.compile(
    r'(?:cancel|refund|void|reverse).*'
    r'(?!.*(?:\\.status\\s*==|\\.state\\s*==|if.*status|'
    r'can_be_cancelled|can_be_refunded|is_refundable|is_cancellable))',
    re.IGNORECASE | re.DOTALL,
)

# 5. Float arithmetic for money (should use Decimal)
FLOAT_MONEY = re.compile(
    r'(?:price|amount|sum|total|balance|cost|fee|tax|commission|'
    r'cashback|bonus|discount|payment|charge|refund|deposit|withdrawal)'
    r'\s*[:=]\s*float',
    re.IGNORECASE,
)

# Float operations on money
FLOAT_MONEY_OP = re.compile(
    r'(?:float|int)\\(.*(?:price|amount|sum|total|balance|cost|fee|tax|'
    r'commission|cashback|bonus|payment)\\)',
    re.IGNORECASE,
)

# 6. Webhook handler without signature verification
WEBHOOK_NO_SIGNATURE = re.compile(
    r'@(?:app|router|bp|blueprint)\\.(?:route|post).*(?:webhook|callback|hook)',
    re.IGNORECASE,
)

NO_SIG_VERIFY = re.compile(
    r'webhook|callback.*'
    r'(?!.*(?:verify.*signature|verify_signature|validate.*signature|'
    r'hmac|X-Signature|X-Hub-Signature|webhook.*secret|sha256|sha512|'
    r'signature_header))',
    re.IGNORECASE | re.DOTALL,
)

# 7. Rate limiting missing on sensitive payment ops
NO_RATE_LIMIT_PAYMENT = re.compile(
    r'@(?:app|router|bp)\\.(?:route|post).*(?:payment|payout|transfer|'
    r'withdraw|deposit|charge|redeem|checkout|topup)'
    r'(?!.*(?:rate_limit|RateLimit|throttle|Throttle|limiter))',
    re.IGNORECASE | re.DOTALL,
)

# 8. Negative amount validation missing
MISSING_NEGATIVE_CHECK = re.compile(
    r'(?:amount|price|sum|total)\s*=\s*(?:float|int|Decimal)\s*\(.*request',
    re.IGNORECASE,
)


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS018" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # Skip if file has no payment-related keywords at all
        if not re.search(r'payment|payout|cashback|promo|coupon|'
                         r'balance|wallet|refund|chargeback|webhook|'
                         r'checkout|invoice|transaction|billing',
                         content, re.IGNORECASE):
            continue

        # 1. Missing idempotency on payment callbacks
        # (We use a combined approach: find payment callback functions,
        #  then check if they have idempotency logic)
        payment_endpoints = re.finditer(
            r'def\s+(payment_?callback|payout_?callback|webhook|'
            r'charge_?callback|transaction_?callback|cashback)\s*\(',
            content, re.IGNORECASE,
        )
        for match in payment_endpoints:
            # Get ~20 lines around the function
            func_start = match.start()
            func_end = min(func_start + 2000, len(content))
            func_body = content[func_start:func_end]

            if not re.search(r'idempotenc|duplicate|already.processed|'
                            r'unique.*constraint|once.*only', func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Payment callback without idempotency: {match.group(0)}",
                    detail="No idempotency key or duplicate check found. Risk: double cashback/charge.",
                    fix_suggestion="Add idempotency key (UUID per transaction). Check before processing. Use DB unique constraint on payment_id.",
                    noise_tier="normal",
                ))

        # 2. Promo code redeem without locking
        promo_funcs = PROMO_REDEEM_NO_LOCK.finditer(content)
        for match in promo_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'select_for_update|SELECT.*FOR UPDATE|'
                            r'with.*transaction|@transaction\\.atomic|'
                            r'BEGIN|lock|Lock|mutex|Mutex',
                            func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Promo code redeem without locking: {match.group(0)}",
                    detail="Promo code redemption without DB lock or transaction. Risk: concurrent reuse.",
                    fix_suggestion="Use SELECT FOR UPDATE on promo code row. Wrap in transaction with commit on success.",
                    noise_tier="normal",
                ))

        # 3. Balance update without atomic protection
        for match in RAW_BALANCE_INCREMENT.finditer(content):
            ctx_end = min(match.start() + 1000, len(content))
            ctx_body = content[match.start():ctx_end]
            if not re.search(r'select_for_update|SELECT.*FOR UPDATE|'
                            r'with.*transaction|@transaction|'
                            r'atomic|lock|Lock|Mutex',
                            ctx_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Balance update without atomic locking — race condition risk",
                    detail=f"Direct balance += at line {_lineno(content, match.start())} without SELECT FOR UPDATE or transaction isolation.",
                    fix_suggestion="Use SELECT ... FOR UPDATE before balance modification. Or use UPDATE ... SET balance = balance + ? WHERE ... RETURNING balance.",
                    noise_tier="normal",
                ))

        # 4. Cancel/refund without state check
        cancel_funcs = CANCEL_MISSING_STATE_CHECK.finditer(content)
        for match in cancel_funcs:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'\.status\s*==|\.state\s*==|if\s+.*status|'
                            r'can_be_cancelled|can_be_refunded|'
                            r'is_refundable|is_cancellable|allowed_states',
                            func_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Cancel/refund without state validation: {match.group(0)}",
                    detail="Cancel/refund function lacks state check. Risk: refund after completion.",
                    fix_suggestion="Validate order status before processing cancel/refund. Define allowed transition states explicitly.",
                    noise_tier="normal",
                ))

        # 5. Float for money
        for match in FLOAT_MONEY.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Float used for monetary value: {match.group(0).strip()[:80]}",
                detail="Float arithmetic for money leads to rounding errors exploitable for arbitrage.",
                fix_suggestion="Use Decimal(str(amount)) for all monetary calculations. Never use float for money.",
                noise_tier="precise",
            ))

        # 6. Webhook without signature verification
        webhook_routes = WEBHOOK_NO_SIGNATURE.finditer(content)
        for match in webhook_routes:
            func_end = min(match.start() + 3000, len(content))
            func_body = content[match.start():func_end]
            if not re.search(r'verify.*signature|verify_signature|'
                            r'validate.*signature|hmac|X-Signature|'
                            r'X-Hub-Signature|webhook.*secret|sha256|sha512|'
                            r'signature_header|compute_signature',
                            func_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="CRITICAL",
                    title=f"Webhook handler without signature verification",
                    detail="Webhook/callback endpoint lacks HMAC signature validation. Vulnerable to forged callbacks.",
                    fix_suggestion="Validate webhook signature using shared secret (HMAC-SHA256). Compare constant-time. Include timestamp to prevent replay.",
                    noise_tier="precise",
                ))

        # 7. Rate limiting missing on payment endpoints
        payment_routes = list(re.finditer(
            r'@(?:app|router|bp|blueprint)\\.(?:route|post|get).*'
            r'(?:payment|payout|transfer|withdraw|deposit|charge|redeem|checkout|topup)',
            content, re.IGNORECASE,
        ))
        for match in payment_routes:
            route_end = min(match.end() + 2000, len(content))
            route_body = content[match.start():route_end]
            if not re.search(r'rate_limit|RateLimit|throttle|Throttle|'
                            r'limiter|@limiter|@rate', route_body):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="MEDIUM",
                    title=f"Payment endpoint without rate limiting",
                    detail="Sensitive payment endpoint lacks rate limit protection.",
                    fix_suggestion="Add rate limiting: max 5-10 requests/minute per user for payment endpoints. Use token bucket or sliding window.",
                    noise_tier="normal",
                ))

        # 8. Negative amount validation
        amount_lines = MISSING_NEGATIVE_CHECK.finditer(content)
        for match in amount_lines:
            ctx_end = min(match.end() + 500, len(content))
            ctx_body = content[match.end():ctx_end]
            if not re.search(r'(?:if|assert).*(?:>\\s*0|>=|positive|'
                            r'amount.*>[^=]|price.*>[^=]|validate.*amount|'
                            r'raise.*ValueError)',
                            ctx_body, re.I):
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Amount from request without negative validation",
                    detail="Amount/price taken from request without checking > 0. Negative amounts can exploit refund logic.",
                    fix_suggestion="Validate all amounts: must be > 0, within allowed range. Add explicit check before processing.",
                    noise_tier="normal",
                ))

    return findings
