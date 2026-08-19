# Brief: Improve GS018 (Payment Logic Abuse) precision in GSC

> For an external AI agent (Claude Code / Codex / ChatGPT). **Self-contained** — the full
> detector source is embedded below, no repo access needed. Return only proposals in the
> format from §6.

---

## 1. Context

GSC is a self-learning SAST platform (Python, 42 detectors). Detectors are regex patterns +
context filters. **The current pain is precision, not recall**: on 10 real-world projects
(160–132K ⭐) the scan yields 2695 findings, precision CRITICAL ~8–12%. The goal is to remove
false positives (FP) **without losing** true positives (TP).

Detector **GS018 — Payment Logic Abuse** (Echelon 2, SECURITY) flags business-logic bugs in
payment/fintech code: missing idempotency on payment/webhook callbacks (double cashback),
promo-code redeem without locking, balance-update race conditions, cancel/refund without
state validation, float arithmetic for money, webhook without signature verification,
missing negative-amount validation, missing rate limiting.

**Current state in the findings DB** (`~/.hermes/state/gsc_audit.db`): `rule_id LIKE 'GS018%'`
has ~985 rows. **Be careful**: 697 of those are a *legacy rule_id collision* (see Lead 3) —
they are NOT payment findings. Of the remaining ~288 HIGH, **~238 (83%)** come from a single
regex, `FLOAT_MONEY`. A fresh self-scan on real code confirms the detector is still noisy:

```
bybit-ws (real trading bot):  32 findings — all "Float used for monetary value"
gsc (self-scan):                0 findings
```

The historical DB top titles:

| title | count | severity |
|---|---|---|
| Python: assert in production (legacy rule_id collision) | 697 | MEDIUM |
| Float used for monetary value: `…: float` / `…=float(` | ~238 | HIGH |
| Cancel/refund without state validation: `def cancel`/`def rollback` | ~44 | HIGH |
| Promo code redeem without locking | 2 | HIGH |
| Amount from request without negative validation | 3 | HIGH |
| Payment callback without idempotency | 2 | HIGH |

## 2. Current detector code (change only patterns/filters, not the contract)

```python
# gs018_payment_abuse.py
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
    r'(?:@(?:app|router|bp|blueprint)\.(?:route|post|get|put).*\n'
    r'^(?!.*(?:idempotenc|idempotent|idempotency_key|idempotencyKey|'
    r'X-Idempotency|duplicate_check|already_processed))'
    r'.*def\s+(?:payment_?callback|payout_?callback|webhook|'
    r'charge_?callback|transaction_?callback|cashback))',
    re.IGNORECASE | re.MULTILINE,
)

# 2. Promo code / coupon redeem without locking
PROMO_REDEEM_NO_LOCK = re.compile(
    r'def\s+(?:redeem|apply|use(?!r)|activate).*(?:promo|coupon|discount|code|voucher)',
    re.IGNORECASE,
)

PROMO_WITHOUT_LOCK_CHECK = re.compile(
    r'promo.*(?:count|usage|uses|redeemed).*\\+=|'
    r'promo.*\.save\s*\(\s*\)(?!.*select_for_update|with transaction|atomic)',
    re.IGNORECASE | re.DOTALL,
)

# 3. Balance/account update without atomic locking
BALANCE_RACE_CONDITION = re.compile(
    r'(?:balance|amount|credit|debit|wallet)\s*[+\-]?=\s*'
    r'(?!.*(?:\.select_for_update|SELECT.*FOR UPDATE|'
    r'BEGIN.*COMMIT|with.*transaction|@transaction\.atomic|'
    r'UPDATE.*WHERE.*balance))',
    re.IGNORECASE | re.DOTALL,
)

# Simple balance increment without protection
RAW_BALANCE_INCREMENT = re.compile(
    r'(?:balance|wallet|account)\s*\.\s*(?:balance|amount|sum)\s*\+=\s*',
    re.IGNORECASE,
)

# 4. Cancel/refund after payment without state validation
CANCEL_MISSING_STATE_CHECK = re.compile(
    r'def\s+(?:cancel|refund|void|chargeback|reverse|rollback)\b',
    re.IGNORECASE,
)

# Payment-domain signal required inside a cancel/refund/rollback function body.
# DB-driver rollback()/cancel() (peewee/django/twisted) carry none of these and
# are filtered out.
PAYMENT_CONTEXT = re.compile(
    r'order|payment|invoice|billing|subscription|charge|refund_amount|'
    r'transaction_id|purchase', re.IGNORECASE)

STATE_CHECK_MISSING = re.compile(
    r'(?:cancel|refund|void|reverse).*'
    r'(?!.*(?:\.status\s*==|\.state\s*==|if.*status|'
    r'can_be_cancelled|can_be_refunded|is_refundable|is_cancellable))',
    re.IGNORECASE | re.DOTALL,
)

# 5. Float arithmetic for money (should use Decimal)
FLOAT_MONEY = re.compile(
    r'(?:price|amount|sum|total|balance|cost|fee|tax|commission|'
    r'cashback|bonus|discount|payment|charge|refund|deposit|withdrawal)'
    r'\s*=\s*float\s*\(',   # only real conversion float(...), not type annotation
    re.IGNORECASE,
)

# Float operations on money
FLOAT_MONEY_OP = re.compile(
    r'(?:float|int)\(.*(?:price|amount|sum|total|balance|cost|fee|tax|'
    r'commission|cashback|bonus|payment)\)',
    re.IGNORECASE,
)

# 6. Webhook handler without signature verification
WEBHOOK_NO_SIGNATURE = re.compile(
    r'@(?:app|router|bp|blueprint)\.(?:route|post).*(?:webhook|callback|hook)',
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
    r'@(?:app|router|bp)\.(?:route|post).*(?:payment|payout|transfer|'
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
        payment_endpoints = re.finditer(
            r'def\s+(payment_?callback|payout_?callback|webhook|'
            r'charge_?callback|transaction_?callback|cashback)\s*\(',
            content, re.IGNORECASE,
        )
        for match in payment_endpoints:
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
                            r'with.*transaction|@transaction\.atomic|'
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
            if not PAYMENT_CONTEXT.search(func_body):
                continue
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
            r'@(?:app|router|bp|blueprint)\.(?:route|post|get).*'
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
            if not re.search(r'(?:if|assert).*(?:>\s*0|>=|positive|'
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
```

> **Note (do NOT change, just know):** `detect()` actually uses only
> `PROMO_REDEEM_NO_LOCK`, `RAW_BALANCE_INCREMENT`, `CANCEL_MISSING_STATE_CHECK`,
> `FLOAT_MONEY`, `WEBHOOK_NO_SIGNATURE`, `MISSING_NEGATIVE_CHECK` + inline regexes.
> The compiled `MISSING_IDEMPOTENCY`, `PROMO_WITHOUT_LOCK_CHECK`,
> `BALANCE_RACE_CONDITION`, `STATE_CHECK_MISSING`, `FLOAT_MONEY_OP`, `NO_SIG_VERIFY`,
> `NO_RATE_LIMIT_PAYMENT` are **dead code** (never called). Account for this when
> narrowing patterns.

## 3. Metric — what counts as "better"

- **Primary: precision** = TP/(TP+FP). Remove FP **without losing TP**.
- **Guard:** any narrowing/disabling of a pattern is acceptable only if TP cases still fire.
- Recall (new patterns) is secondary, and only after precision is stable.

## 4. Known FP candidates (leads — verify and confirm/refute each)

### Lead 1 (main detector bug) — `FLOAT_MONEY`: conversion ≠ arithmetic

`FLOAT_MONEY = (price|amount|…)\s*=\s*float\s*\(` flags **any** `price = float(…)`,
including parsing a value out of an API/JSON response — which is NOT monetary
arithmetic and carries no rounding-exploit risk. A fresh self-scan of a real trading
bot (bybit-ws) shows **32 findings, all of this type**:

| file:line | matched | real code |
|---|---|---|
| `bybit_ws/api.py:301` | `price = float(` | parsing ticker price from exchange API |
| `bybit_ws/auto_entry.py:626` | `balance = float(` | parsing account balance from API |
| `bybit_ws/auto_short.py:392` | `price = float(` | parsing price |
| `bybit_ws/auto_short.py:512` | `balance = float(` | parsing balance |

These are `float(str_value_from_api)` conversions, not `float` *arithmetic* on money.

**Fix direction (regex narrowing / context):** only flag when `float(...)` actually
participates in arithmetic or a money computation, e.g. require one of `+ - * /`
nearby, or a comparison/accumulation, or narrow the value source (reject
`float(request…|response…|json…|str…|data[…])`). Alternatively drop `price`/`amount`/
`balance`/`cost`/`fee` from the bare-conversion branch and keep only a clearly
arithmetic signal. **Do not simply delete `FLOAT_MONEY`** — the TP case
"float arithmetic for money" (e.g. `total = float(a) * 0.9`) must still fire.

### Lead 2 — `CANCEL_MISSING_STATE_CHECK`: residual ORM/DB-driver FP

The current code already has a word boundary (`\b`) and a `PAYMENT_CONTEXT` gate, but
verify whether DB-driver functions still slip through when the surrounding file mentions
`transaction`/`refund` (the file-level keyword gate lets them in):

| file:line | matched | why FP |
|---|---|---|
| `peewee.py:4037,4386,5261,5305` | `def rollback` | ORM transaction rollback, not payment refund |
| `django/db/backends/base/base.py:333` | `def rollback` | DB backend |
| `src/twisted/enterprise/adbapi.py:46` | `def rollback` | DB pool |
| `src/twisted/internet/interfaces.py:133,1230` | `def cancel` | Deferred.cancel, not payment |

**Fix direction (context analysis):** tighten `PAYMENT_CONTEXT` so a bare `transaction`/
`refund` word is not enough — require a payment *domain* noun (order, invoice, charge,
checkout, refund_amount, transaction_id) rather than the generic `transaction`.

### Lead 3 — legacy `rule_id` collision "assert in production" (NOT the detector)

697 MEDIUM rows titled "Python: assert in production" sit under `rule_id='GS018'` but are
produced by a generic `\bassert\s` pattern in `gsc_cli/main.py`, which
`_derive_rule_id()` maps to `GS018` (`if "assert" in title: return "GS018"`). This is a
separate bug outside the detector; **do not "fix" it inside gs018_payment_abuse.py**. Just
be aware that ~71% of the GS018 bucket in the DB is this collision, so when measuring your
precision impact, filter it out (`AND title != 'Python: assert in production'`).

### Lead 4 — `PROMO_REDEEM_NO_LOCK`: `use` prefix-matches `user_…`

`(?:redeem|apply|use(?!r)|activate)` — the `use` alternative (already neg-lookahead'd
against `user`) can still prefix-match `user_…` in some spellings. Historical example:
`backend/db/dal/promo_code_dal.py:646` → `def user_has_pending_payment_with_promo`
(read-only check, not a redeem). `def apply_promo` is a legitimate TP — keep it.
**Fix direction:** require a word boundary after the verb and confirm the function is a
redeem/apply action (not a read-only `has_/get_/is_` check).

### Lead 5 (minor, verify) — "Amount from request without negative validation"

3 historical HIGH, all in `/tmp/gsc-hunt-4/app/api/views.py`. The pattern is narrow and
likely TP/borderline. Verify on a fresh scan before touching.

## 5. Your task

Analyze the code above. For each candidate in §4 (and any OTHER FP you notice) propose a
concrete fix. Three allowed tools (in order of preference):

1. **Path exclusion** — add to a path/glob exclusion (tests, samples, benchmark, vendor).
2. **Regex narrowing** — require more context in the pattern itself.
3. **Context analysis** — extend a filter (±3 lines / key capture).

## 6. Response format (strict)

For each proposal, one block:

```
### GS018: <name>
- Type: path_exclusion | regex_narrowing | context_analysis
- Pattern/code: <concrete regex or diff>
- Rationale: why it's an FP (file/line example)
- FP it removes: <real code line>
- TP impact: which TP cases are NOT affected
```

## 7. Do NOT do

- ❌ Do not change `RULE_ID`, the severity scale, the `detect()` signature, or `Finding` keys.
- ❌ Do not disable the detector wholesale — only filters.
- ❌ Do not "clean up" code beyond the task (scope discipline). The dead compiled patterns
  in §2 must stay as-is unless your fix genuinely touches them.
- ❌ Do not propose without FP examples (can't assess risk/benefit).
- ❌ Do not add new payment-abuse *detection* (recall) — this is a precision pass only.

## 8. Verification procedure (run before claiming a fix)

```bash
cd ~/gsc
# Fresh FP slice — do NOT trust the historical DB for "is it still firing"
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from pathlib import Path
from gsc_detectors import AuditContext
from gsc_detectors import gs018_payment_abuse as g18
for root in ('.', str(Path.home()/'bybit-ws')):
    ctx = AuditContext(project='x', path=Path(root)); ctx.files = ctx.get_files()
    fs = g18.detect(ctx)
    print(root, '->', len(fs), 'findings')
    for f in fs[:20]:
        print('  ', f.get('severity'), f.get('file_path'), f.get('title'))
PY

# full suite + standalone regression/compliance
python3 -m pytest -q
python3 tests/test_regression.py
python3 tests/test_compliance_secrets.py
```

Pitfalls:
- `Finding` is dict-like: `severity=`/`category=` (same), `file_path`/`line_number`/`detail`
  (NOT `file=`/`message=`). Emit both where a bridge expects one.
- `get_source_files()` excludes tests/fixtures via `TEST_GLOBS`; the detector scans
  `.py/.js/.ts/.go/.java/.rb/.php` only.
- `test_regression.py` / `test_compliance_secrets.py` are standalone — run with
  `python3 tests/…`, not `pytest`.
- **Commit only on explicit instruction** — the repo owner gates all commits.
