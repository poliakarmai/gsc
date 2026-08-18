# Бриф: GS018 — Payment Logic Abuse (precision-улучшение)

> Самодостаточный бриф для внешнего агента **без доступа к репозиторию**.
> Весь код детектора вшит внутрь. Задача — **снизить FP при неизменном recall (TPR drop ≤ 3%)**.
> Формат и контракт — по образцу `DETECTOR_BRIEF_GS017.md`.

---

## 1. Что это за детектор

**GS018 — Payment Logic Abuse**, Echelon 2 (SECURITY). Ищет business-logic уязвимости в платёжном коде:
- отсутствие идемпотентности на payment/webhook callback'ах (double cashback);
- abuse промокодов (redeem без блокировки);
- race condition в балансовых апдейтах (без `SELECT FOR UPDATE`);
- cancel/refund после оплаты без валидации состояния;
- отсутствие валидации отрицательной суммы/цены;
- float-арифметика для денег (rounding exploit);
- webhook без проверки подписи (replay).

**Проблема:** на живых сканах под `rule_id LIKE 'GS018%'` лежит **985 строк**, из которых **697 (71%) — вообще не платёжный детектор**, а legacy-коллизия generic-правила «assert in production». Из остальных 288 HIGH **~238 (83%) — FP** от одного регэкса `FLOAT_MONEY`, который ловит **аннотации типов** `amount: float` вместо float-арифметики.

## 2. Срез из живой БД (снимок 2026-08-18)

```sql
SELECT rule_id, category, COUNT(*) FROM findings
WHERE rule_id LIKE 'GS018%' GROUP BY rule_id, category;
```

```
GS018                                              | HIGH    | 266
GS018                                              | MEDIUM  | 697
GS018 (Payment logic abuse — double cashback, ...) | HIGH    | 22
```

**Итого 985 строк, из них два «грязных» правила:**
- `rule_id = "GS018"` → 963 строки (266 HIGH + 697 MEDIUM);
- `rule_id = "GS018 (Payment logic abuse — double cashback, promo code abuse, rac)"` → 22 HIGH — это **`description`, записанное в `rule_id`** в старой версии детектора (текущий код пишет `rule_id=RULE_ID`). Legacy-данные, к текущему коду отношения не имеют.

**Критически важно:** `category = MEDIUM` в GS018 — это **697 находок «Python: assert in production»**. Они порождены НЕ детектором `gs018_payment_abuse.py`, а generic-паттерном `\bassert\s` из `gsc_cli/main.py:1566`, которому функция `_derive_rule_id()` в `gsc_cli/main.py:486` присваивает rule_id `GS018`:

```python
# gsc_cli/main.py:477-490
def _derive_rule_id(pattern: dict) -> str:
    title = (pattern.get("title") or "").lower()
    ...
    if "assert" in title: return "GS018"   # ← строка 486, коллизия
```

Раскладка по проектам (откуда шум):

| Проект | Находок | Что это |
|---|---|---|
| `/tmp/gsc-hunt-4` | 236 | Telegram-шоп/raid-бот — **float-аннотации + cancel_*** (real code) |
| `benchmark/real_world/youtube-dl` | 222 | **«assert in production» (legacy-коллизия)** |
| `benchmark/real_world/rich` | 144 | «assert in production» |
| `benchmark/real_world/httpie` | 69 | «assert in production» |
| `/tmp/gsc-external/Hyperion` | 67 | «assert in production» + float |
| `/tmp/gsc-hunt-5` | 49 | «assert in production» |
| `benchmark/real_world/sanic` | 40 | «assert in production» |
| `/tmp/gsc-hunt-20260817/Telegram-shop` | 24 | **float-аннотации + cancel_*** (real code) |
| `peewee` / `twisted` / `django` | 8+8+3 | **`def rollback`/`def cancel` в ORM/DB-драйверах** (real code) |

**Ключевой вывод:** шум GS018 имеет ДВА независимых источника:
1. **Legacy-коллизия rule_id** (697 MEDIUM «assert in production») — 71% всех строк, не платёжный код вообще;
2. **Два широких регэкса** в самом детекторе — `FLOAT_MONEY` (238 HIGH) и `CANCEL_MISSING_STATE_CHECK` (44 HIGH) — дают 282 из 288 HIGH.

---

## 3. Код детектора (вшит целиком)

Файл: `gsc_core/gsc_detectors/gs018_payment_abuse.py` (311 строк).

```python
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
```

> **Примечание для агента (не менять код, только знать):** в `detect()` реально используются только паттерны `PROMO_REDEEM_NO_LOCK`, `RAW_BALANCE_INCREMENT`, `CANCEL_MISSING_STATE_CHECK`, `FLOAT_MONEY`, `WEBHOOK_NO_SIGNATURE`, `MISSING_NEGATIVE_CHECK` + inline-регэксы. Скомпилированные `MISSING_IDEMPOTENCY`, `PROMO_WITHOUT_LOCK_CHECK`, `BALANCE_RACE_CONDITION`, `STATE_CHECK_MISSING`, `FLOAT_MONEY_OP`, `NO_SIG_VERIFY`, `NO_RATE_LIMIT_PAYMENT` — **мёртвый код** (нигде не вызываются). При сужении паттернов это учитывать.

---

## 4. Реальные FP (из БД, file:line → что заматчилось)

### 4.0 `rule_id`-коллизия: «Python: assert in production» (697 MEDIUM, 71% всех строк)

Не платёжный код. Generic-паттерн `\bassert\s` (`gsc_cli/main.py:1566`), который `_derive_rule_id()` (`gsc_cli/main.py:486`) мапит на `GS018`. Подтверждено `scan.json` и БД:

| file:line | заматчилось | почему FP |
|---|---|---|
| `rich/rich/color.py:365,368,371,374,377` | `assert ...` | rich — консольный рендер, не платёж |
| `httpie/httpie/internal/daemon_runner.py:44,45` | `assert ...` | httpie — HTTP-клиент |
| `httpie/httpie/downloads.py:217,263,319` | `assert ...` | httpie |
| `sanic/sanic/cli/console.py:91,110,112,271` | `assert ...` | sanic — web-фреймворк |
| `piccolo-api/piccolo_api/session_auth/endpoints.py:287` | `assert ...` | piccolo-api ORM |

**Корень:** не в детекторе `gs018_payment_abuse.py`. Это отдельный баг `_derive_rule_id()` — «assert» ≠ payment abuse.

### 4.1 `FLOAT_MONEY` — аннотации типов `amount: float` (127 из 238 float-FP)

Регэкс `(price|amount|sum|total|balance|cost|fee|...)[:=]\s*float` ловит **объявление типа** `: float` — Pydantic-поля, параметры функций, TypedDict-ключи. Это не float-арифметика. Подтверждено живым кодом Telegram-shop:

| file:line | заматчилось | реальный код |
|---|---|---|
| `services/crypto_bot.py:15` | `amount: float` | `def generate_payment_address(self, amount: float, transaction_id: int, ...)` — **параметр функции** |
| `services/crypto_bot.py:90` | `amount: float` | `def check_payment_status(self, crypto_address: str, expected_amount: float) -> bool` — **параметр** |
| `utils/helpers.py:46` | `price: float` | `def format_price(price: float) -> str:` — **параметр** |
| `backend/bot/app/web/admin_api_impl/response_schemas.py:130,147` | `price: float` | Pydantic-схема |
| `backend/bot/infra/event_payloads.py:70,78,79` | `amount: float` | dataclass/payload-схема |

**Корень:** `[:=]` включает `:` (аннотация типа). Для «float-арифметики для денег» аннотация типа TP не является никогда.

### 4.2 `CANCEL_MISSING_STATE_CHECK` — UI-обработчики `cancel_*` (prefix-match)

Регэкс `def\s+(?:cancel|refund|void|chargeback|reverse|rollback)` **без `\b`** матчит префикс `cancel` в `cancel_restock`, `cancel_topup` и т.д. — это Telegram-bot «отмена диалога», а не отмена/возврат платежа:

| file:line | заматчилось | реальный код |
|---|---|---|
| `handlers/admin_handlers.py:1363` | `def cancel` | `async def cancel_restock(...)` — отмена пополнения склада (UI) |
| `handlers/payment_handlers.py:377` | `def cancel` | `async def cancel_topup(...)` — выход из диалога пополнения |
| `handlers/payment_handlers.py:395` | `def cancel` | `async def cancel_payment_page(...)` — выход из UI |
| `handlers/payment_handlers.py:821` | `def cancel` | `async def cancel_purchase(...)` — выход из UI |
| `app/modules/raid/endpoints_raid.py:1327` | `def cancel` | raid-модуль (игра), не платёж |
| `app/modules/sport_competition/cruds_sport_competition.py:562` | `def cancel` | спорт-соревнования, не платёж |

**Корень:** нет `\b` после глагола → `cancel_xxx` считается `def cancel`.

### 4.3 `CANCEL_MISSING_STATE_CHECK` — `def rollback`/`def cancel` в ORM/DB-драйверах (22 HIGH в description-bucket)

`def rollback` в peewee/django/twisted — это **транзакционный rollback БД**, не возврат платежа. Файловый gate (`payment|refund|transaction|...`) пропускает ORM-файлы, потому что в них есть слова `transaction`/`refund`:

| file:line | заматчилось | что это |
|---|---|---|
| `peewee.py:4037,4386,5261,5305` | `def rollback` | ORM-транзакция |
| `django/db/backends/base/base.py:333` | `def rollback` | DB backend |
| `src/twisted/enterprise/adbapi.py:46` | `def rollback` | DB-пул |
| `src/twisted/internet/interfaces.py:133,1230` | `def cancel` | интерфейсы (Deferred cancel) |
| `src/twisted/mail/smtp.py:2192` | `def cancel` | SMTP |

**Корень:** `CANCEL_MISSING_STATE_CHECK` не требует платёжного контекста в теле функции — только в файле.

### 4.4 `PROMO_REDEEM_NO_LOCK` — `use` префикс-матчит `user_...`

| file:line | заматчилось | реальный код |
|---|---|---|
| `backend/db/dal/promo_code_dal.py:646` | `def user_has_pending_payment_with_promo` | read-only проверка «есть ли pending payment с промо», НЕ redeem. Матч через `use` ← префикс «user» |

**Корень:** альтернатива `(?:redeem|apply|use|activate)` без `\b` → `use` матчит `user_...`. `def apply_promo` (`billing_subscription.py:111`) — легитимный матч (потенциальный TP), не трогать.

### 4.5 Прочее (не подтверждено, низкий приоритет)

- **«Amount from request without negative validation»** (3 HIGH, все в `/tmp/gsc-hunt-4/app/api/views.py:1027,2421,2523`) — hunt-4 перезаписан новым сканом, исходники недоступны. Требует ручной проверки; паттерн узкий, вероятнее TP/пограничные.
- **«Payment callback without idempotency: def webhook(»** (1 HIGH, `app/core/payment/endpoints_payment.py:35`) — похоже на реальный TP (webhook без идемпотентности), НЕ резать.
- **Дубликаты:** одна и та же строка встречается ×2–×3 (напр. `handlers/payment_handlers.py:377` ×3, `services/crypto_bot.py:15` ×3) — накопление по разным `run_id`, не баг детектора. Для отчётов — dedup по `finding_key` внутри `run_id`.

---

## 5. Лиды (по приоритету)

> Каждый лид — самостоятельный фикс. Принимаются только подтверждённые на реальном коде (`FP↓ при TP-константе`). Не резать recall.

### Лид 1 (максимум эффекта, но НЕ детектор) — убрать коллизию `_derive_rule_id`: «assert» → GS018
**Тип:** path_exclusion (на уровне rule-id деривации, вне детектора).
**Симптом:** 697 MEDIUM «Python: assert in production» под rule_id GS018 — 71% всех строк.
**Фикс:** в `gsc_cli/main.py:486` `if "assert" in title: return "GS018"` → возвращать `"GS000-LEGACY"` (или отдельный rule_id для generic assert). Generic-паттерн `\bassert\s` не имеет отношения к payment abuse.
**Риск:** меняется `finding_key` у legacy-assert находок (они перестанут ложиться в GS018). Это и есть цель — сейчас они ложно «в GS018». Текущий `gs018_payment_abuse.py` при этом НЕ трогается.

### Лид 2 (главный детекторный баг) — `FLOAT_MONEY` не должен матчить аннотации типов `: float`
**Тип:** regex_сужение.
**Симптом:** 238 HIGH (~83% HIGH), из них 127 — `: float` (аннотация типа).
**Фикс:** сузить `[:=]\s*float` до `=\s*float\s*\(` (реальная конверсия `amount = float(...)`), убрав ветку `:` (аннотация). Паттерн `FLOAT_MONEY_OP` (`(?:float|int)\(...`) уже покрывает `float(x)`-конверсии, но он **мёртвый** — его либо подключить, либо удалить; дублировать не нужно.

```python
FLOAT_MONEY = re.compile(
    r'(?:price|amount|sum|total|balance|cost|fee|tax|commission|'
    r'cashback|bonus|discount|payment|charge|refund|deposit|withdrawal)'
    r'\s*=\s*float\s*\(',   # только реальная конверсия float(...), не аннотация типа
    re.IGNORECASE,
)
```
**Ожидание:** снимает `amount: float` / `price: float` (127 находок) и `amount = float`-без-скобок; сохраняет `amount = float(amount_str)` (реальные конверсии — как `utils/helpers.py:79`).
**Влияние на TP:** TP-кейс «float-арифметика для денег» (`price = float(x)`, `float(amount)`) остаётся за счёт `=\s*float\s*\(` и `FLOAT_MONEY_OP`.

### Лид 3 — `CANCEL_MISSING_STATE_CHECK`: word boundary после глагола
**Тип:** regex_сужение.
**Симптом:** `def cancel_restock`/`def cancel_topup`/`def cancel_purchase` матчатся как `def cancel` (UI-обработчики, не возврат платежа) — 20+ HIGH.
**Фикс:** добавить `\b` после глагола:

```python
CANCEL_MISSING_STATE_CHECK = re.compile(
    r'def\s+(?:cancel|refund|void|chargeback|reverse|rollback)\b',
    re.IGNORECASE,
)
```
**Ожидание:** отсекает все `cancel_*`/`refund_*`/`rollback_*` суффиксы, оставляет `def cancel(`/`def refund(`/`def rollback(`.
**Влияние на TP:** TP «cancel/refund без проверки статуса» — это функции именно с именем `cancel`/`refund`, `\b` их не режет.

### Лид 4 — `CANCEL_MISSING_STATE_CHECK`: платёжный контекст в теле функции
**Тип:** context_analysis.
**Симптом:** `def rollback` в `peewee.py`/`django/db/...`/`twisted/enterprise/adbapi.py` (транзакционный rollback БД) и `def cancel` в `twisted/internet/interfaces.py`/`smtp.py` — 22 HIGH (description-bucket) + часть из 20 HIGH.
**Фикс:** для `cancel`/`refund`/`rollback` требовать платёжный признак в теле функции (первые ~3000 симв. после `def`): `order|payment|invoice|transaction_id|refund_amount|charge|billing|subscription` ИЛИ state-переход (`status`, `state`). БД-драйверы (`rollback` без `payment|order|refund`) отсекаются.

```python
PAYMENT_CONTEXT = re.compile(
    r'order|payment|invoice|billing|subscription|charge|refund_amount|'
    r'transaction_id|purchase', re.IGNORECASE)
...
# внутри cancel_funcs-loop, до state-check:
if not PAYMENT_CONTEXT.search(func_body):
    continue
```
**Риск:** узкий — редкий TP, где функция `def refund` не содержит слов order/payment (крайне маловероятно в платёжном коде). Проверить на smoke-кейсах.
**Влияние на TP:** реальный `def cancel(self)` в платёжном сервисе содержит `order`/`payment` в теле — остаётся.

### Лид 5 — `PROMO_REDEEM_NO_LOCK`: word boundary на глаголах
**Тип:** regex_сужение.
**Симптом:** `def user_has_pending_payment_with_promo` (read-only check) матчится через `use`-префикс «user» — 1 HIGH.
**Фикс:** `def\s+(?:redeem|apply|use|activate)\b.*(?:promo|coupon|discount|code|voucher)`.
**Влияние на TP:** `def apply_promo` (`billing_subscription.py:111`, потенциальный TP) не задевается.

### Лид 6 (косметика/данные) — legacy `description`-в-`rule_id` bucket + dedup
**Симптом:** 22 HIGH с `rule_id = "GS018 (Payment logic abuse — ...)"` — `description`, записанное в `rule_id` старой версией детектора. Плюс дубликаты ×2–×3 по `run_id`.
**Фикс:** разовая миграция `UPDATE findings SET rule_id='GS018' WHERE rule_id LIKE 'GS018 (%'`; для отчётов — dedup по `finding_key` внутри `run_id`. **Детектор не трогать** (текущий код уже пишет `rule_id=RULE_ID`).

---

## 6. Контракт верификации (обязателен перед приёмкой)

1. **Smoke** на синтетических TP/FP через `AuditContext` + `gs018_payment_abuse.detect(ctx)` (см. `tests/test_regression.py` паттерн `AuditContext(project="x", path=p)`):
   - **TP должны остаться:** `def payment_callback(self):` без idempotency (идемпотентность отсутствует); `def redeem_promo(self):` без `select_for_update`; `def refund(self):` в классе с `order`/`payment` и без `.status ==`; `amount = float(request.json['amount'])` без проверки `> 0`; `price = float(x)`.
   - **FP должны уйти:** `def generate_payment_address(self, amount: float, ...)` (аннотация); `def format_price(price: float) -> str:`; `def cancel_restock(...)`; `def cancel_topup(...)`; `def user_has_pending_payment_with_promo(...)`; `def rollback(self):` (ORM, без payment-контекста).
2. **Регрессия:** `python3 tests/test_regression.py` — зелёный; `python3 -m pytest -q` — без новых падений (базовые кейсы не задевают GS018-специфику, но общий прогон обязателен).
3. **Проверка на живом коде:** перегнать GS018 на `/tmp/gsc-hunt-20260817/Telegram-shop` (float + cancel_* FP-эталон) и `benchmark/real_world/rich`/`httpie` (assert-коллизия — должна уйти после Лида 1). FP-счёт по HIGH должен упасть с ~288 до <50, TP (webhook, redeem_promo, refund с order-контекстом) — не потеряны.
4. **Проверка Лида 1 отдельно:** после правки `_derive_rule_id` — `SELECT COUNT(*) FROM findings WHERE rule_id='GS018' AND title='Python: assert in production'` на новом скане = 0.

## 7. Жёсткие инварианты (нарушать нельзя)

- `RULE_ID = "GS018"` и `finding_key` не менять (в детекторе — `rule_id=RULE_ID` везде).
- TP-кейсы не резать (TPR drop ≤ 3%): webhook-идемпотентность, redeem без блокировки, `def refund`/`def cancel` **в платёжном контексте**, `amount = float(request...)` без `> 0`, `price = float(x)`.
- Severity-шкалу не менять (`CRITICAL`/`HIGH`/`MEDIUM` как есть в коде).
- Детектор целиком не отключать — только фильтры/сужения/гейты.
- Мёртвые скомпилированные паттерны (`MISSING_IDEMPOTENCY`, `STATE_CHECK_MISSING`, `FLOAT_MONEY_OP`, `NO_SIG_VERIFY`, `NO_RATE_LIMIT_PAYMENT`, `BALANCE_RACE_CONDITION`, `PROMO_WITHOUT_LOCK_CHECK`) — можно подключать/удалять только если это НЕ меняет текущий вывод; `FLOAT_MONEY_OP` при сужении `FLOAT_MONEY` (Лид 2) использовать как уже готовый эквивалент, а не дублировать.
- Лид 1 — правка `gsc_cli/main.py::_derive_rule_id`, **не** детектора; не менять сам `gs018_payment_abuse.py` ради assert-фикса.
- Код-стиль: только stdlib (`re`, `pathlib`); `Finding` — dict-like (`severity=`, `file_path=`, `line=`); `ctx.get_source_files(extensions=...)`.

---

*Файл детектора: `gsc_core/gsc_detectors/gs018_payment_abuse.py`.*
*Срез БД: `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE rule_id LIKE 'GS018%' GROUP BY rule_id, category;"` — переснять перед работой.*
*Коллизия rule_id: `gsc_cli/main.py:486` (`_derive_rule_id`).*
