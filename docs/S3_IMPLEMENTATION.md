# GSC S3 — Web Dashboard + Stripe/metering (v0.30)

> 7 коммитов. Тесты 82→90. Продуктовый слой: дашборд, OAuth, биллинг.

## Границы S3

| Входит | Не входит (S4) |
|---|---|
| GitHub OAuth + сессии | SSO/OIDC Enterprise |
| Web Dashboard (BFF + Next.js) | SOC 2, DPA |
| Stripe: checkout, subscription, webhook | Overage-покупки |
| Metering + 402-флоу | Audit log как продукт |

## Коммиты

| # | Что | Гейт |
|---|---|---|
| 1 | Схема S3 (users, memberships, stripe_events) | psql + RLS |
| 2 | GitHub OAuth + сессии (state, HMAC cookie) | state/tamper тесты |
| 3 | BFF API дашборда (/api/v2/dash/*) | membership/IDOR |
| 4 | Stripe billing + webhook | idempotency/signature |
| 5 | Next.js scaffold + pages | next build |
| 6 | Auth flow + billing UI | round-trip |
| 7 | Тесты S3 (+8 → 90/90) | 90/90 |

## Ключевые решения

- **Дашборд без своей БД** — только BFF-эндпоинты над PG
- **GitHub OAuth** — нулевой барьер (клиенты уже через App)
- **httpOnly cookie + HMAC** — не JWT localStorage, XSS-устойчиво
- **Stripe seat-based:** team $29/mo, business $49/mo
- **402-флоу:** баннер при превышении квоты, апгрейд через checkout

## Найденные баги (6)

1. CSRF на OAuth логин 2. IDOR через подмену tid 3. Stripe ретраи
4. План из metadata 5. XSS через snippet 6. developer → billing
