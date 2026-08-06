# GSC S4 — Доверие и рост → Cloud 1.0

> 9 коммитов. Тесты 90→98. Финал SaaS-трека.

## Состав S4

| Направление | Что |
|---|---|
| Audit log (Business+) | append-only + hash chain + экспорт |
| SSO OIDC (Business+) | Okta/Azure AD/Google, JIT provisioning |
| DPA / GDPR | retention + deletion flow |
| SOC 2 Type I | controls map + evidence pack |
| GitHub Marketplace | plan sync webhook |
| Cloud 1.0 | observability, GA gate |

## Коммиты

| # | Что | Гейт |
|---|---|---|
| 1 | Schema S4 + audit log hash chain | RLS + grants smoke |
| 2 | Audit API/export + redaction | 402 non-Business |
| 3 | SSO OIDC + JIT | domain/nonce tests |
| 4 | Retention + deletion flow | cascade invariant |
| 5 | Marketplace plan sync | signature + idempotency |
| 6 | Observability (health/metrics) | readiness checks |
| 7 | SOC2 controls + DPA + evidence pack | pack builds |
| 8 | Tests S4 (+8 → 98/98) | 98/98 |
| 9 | Cloud 1.0 changelog + GA gate | all gates |

## Найденные баги (7)

1. Audit-лог редактируем 2. Экспорт без redaction 3. JIT без домена
4. NOT NULL github_id 5. Каскад пропускает таблицы 6. Единый retention
7. Marketplace без подписи
