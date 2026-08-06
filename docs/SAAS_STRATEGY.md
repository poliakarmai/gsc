# GSC → SaaS: стратегия и архитектура перехода

> v0.26 → Cloud 1.0. Проект на ~70% готов к SaaS-ификации.

## Аудит активов

| Актив | Ценность для SaaS |
|---|---|
| Stateless CLI (JSON/SARIF) | Готовый container worker |
| REST API v0.16 (x-api-key) | Зародыш control plane |
| finding_key + feedback loop | Per-tenant self-learning |
| Profiles (LLM 10/20/50) | Готовая основа тарифов |
| Self-learning + авто-деактивация | Moat: Snyk/Semgrep так не умеют |
| SARIF + GitHub Adapter | Экосистема интеграций из коробки |
| Findings/snippets, не код | Privacy-преимущество |
| 400K находок в SQLite | Доказательство масштаба |

## Позиционирование

**ICP:** команды 5–50 dev без AppSec-инженера.

**УТП:** «Сканер, который доказывает уязвимости эксплойтами и учится на ваших ответах — через месяц он молчит там, где другие кричат».

**Сетевой эффект:** глобальный кэш по fingerprint — FP у одного → гасится у всех.

## Архитектура

```
Dev → Dashboard (Next.js) → Control Plane (FastAPI) → Queue (Redis)
                                                        ↓
                          Scan Workers (Docker, эфемерные)
                                                        ↓
                          PostgreSQL (tenant_id + RLS)
```

Принципы: worker эфемерный (код не хранится), LLM Gateway с глобальным кэшем (экономия 40–60%), GitHub App вместо PAT.

## Поэтапный план

| Этап | Что | Оценка | Версия |
|---|---|---|---|
| **S1** | Docker, PgBackend, tenants, очередь, 1 worker | 3–4 нед | v0.27–0.28 |
| **S2** | GitHub App, webhooks, checks, /gsc-команды | 3 нед | v0.29 |
| **S3** | Dashboard, Stripe, metering, тарифы | 4–5 нед | v0.30 |
| **S4** | SOC 2, SSO, Marketplace, VSCode extension | 6–8 нед | Cloud 1.0 |

## Тарифы

| План | Цена | Лимиты |
|---|---|---|
| Free | $0 | 3 репо, 50 сканов/мес |
| Team | $29/польз/мес | 20 репо, 500 сканов |
| Business | $49/польз/мес | безлимит репо, SSO |
| Enterprise | custom | hybrid-agent, SLA, SOC 2 |

## Первые шаги (S1)

- [ ] Dockerfile сканера
- [ ] 12-factor аудит
- [ ] gsc_db.py: DbBackend + PgBackend
- [ ] tenants/repos/scans + API key middleware
- [ ] Redis + worker
- [ ] Лендинг + домен
- [ ] GitHub App manifest

См. полный документ: [[inbox/gsc-saas-strategy-2026-08-06]]
