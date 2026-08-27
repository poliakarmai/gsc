# GSC_SAAS_ROADMAP.md — путь от инструмента к SaaS

> Для: стратегического планирования продукта
> Автор: Море
> Дата: 2026-08-06
> Статус: активный (обновляется по факту этапов S1–S4)

## Executive summary

GSC готов к превращению в SaaS без переписывания ядра. Stateful-часть
(сканер, детекторы, self-learning, finding_key/feedback) переносится
напрямую в облачные worker-контейнеры; вокруг неё строится multi-tenant
обвязка (PostgreSQL + Redis + REST API v2). Уникальное рыночное
предложение: **«сканер, который учится на вердиктах клиентов»** —
сетевой эффект через глобальный кэш ревалидации.

## Активы, готовые к SaaS

| Актив ядра | Значение для SaaS |
|---|---|
| Stateless сканер с JSON/SARIF выходом | Готовый эфемерный worker-образ |
| REST API v0.16 (x-api-key) | Зародыш control plane |
| `finding_key` + feedback loop | Per-tenant обучение |
| Profiles (LLM 10/20/50) | Тарифные лимиты |
| Self-learning + авто-деактивация | Главный moat |
| SARIF + GitHub Adapter | Интеграции из коробки |
| Redaction audit v0.15 | Обязательный комплайнс-слой |
| 400K находок (SQLite) | Доказательство масштаба модели |

## Позиционирование и рынок

**ICP:** команды 5–50 разработчиков без AppSec-инженера, не могут
позволить Snyk/Checkmarx, но хотят больше, чем Dependabot.

| Конкурент | Их слабость | Наш ответ |
|---|---|---|
| Semgrep Cloud | Статичные правила | Self-learning, правила отключаются по FP |
| Snyk | Дорого, только зависимости | Дешевле + SAST + PoC |
| GitHub Advanced Security | $49/committer | Attack chains + PoC + AI-code scanner |

**Уникальная формулировка:**
> «Сканер, который доказывает уязвимости эксплойтами и учится на ваших
> ответах — через месяц он молчит там, где другие кричат».

**Сетевой эффект:** глобальный кэш ревалидации по fingerprint'ам —
находка, подтверждённая FP у одного клиента, гасится у всех. Moat
невозможно повторить без установленной базы.

## Целевая архитектура (GSC Cloud)

```
  Разработчик / Sec-инженер
          │
          ▼ OIDC / API key
  ┌─────────────────────────┐
  │  Web Dashboard (S3)     │
  └─────────────┬───────────┘
                │
  ┌─────────────▼───────────┐    ┌──────────────┐
  │  Control Plane (FastAPI)│◄───│ GitHub App   │
  │  v0.16 API → multi-tenant│   │ (install/webhook)│
  └─────────────┬───────────┘    └──────────────┘
                │ enqueue
  ┌─────────────▼───────────┐
  │  Redis Queue            │
  └─────────────┬───────────┘
       ┌────────┼────────┐
       ▼        ▼        ▼
  [Worker]  [Worker]  [LLM Gateway: кэш + квоты]
       │        │
       ▼        ▼ findings JSON (код не сохраняется)
  ┌────────────────────────────────┐
  │ PostgreSQL + RLS per tenant_id │
  └────────────────────────────────┘
```

**Принципы:**
1. Worker эфемерный: клонирует код → сканирует → отправляет findings →
   временный том удаляется. Код тенанта не хранится.
2. LLM Gateway — единая точка с бюджетом на тенант и глобальным кэшем
   по fingerprint (экономия 40–60% LLM-бюджета).
3. GitHub App вместо PAT — стандартный B2B-onboarding.

## Модель данных (multi-tenant)

Все таблицы tenant-scoped; row-level security через `SET app.tenant_id`.

- `tenants` (id, name, plan, scan_limit_month, llm_budget_month)
- `api_keys` (tenant_id, key_hash, prefix)
- `repos`, `scans`, `findings`, `verdicts`, `usage`
- v0.27 (S1): базовый контур (сканы + findings + verdicts)
- S2: портируются chains, mutations, overrides, invariants

## Тарифы

| План | Цена | Лимиты | Фичи |
|---|---|---|---|
| Free | $0 | 3 репо, 50 сканов/мес | regex-детекторы, SARIF |
| Team | $29/польз/мес | 20 репо, 500 сканов, LLM | + LLM, PoC, цепочки |
| Business | $49/польз/мес | без лимита репо | + инварианты, SSO, audit log |
| Enterprise | custom | — | + hybrid-agent, SLA, SOC 2 |

## Этапы

| Этап | Содержание | Оценка | Версии |
|---|---|---|---|
| **S1. Фундамент** | Docker-образ; PgBackend; tenants/repos/scans; API key per tenant; queue + worker | 3–4 нед | v0.27–v0.28 |
| **S2. Onboarding** | GitHub App + webhooks + /gsc-команды через App; порт chains/mutations/overrides в PG | 3 нед | v0.29 |
| **S3. Продукт** | Web Dashboard + Stripe + metering; тарифные лимиты | 4–5 нед | v0.30 |
| **S4. Доверие** | SOC 2 Type I; DPA; audit log; SSO; GitHub Marketplace | 6–8 нед | Cloud 1.0 |

Параллельно: VSCode extension v0.27 (план готов, подключается к cloud API).

## Безопасность и compliance

1. **«Мы не храним ваш код»** — findings/snippets только; код в
   эфемерном worker'е. Главный пункт лендинга и security-вопросников.
2. **Изоляция:** tenant_id + PostgreSQL RLS + middleware проверяет
   владельца ресурса в каждом запросе.
3. **Redaction:** audit v0.15 обязателен на всех выходах.
4. **SOC 2 Type I** — в S4, без него Enterprise-продажи не начнутся.
5. **Hybrid-режим для Enterprise:** worker ставится у клиента (Docker),
   в облако уходят только findings.

## Риски и митигация

| Риск | Митигация |
|---|---|
| LLM-расходы при росте | Кэш по fingerprint + квоты на план |
| Доверие (код!) | Не храним код + SOC 2 + hybrid |
| Semgrep/Snyk маркетинг | Ниша self-learning + PLG free-tier |
| Расползание скоупа | S1–S2 без дашборда; дашборд только в S3 |
| Cross-tenant утечка | RLS + интеграционные тесты |

## Первые шаги (этот месяц)

- [ ] Dockerfile сканера
- [ ] 12-factor аудит (конфиг из env, секреты вне кода)
- [ ] PgBackend + миграция schema 23 → PG
- [ ] tenants/repos/scans + API key middleware
- [ ] Очередь Redis + worker-процесс
- [ ] Лендинг + waitlist + домен
- [ ] Черновик GitHub App

Пункты 1–5 = S1; каждый независим и не ломает production.

---

См. также:
- [PROJECT.md](PROJECT.md) — обзор архитектуры
- [GSC_APPLY_PLAN.md](GSC_APPLY_PLAN.md) — история коммитов v0.17→v0.26
- [docs/S1_IMPLEMENTATION.md](docs/S1_IMPLEMENTATION.md) — поблочный план S1
- [docs/SAAS_STRATEGY.md](docs/SAAS_STRATEGY.md) — полная стратегия SaaS
