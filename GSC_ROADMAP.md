# GSC ROADMAP — что сделано и что предстоит

> **Статус на 06.08.2026** | Ядро: v0.26 production, 29 детекторов | Cloud: спроектирован (S1–S4) | VSCode: v0.32 scaffold

Сводная дорожная карта по всем трекам: ядро, rollout, SaaS, Enterprise, VSCode, бизнес.

---

## 1. Сводный обзор

| Трек | Статус | Что осталось |
|---|---|---|
| Ядро сканера (v0.11→v0.26) | ✅ готово (29 детекторов) | ничего |
| Production rollout Phase 0–5 | ✅ завершён | наблюдение |
| Юридическая защита | 🟡 частично (BSL + SPDX ✅, CLA ❌) | CONTRIBUTING.md + trademark (1 день) |
| SaaS Cloud (S1–S4) | 📝 спроектирован | реализация (~4 мес) |
| Enterprise hybrid agent | 📝 спроектирован | реализация (2–3 нед) |
| VSCode extension | 📝 спроектирован (scaffold есть) | доделать (2 нед) |
| Продажа / пилоты | 🔜 | one-pager, покупатели, пилоты |

---

## 2. Что СДЕЛАНО

### 2.1. Ядро GSC (✅ production)

| Версия | Результат | Доказательство |
|---|---|---|
| v0.11–v0.16 | MVP → finding_key, feedback, REST API | 8/8 тестов |
| v0.17 | PoC Auto-Generation + GS025 AI-provenance | redaction gate |
| v0.18 | Exploit Chain Composer + chains feedback | schema 18 |
| v0.19 | Temporal Mutation Tracker + auto-resolve | backfill 400K, schema 19 |
| v0.20 | Security Invariant Engine + GS028 | safe-mode |
| v0.21 | AST taint, cross-file chains, hard calibration | 17/17 |
| v0.22–v0.26 | Rollout Phase 1–5: dry-run → warn → feedback → blocking CRITICAL → blocking standard | overrides, bypass, shadow |

**Итог:** 29 детекторов + LLM, тесты, calibration 17/17, schema 23, 400K находок, self-learning.

### 2.2. Юридическая защита (🟡 2/3)

| Задача | Статус | Дата |
|---|---|---|
| BSL 1.1 LICENSE + README-блок | ✅ сделано | 05.08.2026 |
| SPDX-заголовки (40 файлов) | ✅ сделано | 05.08.2026 |
| CONTRIBUTING.md с CLA | ❌ не сделано | — |
| Trademark | ❌ не сделано | — |

### 2.3. Документация и дизайн (✅ готово)

| Артефакт | Содержание |
|---|---|
| PROJECT.md | полная документация ядра |
| GSC_APPLY_PLAN.md | 31 коммит v0.17→v0.26, откаты, бэкапы |
| GSC_ROADMAP.md | этот файл |
| GSC_SAAS_ROADMAP.md | стратегия SaaS, тарифы, архитектура |
| План S1 | 9 коммитов: Docker, PgBackend, queue, API v2, metering |
| План S2 | 8 коммитов: GitHub App, порт подсистем в PG |
| План S3 | 7 коммитов: dashboard, OAuth, Stripe |
| План S4 | 9 коммитов: audit log, SSO, DPA, SOC 2, Marketplace, Cloud 1.0 |
| План Enterprise agent | 8 блоков: runner, activation, ingest, air-gap |
| План VSCode v0.32 | 8 блоков: diagnostics, CodeLens, chains, SARIF |

### 2.4. Инфраструктура (✅)

| Компонент | Статус |
|---|---|
| Docker Compose (Cloud 1.0) | ✅ закоммичен |
| Kubernetes-манифесты | ✅ закоммичены |
| FastAPI-роутеры | ✅ закоммичены |
| Все SQL-схемы | ✅ закоммичены |
| Dashboard (Next.js scaffold) | ✅ закоммичен |

---

## 3. Что НАДО СДЕЛАТЬ

### Трек 0. Юридический фундамент — доделать (1 день)

| # | Задача | Статус |
|---|---|---|
| 0.1 | BSL 1.1 + README-блок + SPDX | ✅ |
| 0.2 | CONTRIBUTING.md с CLA | ❌ 30 мин |
| 0.3 | Прогнать историю на секреты (gitleaks) | ❌ 2 часа |
| 0.4 | Аудит лицензий зависимостей (нет GPL) | ❌ 1 час |
| 0.5 | Trademark на название/логотип | ❌ 1 нед (заявка) |
| 0.6 | Зафиксировать доказательства авторства | ❌ 1 час |

### Трек 1. SaaS Cloud 1.0 (≈ 16–20 недель)

| Этап | Содержание | Оценка |
|---|---|---|
| S1 | Docker-образ, PgBackend + RLS, tenants/api_keys, Redis queue + worker, /api/v2, metering | 3–4 нед |
| S2 | GitHub App (install/webhooks), порт chains/mutations/overrides в PG, /gsc через webhook | 3 нед |
| S3 | Dashboard (Next.js), GitHub OAuth, Stripe checkout + webhook, квоты/402 | 4–5 нед |
| S4 | Audit log + hash chain, SSO OIDC, retention/deletion, SOC 2 prep, Marketplace, GA-гейт | 6–8 нед |

### Трек 2. Enterprise hybrid agent (2–3 недели)

Runner + activation key + ingest API + кэш/offline + air-gap экспорт. Запускать после S1.

### Трек 3. VSCode extension (2 недели + Marketplace)

Scaffold есть (gsc-vscode, v0.32). Осталось: GscClient, diagnostics, CodeLens-вердикты, chains webview, публикация.

### Трек 4. Бизнес и продажа (параллельно)

| # | Задача | Когда |
|---|---|---|
| 4.1 | One-pager/тизер | неделя 1 |
| 4.2 | Демо-сценарий: цепочка атак + PoC за 15 мин | неделя 1–2 |
| 4.3 | Список 20–30 покупателей + шаблон письма | неделя 2 |
| 4.4 | Пилоты: 3–5 команд | после S2 |
| 4.5 | Конверсия пилотов в Team/Business | после S3 |
| 4.6 | Листинги: GitHub Marketplace, Product Hunt, VSCode Marketplace | после S4 |

---

## 4. Зависимости

```
Трек 0 (CLA + trademark, 1 день)
   │
   ├──► Трек 1 S1 ──► S2 ──► S3 ──► S4 ──► Cloud 1.0 GA
   │         │         │       │
   │         ├──► Трек 2 (agent) ──┘
   │         │
   └──► Трек 3 (VSCode, параллельно)
```

Трек 4 (бизнес) параллельно всему: one-pager → пилоты (после S2) → платежи (после S3).

---

## 5. Рекомендуемый план

| Период | Фокус | Результат |
|---|---|---|
| Авг 2026 | Трек 0 (CLA, gitleaks, аудит) + CONTRIBUTING.md + one-pager | Юридически чистый репо |
| Авг–Сен 2026 | S1 + S2 + VSCode | GitHub App, 3–5 пилотов |
| Окт–Дек 2026 | S3 + первые платежи | Private beta Cloud |
| Янв–Мар 2027 | S4 + Enterprise agent | Cloud 1.0 GA |
| Апр–Июн 2027 | Marketplace-листинги, рост / продажа | Traction → решение |

---

## 6. Критический путь к выручке

```
CLA (1 день) → S1 (3–4 нед) → S2 (3 нед) → пилоты → S3 (4 нед) → платежи
```
≈ 3 месяца до первых денег.

---

## 7. Риски

| Риск | Митигация |
|---|---|
| Соло-пропускная способность | Жёсткая последовательность S1→S4 |
| LLM-расходы при росте | Глобальный кэш по fingerprint, regex-first |
| Стоимость SOC 2 | Отложить до Enterprise-спроса |
| Конкуренты (Semgrep/Snyk) | Ниша self-learning + PoC, PLG free-tier |

---

*Обновлено: 06.08.2026*
