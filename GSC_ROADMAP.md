# GSC ROADMAP — что сделано и что предстоит

> **Статус на 18.08.2026** | Ядро v1.4.0, 42 детектора | Безопасность: аудит 28/28 ✅ + AppSec DD-01..DD-10 ✅ + pre-фильтр ✅ | Cloud: спроектирован (S1–S4), PostgreSQL ⏳ | VSCode: Open VSX ✅ | Фичи: attack-graph + fix-quality + MTTFV SLA + watermark + perf-бенчмарк + pre-commit ✅, runtime validator #1 Phase 1+2 ✅ (in-process + strace) | **Precision CRITICAL ~8–12% ⚠️ → Трек 0.12** | **Traction 4★ ⚠️ → Трек 0.13**

Сводная дорожная карта по всем трекам: ядро, безопасность, rollout, SaaS, Enterprise, VSCode, бизнес.

---

## 1. Сводный обзор

| Трек | Статус | Что осталось |
|---|---|---|
| Ядро сканера (v0.11→v1.3) | ✅ готово (42 детектора) | ничего |
| Безопасность (аудит 28 + AppSec DD-01..DD-10) | ✅ 28/28 + 10/10 закрыто (13.08 + 15.08) | PostgreSQL для multi-tenant (DD-09) |
| Pre-фильтр файлов (скорость скана) | ✅ `6071d5d` (15.08) | ничего |
| Packages split (core/cli/cloud) | ✅ 0.5.1–0.5.5 все запушены (`78222dc`,`e821e62`,`b29af60`,`b1cb6c6`) | ничего |
| Production rollout Phase 0–5 | ✅ завершён | наблюдение |
| Юридическая защита | 🟡 частично (BSL + SPDX ✅, CLA ❌) | CONTRIBUTING.md + trademark (1 день) |
| SaaS Cloud (S1–S4) | 📝 спроектирован | PostgreSQL + RLS (S1) + реализация (~4 мес) |
| Enterprise hybrid agent | 📝 спроектирован | реализация (2–3 нед) |
| VSCode extension | ✅ v0.32 + Open VSX опубликован | GitHub Releases (Marketplace РФ ❌) |
| Киллер-фичи | 🟡 #2 supply-chain + #3 exploit-refinement ✅ | #1 runtime validator Phase 1+2 ✅ (in-process + strace) |
| GSC Bot (виральность чужих PR) | 📝 спроектирован (`docs/GSC_BOT.md`) | реализация 0.8.1–0.8.5 (~2 нед, до S1) |
| Языки JS/TS/Go (top-5 детекторов) | 📝 спроектирован | 0.9.1–0.9.5 — снять потолок роста |
| Security Debt Ledger (фин. слой) | 📝 спроектирован | 0.10.1–0.10.4 — риск в деньгах |
| Agentic self-healing (итеративный) | 📝 спроектирован | 0.11.1–0.11.4 — patch→test→retry |
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

**Итог (v1.4.0, 19.08):** 42 детектора, 426 тестов (75 файлов), calibration 13/13, schema 33, 154 модуля (packages split 0.5.1–0.5.3), self-learning + MTTFV SLA + attack-path graph + fix-quality + PoC watermarking + perf + pre-commit.

### 2.1a. Безопасность (✅ 15.08) — укрупнённый итог

Два независимых аудита + сканер-оптимизация закрыты полностью.

| Аудит | Результат | Коммит |
|---|---|---|
| Внутренний аудит (28 замечаний) | 28/28 закрыто (8 коммитов) | 13.08 |
| AppSec due-diligence (DD-01..DD-10) | 10/10 закрыто (2×P0, 4×P1, 4×P2) | `56c6d6f` (15.08) |
| Pre-фильтр файлов (скорость скана) | не зависает на больших проектах | `6071d5d` (15.08) |

**Ключевое из DD-аудита (закрыто):**
- **DD-01/DD-02 (P0):** сгенерированный PoC больше не наследует `os.environ`
  (env-whitelist вместо `{**os.environ}`) и выполняется в контейнере → rlimit
  fallback, а не на хосте через bare `subprocess.run`.
- **DD-03:** `_detect_fn` использует реальный registry, не заглушку из 4 правил.
- **DD-09 (частично):** `scan_jobs` UPDATE scoped по `tenant_id`; сам PostgreSQL — см. Трек 1 (S1).

**Вывод аудитора:** после P0-фиксов GSC готов к single-tenant/self-hosted пилоту.
Multi-tenant SaaS требует PostgreSQL (→ Трек 1 S1).

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
| 0.7 | **Пересмотр лицензии**: BSL → Apache 2.0 + Commercial dual | ✅ сделано (13.08: `LICENSE` + `COMMERCIAL.md` + README) |

### Трек 0.5. Packages split — физический рефакторинг (3–5 дней)

> Аудит A-01. Логический уровень уже закрыт в `e06c355` (deps + extras + artifacts).
> Здесь — физический перенос в `gsc_core/` `gsc_cli/` `gsc_cloud/` с shim-совместимостью.

**Цель:** убрать конкурирующие runtime-слои (gsc.py, gsc_external.py, server.py, cloud/, enterprise/ в одном checkout) и дать чистый seam для S1 PgBackend.

| # | Порция | Содержание | Проверка |
|---|---|---|---|
| 0.5.1 | `gsc_core/` | ✅ `78222dc`: движок + детекторы (db, blocking, detectors/, invariant_engine, compliance, sca, epss, federated, ast_dataflow, iac, secrets_core, yaml_rules) + shim (module-aliasing), 272 passed | `tests/test_schema_integrity.py` + `tests/test_corpus.py` зелёные |
| 0.5.2 | `gsc_cli/` | ✅ `e821e62`: CLI+сканеры (51 модуль + main.py) — orchestrator, external, github_adapter, poc_*, chain/exploit, proofoffix, selfhealing, archaeology, forecast, nlpolicy, nuclei, dast, sbom, spdx, revalidate, runtime_validator + `scripts/`; entry `gsc = "gsc_cli.main:main"` | `gsc scan` + `gsc external-scan` smoke |
| 0.5.3 | `gsc_cloud/` | ✅ `b29af60`: SaaS (39 модулей) — api, api_v2, auth, billing, tenancy, sso, worker(s), scan_queue, marketplace, federated_server, mcp_server, pr_commands + `server.py` shim | TestClient smoke (signup/stats/findings) |
| 0.5.4 | dev/collector | ✅ `b1cb6c6`: `gsc_collector/` → `gsc_core/gsc_collector/` (Scrapy-пакет + runner + scrapy.cfg); `enterprise/tests/test_enterprise.py` → `tests/`; `include-package-data=false` + MANIFEST `prune` | wheel без dev-артефактов (grep чист) |
| 0.5.5 | shim + cleanup | ✅ `b1cb6c6`: cron/scripts мигрированы на `gsc_core`/`gsc_cli`/`gsc_cloud` (21 импорт); shim остаются re-export; `build/lib` удалён | `compileall` OK + 272 passed/5 skipped + reconcile ALL MATCH |

**Инварианты:** каждый шаг — зелёные тесты перед/после; shim-слой живёт до миграции всех cron-скриптов; `build/lib` (вторичная копия) удаляется в 0.5.5.

**Зависимость:** выполняется ДО S1 (PgBackend требует чистого core/cloud разделения).

### Трек 0.6. Runtime Validator — IAST-lite (из экспертизы #1)

> Proof-of-Fix верификация по факту runtime-эксплуатации, не по stdout-маркеру.
> Решение принято (13.08): phased **D → B → F**, без eBPF `--privileged` (откатывает F-05).

| # | Порция | Содержание | Проверка |
|---|---|---|---|
| 0.6.1 | Phase 1 (in-process) | ✅ `gsc_runtime_validator.py`: monkeypatch `open`/`subprocess.Popen`/`socket.connect` в `sitecustomize.py` (hook через PYTHONPATH), лог факта вызова в JSONL | coverage 93%, 8 тестов |
| 0.6.2 | Phase 2 (strace) | ✅ `strace_validate()` в `gsc_runtime_validator.py`: `strace -f -e trace=openat,connect,execve` + парсинг + фильтр | фильтр по workdir, 6 тестов |
| 0.6.3 | Phase 3 (Falco/Tetragon) | отдельный privileged-агент в K8s, только enterprise on-prem (>10 тенантов) | изоляция от GSC core |

**Готово к этому треку:** Phase 0 замер + fmt-dispatch фикс + HTTP-server runner (`gsc_pof_sandbox`) + **Phase 3 multi-module runner** (entrypoint-детект + symlink-проекта).

### Трек 0.7. Sale-Readiness (из sell-side аудита, 13.08)

> Готовность к due-diligence покупателя. Блокеры P0→P1 из `GSC_SALE_ANALYSIS.pdf`.

| # | Задача | Статус |
|---|---|---|
| 0.7.1 | pytest collectible (sys.exit guard + rename custom runner) | ✅ 105 passed / 4 skipped |
| 0.7.2 | README overclaims «*Nobody*» → evidence-backed таблица | ✅ |
| 0.7.3 | MCP server (scan/findings/explain/fix/verify tools) | ✅ read-only (scan_repo/list_findings/verify_finding) |
| 0.7.4 | Traction: 5 design partners, 2 paid pilots | ⏳ бизнес |
| 0.7.5 | IP: assignment, contributor waivers, SPDX, clean chain-of-title | ⏳ юрид. |
| 0.7.6 | Benchmark: 100–150 fixtures + сравнение Semgrep/CodeQL/Bandit | ❌ новый трек |
| 0.7.7 | Enterprise hardening: sandbox threat model, egress policy, LLM no-LLM/retention | ❌ P1 |
| 0.7.8 | Repo hygiene: build artifacts, `.next`, `.repowise`, stable/experimental split | 🟡 частично |

**Позиционирование:** «verified remediation engine» (PoC → patch → re-verify), **не** «SAST-конкурент Snyk».
Оценка sell-side: $100–500K tech / $50–150K acqui-hire сейчас; $1–3M после 3–6 мес доказательств (benchmark, pilots).

### Трек 0.8. GSC Bot — виральная верификация чужих PR (спроектирован, ~2 недели)

> GitHub App `gsc-bot` приходит на ЧУЖОЙ PR по вызову `@gsc`/`/gsc` и оставляет плашку GSC
> (badge + отчёт + label `gsc-verified` + check-run). Каждый такой PR = бесплатная реклама.
> **Полная спека:** `docs/GSC_BOT.md`. Активирует no-op `co_author_trailer()` из `gsc_signature.py`.

| # | Фаза | Содержание | Проверка |
|---|---|---|---|
| 0.8.1 | App scaffold | манифест, webhook endpoint, HMAC-верификация, installation token | неверный HMAC → 401 |
| 0.8.2 | `/gsc scan` | diff-скан → комментарий `🔍 Scanned by GSC` + badge + отчёт (adapter+signature) | `@gsc scan` → комментарий < 30 сек |
| 0.8.3 | `/gsc verify` | PoF по изменениям → label `gsc-verified` (только verified) + check-run | label только при verified |
| 0.8.4 | co-author | `Co-authored-by: gsc-bot[bot]` (закрывает no-op trailer) | трейлер линкуется |
| 0.8.5 | авто-детект | AI-сигнатура в PR body → предложение `@gsc scan` | PR от Claude/Codex → предложение |

**Безопасность (non-negotiable):** HMAC webhook, installation token short-lived, permissions
least-privilege (`contents: read`, `pull-requests/issues/checks: write`, БЕЗ `contents: write`),
fork-код — static + sandbox (не исполняется с привилегиями), private key — age-шифрование.

**Связь с S2:** 0.8 — минимальный **standalone** App (SQLite, self-hosted), можно ДО S1.
S2 затем поглощает 0.8 (multi-tenant GitHub App поверх PG).

### Трек 0.9. Языковая поддержка JS/TS/Go (спроектирован, ~2–3 недели)

> Снять потолок роста: GSC сейчас Python-first, на Java/JS/Go детекторы дают 0–слабый TPR
> (замерено: GS004/GS020 0% TPR на OWASP Java). Фокус — top-5 детекторов, НЕ все 41.

| # | Фаза | Содержание | Проверка |
|---|---|---|---|
| 0.9.1 | Инвентаризация | какие из GS005/GS029/GS020/GS004/GS022 language-specific, какие Python-only | карта детектор×язык |
| 0.9.2 | GS029 + GS005 → JS/TS | secrets (language-agnostic) + SQLi (паттерны схожи) | benchmark TPR>0 на JS/TS |
| 0.9.3 | GS020 + GS022 → JS/TS | DOM XSS (React/DOM sinks) + open redirect | benchmark TPR>0 |
| 0.9.4 | GS004 + Go | нативные Go-паттерны (`net/http`, `database/sql`) | benchmark TPR>0 |
| 0.9.5 | Calibration | синтетический benchmark (`ghsa_benchmark`) на JS/TS/Go, замер TPR/FPR | FPR на Python НЕ вырос |

### Трек 0.10. Security Debt Ledger — финансовый слой (спроектирован, ~1–2 недели)

> Перевести технический риск в деньги (annualized loss) для CISO/CIO — язык бюджета.
> Сырьё уже есть: EPSS (exploitability) + compliance mapping (CWE/OWASP/PCI) + SCA (OSV.dev).

| # | Фаза | Содержание | Проверка |
|---|---|---|---|
| 0.10.1 | Формула | severity + EPSS → annualized loss (impact × likelihood × EPSS) | число $ на finding |
| 0.10.2 | CVSS/insurance | CVSS-вектор + cyber-insurance скоринг (CWE → страховая категория) | маппинг CWE→$ |
| 0.10.3 | Отчёт | «Security Debt» в CLI/отчёте: суммарный $ по проекту, топ по деньгам | `gsc debt --repo .` |
| 0.10.4 | Тренд | debt во времени (снижение после фиксов) | график до/после |

### Трек 0.11. Agentic Self-Healing — итеративный (спроектирован, ~2 недели)

> Эволюция self-healing (НЕ новая фича): агент не только генерит патч, но гоняет CI/test
> до успеха. Поверх существующего `gsc_selfhealing.py` (patch + PoF + sandbox уже есть).

| # | Фаза | Содержание | Проверка |
|---|---|---|---|
| 0.11.1 | CI-гейт | после patch — прогон тестов (pytest/unit) перед PoF | патч проходит тесты |
| 0.11.2 | Итерация | patch→test→retry при fail (до N попыток) | авто-retry до успеха |
| 0.11.3 | Trail | фиксация попыток в evidence (какой патч прошёл) | audit trail попыток |
| 0.11.4 | Лимиты | MAX_RETRY + budget + rollback | нет бесконечного цикла |

### Трек 0.12. Precision — от шума к доверию (из экспертного анализа 18.08)

> Первый замер `benchmark/PRECISION_REPORT.md`: **2 695 находок** на 10 проектах,
> **precision CRITICAL ~8–12%** (129 CRITICAL, 244 HIGH). Это главный технический барьер
> перед пилотами и инвесторами: «42 детектора» звучит мощно, но ~9 из 10 CRITICAL — FP.

| # | Порция | Содержание | Проверка |
|---|---|---|---|
| 0.12.1 | Baseline | PRECISION_REPORT.md как эталон (10 проектов, 2695 находок) | цифры заморожены |
| 0.12.2 | Precision-hunt | срез FP из БД по `rule_id×category`, фикс топ-генераторов FP (GS001 extractor уже починен) | CRITICAL 8–12% → ≥30% |
| 0.12.3 | Data-quality | пустые/заголовочные `rule_id` → `GS000-LEGACY`, де-контаминация категорий | 0 мусорных rule_id |
| 0.12.4 | Self-learning пруф | метрика TP до/после ночного revalidate (federated, DP) | график TP-тренда (инвестору) |

**Цель:** precision CRITICAL ≥ 50%, HIGH ≥ 40% до старта пилотов (S2). Без этого любой
pitch про «self-learning» разобьётся вопросом «какой % фич реально работает в production».

### Трек 0.13. Traction / GTM (из экспертного анализа 18.08)

> Экспертный разбор: реальный дифференциатор — **Proof-of-Fix** (уже есть). Главные gap'ы —
> **traction (4★, 0 форков)** и **распыление ICP**. Ниша: AI-generated code (Semgrep/Snyk
> заточены под human-written code, у LLM-кода другие паттерны уязвимостей).

| # | Порция | Содержание | Проверка |
|---|---|---|---|
| 0.13.1 | ICP-фокус | 1 ICP: mid-size SaaS с активным CI/CD (FinTech/Gov — только после Series A) | ICP в one-pager |
| 0.13.2 | GitHub traction | 4★ → 100+: README+демо, HALL_OF_FAME, GSC Bot (Трек 0.8) как виральность, HN/Product Hunt | звёзды/форки растут |
| 0.13.3 | Ниша AI-code | позиционирование «security для LLM-generated code» (GS025 AI-provenance — козырь) | pitch + статья/блог |
| 0.13.4 | Free/paid граница | явно: что бесплатно (self-hosted OSS), что платно (Cloud/Enterprise) — до выхода к инвестору | таблица в one-pager |
| 0.13.5 | GHAS-митигация | CodeQL бесплатен для public → позиционировать «verified remediation + AI-code», НЕ «бесплатный SAST» | pitch не пересекается с GHAS |

### Трек 0.14. DD-аудит 19.08 (Manus AI) — закрытие остатков

> Независимая техническая/коммерческая экспертиза (срез `0d4a9fe`). Закрыто за сессию
> 20.08: P1-01 digest-pin (postgres/redis/python/node), P1-02 calibration commit (13/13),
> P2-01 scan-mode test contract, P2-02 canonical test command. Осталось:

| # | Порция | Содержание | Проверка |
|---|---|---|---|
| 0.14.1 | Sandbox escape CI | запустить escape-suite (network/write/host-read) в реальном Docker/Podman runner — сейчас 5 тестов скипаются без runtime | `verified=true` только после isolated before/after |
| 0.14.2 | Внешний benchmark | ≥100 проектов, pinned revisions, blind labels, per-rule precision/recall/F1 | методология + raw результаты опубликованы |
| 0.14.3 | SBOM + provenance | ✅ generate/sign SBOM есть (`sbom` + `sbom-verify` v0.33); осталось SLSA provenance + CI admission «digest only» | CI блокирует tag-only image refs |
| 0.14.4 | Свои образы digest | ✅ 20.08 — helm digest-механизм (`values.digest` + deployment template); pin digest при релизе | production manifests digest-pinned при сборке |
| 0.14.5 | AutoFix draft-only | ✅ 20.08 — draft-only + least-privilege + human approval + audit trail (GSC_EXCLUSIVE_FEATURES.md) | SCM permission model задокументирован |

**Цель:** закрыть формальные P1/P2 аудита до выхода к инвесторам — supply-chain
immutability + воспроизводимый benchmark как доказательная база для «enterprise-grade».

### Трек 1. SaaS Cloud 1.0 (≈ 16–20 недель)

| Этап | Содержание | Оценка |
|---|---|---|
| S1 | Docker-образ, PgBackend + RLS, tenants/api_keys, Redis queue + worker, /api/v2, metering | 3–4 нед |
| S2 | GitHub App (install/webhooks), порт chains/mutations/overrides в PG, /gsc через webhook | 3 нед |
| S3 | Dashboard (Next.js), GitHub OAuth, Stripe checkout + webhook, квоты/402 | 4–5 нед |
| S4 | Audit log + hash chain, SSO OIDC, retention/deletion, SOC 2 Type I→II + ISO27001 prep, Marketplace, GA-гейт | 6–8 нед |

> **DD-09 (AppSec-аудит, 15.08):** PostgreSQL + RLS в S1 — не просто «масштаб», а
> обязательное условие **tenant isolation** для multi-tenant SaaS. SQLite-часть
> (`scan_jobs` UPDATE по `tenant_id`) уже закрыта; полный переезд на PG — в S1.
> До S1 GSC позиционируется как single-tenant/self-hosted.

### Трек 2. Enterprise hybrid agent (2–3 недели)

Runner + activation key + ingest API + кэш/offline + air-gap экспорт. Запускать после S1.

### Трек 3. VSCode extension (Open VSX ✅, VSCode Marketplace ❌ РФ)

Scaffold есть (gsc-vscode, v0.32). **Опубликовано в Open VSX** (13.08): `poliakarmai.gsc-security v1.0.0`
(`open-vsx.org/extension/poliakarmai/gsc-security`) — VSCodium/Gitpod/Theia/CodeSpaces.
VSCode Marketplace (Azure DevOps) недоступен из РФ — заменён на Open VSX + GitHub Releases.

### Трек 4. Бизнес и продажа (параллельно)

| # | Задача | Когда |
|---|---|---|
| 4.1 | One-pager/тизер | неделя 1 |
| 4.2 | Демо-сценарий: цепочка атак + PoC за 15 мин | неделя 1–2 |
| 4.3 | Список 20–30 покупателей + шаблон письма | неделя 2 |
| 4.4 | Пилоты: 3–5 команд | после S2 |
| 4.5 | Конверсия пилотов в Team/Business | после S3 |
| 4.6 | Листинги: GitHub Marketplace, Product Hunt, VSCode Marketplace | после S4 |
| 4.7 | Интеграции: GitHub Advanced Security + GitLab Ultimate (native, не только PR Adapter) | после S3 |
| 4.8 | Решение по лицензии: Apache 2.0 + Commercial dual (множитель цены, см. Трек 0.7) | немедленно |

---

## 4. Зависимости

```
Трек 0 (CLA + trademark, 1 день)
   │
   └──► Трек 0.5 (packages split, 3–5 дней) ──► Трек 1 S1 ──► S2 ──► S3 ──► S4 ──► Cloud 1.0 GA
                 │         │         │       │
                 ├──► Трек 2 (agent) ─┘
                 │
                 └──► Трек 3 (VSCode, параллельно)
```

Трек 4 (бизнес) параллельно всему: one-pager → пилоты (после S2) → платежи (после S3).

---

## 5. Рекомендуемый план

| Период | Фокус | Результат |
|---|---|---|
| Авг 2026 | Трек 0 (CLA, gitleaks, аудит) + **Трек 0.5 packages split** + CONTRIBUTING.md + one-pager | Юридически чистый репо + чистые core/cli/cloud |
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
| GHAS (CodeQL бесплатен для public) — экзистенциальный в OSS | Ниша AI-code + verified remediation, НЕ «бесплатный SAST» (Трек 0.13.5) |
| Precision CRITICAL 8–12% (FP-шум) | Precision-hunt + data-quality до пилотов (Трек 0.12) |

---

*Обновлено: 18.08.2026*
