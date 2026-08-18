# GSC Roadmap

> v1.4.0 — 08.08.2026. Создано на основе аудита конкурентов и реального использования.

## ✅ Фаза 1 — SaaS MVP (08.08.2026)

| Фича | Статус |
|------|--------|
| FastAPI сервер (10 эндпоинтов) | ✅ |
| Docker-деплой | ✅ |
| GitHub OAuth (JWT-сессии) | ✅ |
| Лендинг с тарифами | ✅ |
| Multi-tenant (SQLite; PostgreSQL готов через S1) | ✅ |
| PR Feedback Tracker (замкнутый цикл) | ✅ |

## 🔴 Фаза 2 — LLM-триаж (в работе)

**Проблема:** без DeepSeek API 95% находок — FP. Regex-детекторы слепы без LLM-перепроверки.

| Фича | Статус |
|------|--------|
| DeepSeek API в контейнере | ⬜ |
| Авто-триаж: regex → LLM → confidence score | ⬜ |
| Батч-ревалидация старых находок | ⬜ |
| Fallback на regex-only при отсутствии API ключа | ✅ уже есть |

## 🟡 Фаза 3 — Semgrep-совместимые правила

**Проблема:** детекторы на Python — никто не будет писать код чтобы добавить правило. Semgrep выиграл YAML-DSL'ом.

| Фича | Статус |
|------|--------|
| YAML → Python rule compiler | ✅ `gsc_yaml_rules.py` |
| Поддержка Semgrep pattern syntax (`$X`, `...`) | ✅ best-effort regex (аппроксимация AST-матча) |
| Импорт community-правил из semgrep-registry | ✅ `registry update <path\|git-url>` — 63% (1425/2234) компилируются |
| GSC Registry — свой реестр правил | ⬜ |

## 🟢 Фаза 4 — GitHub App с Check Runs

**Проблема:** GSC «внешний» — пользователь должен сам запускать. Конкуренты встроены в GitHub UI.

| Фича | Статус |
|------|--------|
| GitHub App (Check Runs API) | ✅ `create_check_run` + `pull_requests` link + annotations |
| Required status checks (блокировать merge) | ✅ conclusion failure/success (branch protection настраивается на GitHub UI) |
| Webhook: авто-скан каждого PR | ✅ `gsc-fork-safe.yml` (pull_request) |
| PR comment с результатами | ✅ `upsert_comment` + `post-comment` |

## 🟢 Фаза 5 — Reachability Analysis (SCA)

**Проблема:** GSC просто сравнивает версии с OSV.dev. Snyk показывает вызывается ли уязвимая функция.

| Фича | Статус |
|------|--------|
| AST-анализ импортов Python | ✅ `gsc_reachability.py` (ImportVisitor/CallVisitor) |
| Call graph: кто вызывает уязвимый код? | ✅ `check_reachability` (imported + called) |
| dos-достижимости: «CVE в библиотеке, но ты не используешь уязвимую функцию» | ✅ not-reachable → downgrade severity (CRITICAL→HIGH→…) |
| Поддержка JS/TS (npm) | 🟢 потом |

## 🟢 Фаза 6 — Dashboard с трендами

| Фича | Статус |
|------|--------|
| Web-дашборд (FastAPI + Chart.js) | ✅ `server.py` `/dashboard` |
| Тренды: «12 XSS в этом месяце, 3 исправлено» | ✅ line chart (30 дней) + fixed count |
| Per-tenant статистика | ✅ tenant-scoped (`get_tenant_from_key`) |
| История сканирований | 🟡 частично (audit_runs last-scan) |

## 🟣 Фаза 7 — Vulnerability Prediction (убийца)

**Идея:** предсказывать какие файлы получат CVE. На основе:
- GSC archaeology (git history уязвимостей)
- ML на истории коммитов
- Паттерны: файлы которые часто патчат → будут патчить снова

Этого нет **ни у кого**. Даже у Snyk/Semgrep.

| Фича | Статус |
|------|--------|
| ML-модель на git history | ✅ `RiskForecaster` (past density + churn + authors + size + age + clustering) |
| Heatmap: «эти 3 файла — кандидаты на CVE» | ✅ `forecast heatmap` (score + level + epss + top_cves) |
| Интеграция с EPSS (exploitability) | ✅ `exploitability_boost` (reachable CVE × EPSS → буст риска) |

## 🟡 S1 — Multi-tenant PostgreSQL + packages split (архитектурный долг)

**Источник:** A-01/A-04/A-05 (audit) — «несколько контуров, in-process workers, SQLite».
→ трек 0.5 packages split + S1 PostgreSQL.

### ✅ Закрыто (14.08.2026)

| Шаг | Что | Где |
|-----|-----|-----|
| 1.1 | Контракт backend-абстракции зафиксирован 12 тестами | `gsc_db_backend.py` + `tests/test_db_backend.py` |
| 1.2 | Backend-фабрика в server.py (`get_backend()`: SQLite default / PgBackend при `GSC_DATABASE_URL`) | `server.py` |
| 1.3 | Миграция SQLite→PG + docker postgres | `scripts/gsc_pg_migrate.py`, `cloud/schema_runtime.sql`, `docker-compose.yml` |

Все endpoint'ы переведены с sqlite3 `conn` на backend API (`fetchone`/`query`/`insert_id`/`execute`).
`INSERT OR REPLACE`→`ON CONFLICT`, `lastrowid`→`RETURNING`, `datetime('now')`→Python timestamp,
`date()`/`date('now')`→`date_expr()`/`now_expr()`. Проверено на реальном postgres:16 (docker):
signup→stats/findings/scans/dashboard 200.

### ⬜ Осталось (не делать без реальной потребности)

| Трек | Что | Когда |
|------|-----|-------|
| **Трек 2** | Workers out-of-process: `cloud/workers.py` → отдельный процесс/контейнер (`gsc_worker`), очередь через существующие таблицы (без Redis), `gsc-worker` сервис в compose | перед multi-tenant prod под нагрузкой |
| **Трек 3** | Packages split: `src/gsc/` layout (`core/`, `scanners/`, `detectors/`, `cloud/`, `enterprise/`, `forecast/`), относительные импорты, `gsc.py` → console-script | перед внешними контрибьюторами |

### ⚠️ Известные ограничения / хвосты

- `cloud/schema_runtime.sql` (server.py SaaS MVP) **не совпадает** с enterprise `schema_s1..s5.sql`:
  там `findings.scan_id NOT NULL`, `scans` вместо `scan_jobs`, нет `sessions`. Это два разных слоя —
  enterprise-слой мигрируется отдельно (S3+); согласование схем не делалось.
- RLS в `schema_runtime.sql` намеренно НЕ включён: server.py ходит одним глобальным backend (tenant_id=0),
  tenant скоупится явно в WHERE. RLS — отдельный этап (per-request/per-tenant backend, `enterprise/tenancy.py`).
- `_fix_sequences` в миграции сбрасывает BIGSERIAL после явных id — обязателен, иначе duplicate key на первом INSERT.
- `write_file` создаёт файлы `600` → для docker-mount init-скриптов нужен `chmod 644`.
- SCA/EPSS audit DB пусты (`GS030 findings: 0`, `epss_cache rows: 0`) — буст Ф7 активируется после накопления данных.

## Эксклюзивы GSC (уже есть, нет у конкурентов)

| Фича | Конкуренты |
|------|-----------|
| **Proof-of-Fix** — авто-проверка фикса | Никто |
| **Federated Self-Learning** — деактивация FP между тенантами | Никто |
| **Security Archaeology** — trace через git history | Никто |
| **Cross-repo Secrets** — отслеживание между репо | Никто |
| **Attack Chain Composer** — связывание уязвимостей в цепочки | Никто |
| **42 детектора** (SAST+SCA+Secrets+IaC+SBOM) | Больше Semgrep Community |

---

## Методология закрытия фазы (Ф3–Ф7, 14.08.2026)

Каждая фаза закрывалась по одному рецепту — переиспользуем для следующей:

1. **Разведка.** Большинство фаз уже наполовину готовы (Ф3 `yaml_rules` regex-only, Ф4 `create_check_run` без PR-link, Ф7 `RiskForecaster`+`gsc_epss.py` не связаны). Работа — «дотянуть недостающее», не «строить с нуля».
2. **Сначала тест.** `tests/test_phases_2_6.py` фиксирует контракт фазы (имена функций, сигнатуры). Не выдумывать параллельный интерфейс.
3. **Контрактный разрыв.** `make_finding()` отдавал `file/line/snippet`, а `gsc_external.py` читает `file_path/line_number/detail` → все YAML-находки были `file_path=None`. Эмитить оба набора ключей.
4. **Smoke на реальном пути.** Реальный импорт semgrep-rules (2234 правила), живой `/dashboard` (uvicorn+signup+curl), реальный `forecast heatmap` — юнит-тест не ловит `patterns: null`/`KeyError: 'trend'`/`IsADirectoryError`.
5. **Замыкание.** Judge (с явным доменом) → commit → push → перевернуть статус фазы ⬜→🟡→🟢.
