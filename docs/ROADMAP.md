# GSC Roadmap

> v1.4.0 — 08.08.2026. Создано на основе аудита конкурентов и реального использования.

## ✅ Фаза 1 — SaaS MVP (08.08.2026)

| Фича | Статус |
|------|--------|
| FastAPI сервер (10 эндпоинтов) | ✅ |
| Docker-деплой | ✅ |
| GitHub OAuth (JWT-сессии) | ✅ |
| Лендинг с тарифами | ✅ |
| Multi-tenant (SQLite) | ✅ |
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

## Эксклюзивы GSC (уже есть, нет у конкурентов)

| Фича | Конкуренты |
|------|-----------|
| **Proof-of-Fix** — авто-проверка фикса | Никто |
| **Federated Self-Learning** — деактивация FP между тенантами | Никто |
| **Security Archaeology** — trace через git history | Никто |
| **Cross-repo Secrets** — отслеживание между репо | Никто |
| **Attack Chain Composer** — связывание уязвимостей в цепочки | Никто |
| **41 детектор** (SAST+SCA+Secrets+IaC+SBOM) | Больше Semgrep Community |

---

## Методология закрытия фазы (Ф3–Ф7, 14.08.2026)

Каждая фаза закрывалась по одному рецепту — переиспользуем для следующей:

1. **Разведка.** Большинство фаз уже наполовину готовы (Ф3 `yaml_rules` regex-only, Ф4 `create_check_run` без PR-link, Ф7 `RiskForecaster`+`gsc_epss.py` не связаны). Работа — «дотянуть недостающее», не «строить с нуля».
2. **Сначала тест.** `tests/test_phases_2_6.py` фиксирует контракт фазы (имена функций, сигнатуры). Не выдумывать параллельный интерфейс.
3. **Контрактный разрыв.** `make_finding()` отдавал `file/line/snippet`, а `gsc_external.py` читает `file_path/line_number/detail` → все YAML-находки были `file_path=None`. Эмитить оба набора ключей.
4. **Smoke на реальном пути.** Реальный импорт semgrep-rules (2234 правила), живой `/dashboard` (uvicorn+signup+curl), реальный `forecast heatmap` — юнит-тест не ловит `patterns: null`/`KeyError: 'trend'`/`IsADirectoryError`.
5. **Замыкание.** Judge (с явным доменом) → commit → push → перевернуть статус фазы ⬜→🟡→🟢.
