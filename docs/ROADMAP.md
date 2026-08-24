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
| Cross-model voting — второй вердикт другой моделью (Qwen/Gemini) для CRITICAL/HIGH, расхождение → demote | ⬜ |
| Receipt-контракт — rejudge по полному `file:line` + taint-пути (`gsc_ast_dataflow.py`), вердикт без цитаты = INCOMPLETE/demote | ⬜ |
| Self-verification (Best-of-N той же модели) — дешевле cross-model voting, доказано +7-9% точности | ⬜ |
| Fine-grained criteria rejudge — source-to-sink / reachability / exploitability вместо одного вердикта | ⬜ |
| Flash-verifier — rejudge на deepseek-v4-flash (дёшево) | ⬜ |
| Logprob-based confidence вместо regex `_extract_confidence` | ⬜ |
| LLM-first-pass auditor — LLM читает весь репо → semantic findings (до regex), опциональный `--with-llm-first-pass` | ⬜ |
| Multi-model panel + judge — 3 ревьюера в изоляции + судья (follow-up) для CRITICAL/HIGH | ⬜ |

> Источник усиления: разбор NeuroSploit (agentic pentest, MIT) — grounding «no claim without a receipt» + cross-model validation. Не конкурент-сканер, но 2 механики бьют по галлюцинациям single-model rejudge (`gsc_rejudge.py` видит только `snippet[:100]`).
> Уточнение (LLM-as-a-Verifier, pip `llm-verifier`): self-verification Best-of-N той же моделью (Pass@1 79→88%) может быть выгоднее cross-model voting; fine-grained criteria + flash-verifier + logprob-калибровка заменяют грубый бинарный rejudge.
> LLM-first-pass (Claude-style «аудит за 30 сек»): GSC использует LLM только как верификатор/threat-model, не как генератор findings первого эшелона — добавить опциональный whole-repo LLM-проход, комплементарно regex (semantic depth vs deterministic recall).
> Rejudge (syabro): panel+judge (3 ревьюера + судья) замыкает лестницу точности Фазы 2 — self-verification (1 модель) < cross-model voting (2) < panel+judge (4). ⚠️ автор честно: «no measured advantage over one strong model», дорого, только CRITICAL/HIGH.

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

## 🟡 Фаза 5.5 — SCA License Compliance

**Источник:** книга «Implementing DevSecOps Practices» (Packt, Vandana Verma Sehgal — Snyk) — Ch 13.
**Проблема:** GSC SCA ловит только уязвимости (OSV.dev), но не лицензии зависимостей. Клиенты в первую
очередь боятся GPL/copyleft-заражения. Snyk/Black Duck/FOSSA продают license detection как core-фичу SCA.

| Фича | Статус |
|------|--------|
| `gsc_sca_license.py` — детект лицензий из manifest (requirements/pyproject/package.json/go.mod) | ✅ |
| Классификация: permissive (MIT/Apache/BSD) vs copyleft (GPL/LGPL/AGPL) vs proprietary | ✅ |
| Policy-движок: approved/forbidden lists → flag/block copyleft в коммерческом коде | ✅ |
| Интеграция с SBOM (SPDX уже есть) + PR-gate | ✅ |

✅ Реализовано (22.08.2026): `gsc_core/gsc_sca_license.py` — SPDX-классификация
(permissive / weak-copyleft / copyleft / proprietary), license lookup PyPI/npm
(без API-ключа), policy-gate `evaluate_policy()`, CLI `gsc sca-license`.
SBOM/SPDX обогащены license (`generate_sbom`/`generate_spdx` + `licenses=`),
PR-gate через `--gate` (exit 1 при forbidden). Тесты (10 passed).

✅ DREAD/PASTA добавлены (22.08.2026): детерминированный DREAD-скоринг (0-50) +
7 стадий PASTA в `gsc_threat_model.py` (`dread_score`/`apply_dread`/`pasta_stages`).
Осталось: attack trees (Фаза 6 атаки).

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

## 🔴 Фаза 8 — Secret Verification (live-проверка ключей)

**Источник:** разбор TruffleHog (884 детектора, `Verify()` логинит в API → live/rotated/dead).
**Проблема:** GS001/GS029 находят тестовые/мёртвые секреты (`AKIA00...0000`, placeholder-токены)
и тащат их как CRITICAL. Precision CRITICAL ~4–5% (Замер 3, 100 проектов) — часть шума тут, часть в голом eval (починен multi_lang.py + `ba4c2d0`).
TruffleHog убивает этот шум проверкой: один запрос к API провайдера → 200 = live (TP), 401/403 = dead (FP).

| Фича | Статус |
|------|--------|
| `gsc_secrets_verifier.py` — движок live-проверки | ✅ |
| Проверка провайдеров (GitHub/AWS/Slack/Stripe/Postgres) | 🟡 GitHub/Slack/Stripe ✅, AWS/DB TODO |
| По ответу 200/401/403 → `status: verified\|dead` → авто-FP/deboost | ✅ `deboost_dead` |
| Кэш результатов (не дёргать API повторно на ре-скане) | ✅ |

✅ Реализовано (22.08.2026): `gsc_cli/gsc_secrets_verifier.py` — `detect_provider` (по
префиксу: ghp_/xoxb-/sk_live_/AKIA/…), `verify_secret` (GitHub `GET /user`, Slack
`auth.test`, Stripe `GET /account`; 200=live, 401/403=dead), кэш по fingerprint,
`deboost_dead` (dead → confidence ×0.3 + metadata). Redaction: значение не логируется,
только fingerprint. Тесты 6 passed. Пайплайн-интеграция: `GS029.detect(verify_live=...)` +
env-флаг `GSC_VERIFY_SECRETS=1` (off by default, как DAST) → dead → confidence ×0.3.
Хвосты добиты: rate-limiter+budget (100ms/200 запросов), `is_test_key` (sk_test_/rk_test_/ASIA → INFO),
pass provider из secret_type. AWS (SigV4) + DB (connect-test) — осознанно не делаем (SSRF/сложность).
| Entropy + redaction (только fingerprint, без значения) | ✅ `gsc_secrets_core.py` + GS029 |
| Cross-repo корреляция (сильнее TruffleHog) | ✅ `gsc_crossrepo_secrets.py` |

⚠️ **Лицензия:** TruffleHog AGPL-3.0 — движок/код не брать, только идею + список провайдеров/паттернов.
⚠️ **Scope:** Discovery-источники (S3/Slack/Jira/docker) и Analysis (deep enum) — off-scope, потом.

## 🔴 Фаза 9 — GitHub Actions CI/CD Audit

**Источник:** разбор reconFTW (доменный recon, MIT) — единственное пересечение с GSC: gato (аудит `.github/workflows/*.yml`).
**Проблема:** GSC не покрывает CI/CD-уязвимости GitHub Actions. GS034 (supply chain) смотрит зависимости, не пайплайны.
YAML-парсер уже есть (`gsc_yaml_rules.py`, `gsc_iac.py`) — не хватает детектора под Actions-специфику.

| Фича | Статус |
|------|--------|
| GS045 — детектор `.github/workflows/*.yml`: `pull_request_target` + checkout untrusted | ✅ |
| Self-hosted runner на PR (RCE через fork) | ✅ GS033 |
| Secrets в `env:` / exfiltration | ✅ GS045 |
| Отсутствие `permissions:` (least-privilege) | ✅ GS045 |
| `workflow_run` без защиты / OIDC misconfig | ✅ GS045 |

✅ Реализовано (22.08.2026): `gsc_core/gsc_detectors/gs045_github_actions.py` — 4 правила:
`missing_permissions`, `hardcoded_env_secret`, `pr_target_checkout_head` (CRITICAL),
`workflow_run_untrusted_checkout`. Self-hosted runner уже покрыт GS033. Тесты
`tests/test_gs045_github_actions.py` (4 passed), registry 43 детектора.

⚠️ reconFTW остальное (subdomain/port/nuclei/OSINT email) — off-scope для Git-сканера.

## 🟡 Фаза 10 — Proof-of-Fix усиление (dependency PoF + adversarial re-attack)

**Источник:** конкурентный разбор Proof-of-Fix аналогов (VeriPatch, Shinobi Security, Nullify,
ai-appsec, AEGIS, Strix, Keygraph) — 22.08.2026. Скилл `gsc-competitive-intel`, раздел 10.
**Проблема:** у GSC замкнутый цикл Detect→Prove→Fix→Verify→Heal (эксклюзив), но `verify_fix`
верифицирует только SAST-фиксы (`finding_key`) и replay'ит старый эксплойт. Два пробела:

| Фича | Статус |
|------|--------|
| Dependency-level PoF (VeriPatch): переустановка зависимости → перескан (CVE исчез) → тесты в sandbox | ✅ |
| Post-fix adversarial re-attack (Shinobi): мутировать/генерировать новые payload'ы, не только replay старого | ✅ |

✅ Реализовано (22.08.2026): `gsc_poc_mutator.py` (детерминированные мутации payload'ов:
url/double-encode, html-entities, case-swap, whitespace/`/**/`, альтернативные payload'ы) +
интеграция в `gsc_proofoffix.py` (`_adversarial_recheck` — если мутация проходит после фикса →
`exploited_after=True`, фикс поверхностный). Dependency-PoF: `gsc_verify_fix.verify_dependency_fix()`
(перескан OSV.dev → CVE исчез → тесты).

⚠️ Оба детерминированные (без LLM). `mutation_tracker` расширить с паттернов на PoC-payload'ы;
dependency-PoF — в `gsc_verify_fix.py`/`proofoffix.py` добавить SCA-ветку (не только SAST finding_key).

## 🟡 S1 — Multi-tenant PostgreSQL + packages split (архитектурный долг)

**Источник:** A-01/A-04/A-05 (audit) — «несколько контуров, in-process workers, SQLite».
→ трек 0.5 packages split + S1 PostgreSQL.

### ✅ Закрыто (14.08.2026)

| Шаг | Что | Где |
|-----|-----|-----|
| 1.1 | Контракт backend-абстракции зафиксирован 12 тестами | `gsc_db_backend.py` + `tests/test_db_backend.py` |
| 1.2 | Backend-фабрика в server.py (`get_backend()`: SQLite default / PgBackend при `GSC_DATABASE_URL`) | `server.py` |
| 1.3 | Миграция SQLite→PG + docker postgres | `scripts/gsc_pg_migrate.py`, `cloud/schema_runtime.sql`, `docker-compose.yml` |
| **Трек 2** | Workers out-of-process: `gsc-worker` контейнер (`gsc_scan_worker.py --loop` поллит `scan_jobs`, без Redis); server при `GSC_WORKER_DAEMON=1` только enqueue; `workers.py` (gsc_jobs enterprise-schema) помечен legacy для runtime | `gsc_cloud/gsc_scan_worker.py`, `gsc_cloud/server.py`, `docker-compose.yml` |

Все endpoint'ы переведены с sqlite3 `conn` на backend API (`fetchone`/`query`/`insert_id`/`execute`).
`INSERT OR REPLACE`→`ON CONFLICT`, `lastrowid`→`RETURNING`, `datetime('now')`→Python timestamp,
`date()`/`date('now')`→`date_expr()`/`now_expr()`. Проверено на реальном postgres:16 (docker):
signup→stats/findings/scans/dashboard 200.

### ⬜ Осталось (не делать без реальной потребности)

| Трек | Что | Когда |
|------|-----|-------|
| **Трек 3** | ~~Packages split~~ ✅ **ЗАВЕРШЁН** (0.5.1–0.5.5: `gsc_core/`+`gsc_cli/`+`gsc_cloud/`, shim-ы; `78222dc`, `e821e62`, `b29af60`) | — |
| — | ⚠️ Redis-цепочка webhook (`scan_queue.py` → `api.py`/`scanjobs.py`) — заменить на БД-очередь `scan_jobs` для полного «без Redis» (отдельный объём, не входит в Трек 2) | при переносе PR-webhook на PG-очередь |

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
| **Proof-of-Fix** — авто-проверка фикса (замкнутый цикл) | VeriPatch/Nullify/Shinobi (отдельные звенья) |
| **Federated Self-Learning** — деактивация FP между тенантами | Никто |
| **Security Archaeology** — trace через git history | Никто |
| **Cross-repo Secrets** — отслеживание между репо | Никто |
| **Attack Chain Composer** — связывание уязвимостей в цепочки | Никто |
| **47 детекторов** (SAST+SCA+Secrets+IaC+SBOM) | Больше Semgrep Community |

---

## Методология закрытия фазы (Ф3–Ф7, 14.08.2026)

Каждая фаза закрывалась по одному рецепту — переиспользуем для следующей:

1. **Разведка.** Большинство фаз уже наполовину готовы (Ф3 `yaml_rules` regex-only, Ф4 `create_check_run` без PR-link, Ф7 `RiskForecaster`+`gsc_epss.py` не связаны). Работа — «дотянуть недостающее», не «строить с нуля».
2. **Сначала тест.** `tests/test_phases_2_6.py` фиксирует контракт фазы (имена функций, сигнатуры). Не выдумывать параллельный интерфейс.
3. **Контрактный разрыв.** `make_finding()` отдавал `file/line/snippet`, а `gsc_external.py` читает `file_path/line_number/detail` → все YAML-находки были `file_path=None`. Эмитить оба набора ключей.
4. **Smoke на реальном пути.** Реальный импорт semgrep-rules (2234 правила), живой `/dashboard` (uvicorn+signup+curl), реальный `forecast heatmap` — юнит-тест не ловит `patterns: null`/`KeyError: 'trend'`/`IsADirectoryError`.
5. **Замыкание.** Judge (с явным доменом) → commit → push → перевернуть статус фазы ⬜→🟡→🟢.
