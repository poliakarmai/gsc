# Аудит-фиксы GSC — отчёт (14.08.2026)

> Источник: `GSC_REVIEW_v2.pdf` (Manus AI, повторный аудит commit `c448664`).
> Все находки сверены с кодом grep'ом перед фиксом; каждый фикс закоммичен отдельно.

## P0 trust boundary — закрыт (6 находок)

| ID | Проблема | Фикс | Коммит |
|---|---|---|---|
| C-01 | MCP `verify_finding` гонял PoC на `snippet`, а не на файле → ложные SAFE | реальный файл (resolve от repo root) + `project_dir` + статусы `verified/not_reproducible/execution_error` | `6a8b7ba` |
| C-04 | Path traversal через `scan_id` | regex `^[a-f0-9]{12}$` + `resolve().is_relative_to()` + 400 на invalid | `349386b` |
| S-01 | default API key `gsc-dev-key` | fail-closed: без `GSC_API_KEY` не стартует (или `GSC_DEV_MODE=1`) | `84e62c4` |
| C-03 | 6 endpoints legacy API без auth (в т.ч. `POST feedback` — poisoning) | auth-dependency на 8 endpoints (5 write уже имели) | `a1069a9` |
| C-02 | `INSERT OR REPLACE` перепривязывал finding чужому tenant | composite `PRIMARY KEY (tenant_id, finding_key)` + миграция | `09c645c` |
| S-03 | Docker socket + хардкод GitHub secret в compose | docker.sock убран, секреты убраны | `5a021c6` |

## P1 reproducibility — закрыт (4 находки)

| ID | Проблема | Фикс | Коммит |
|---|---|---|---|
| F-01 | `~/gsc/gsc.py` hardcoded → 7 ложных падений в чистом checkout | `Path(__file__).parents[1]` (4 файла) | `c658b30` |
| A-03 | `fastmcp` не в extras → clean install падал | `mcp` extra + `fastmcp` в dev | `742c329` |
| A-02 | top-level модули не входили в wheel | 62 модуля в `py-modules` | `742c329` |
| F-06 | claim «никто не делает exploit confirmation» | назван PT Application Inspector как ближайший конкурент | `c966ad3` |

## Перепроверки (как просил)

- Каждая находка сверена с кодом до фикса (grep точных строк из PDF).
- C-04: `../etc/passwd`, `..%2F..%2Fetc` → REJECTED (валидный hex проходит).
- C-02: тест с двумя tenant + одинаковый finding_key → оба выживают.
- S-01: без ключа → RuntimeError; с `GSC_DEV_MODE=1` → OK.
- F-01: corpus-тест 8 passed, hardcoded путей = 0.
- Полный pytest — см. ниже.

## Что НЕ закрыто (требует решения)

- **S-05/S-06** (GitHub Action mutable tag + `pull-requests: write`) — pin по SHA, разделение jobs.
- **A-01/A-04/A-05** (архитектура: несколько контуров, in-process workers, SQLite) = трек 0.5 packages split + S1 PostgreSQL.
- **S-08** (signup без OAuth proof) — решение по onboarding-модели.
- **A-06** (feedback poisoning через self-learning) — rate-limit + approval + rollback.
- **F-06/F-07** (несогласованные numbers: 38 vs 25 detectors, 17/17 vs 14/14 calibration) — нужен один release manifest.

## ⚠️ Требует действия пользователя

**Отозвать GitHub OAuth App secret** — старый `GITHUB_CLIENT_SECRET` был закоммичен в
`docker-compose.yml` и теперь в git-истории. Отозови его на GitHub (Settings → OAuth Apps)
и выстави новый через env.
