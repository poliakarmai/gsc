# GSC S1 — Multi-tenant фундамент (v0.27)

> Граница этапа: пайплайн сканирования + изоляция + metering. Глубокие подсистемы → S2.

Входное состояние: v0.26, 67/67 тестов, schema 23 (SQLite). Внутренний контур не трогаем.

## Архитектурный принцип

```
Внутренний контур (неизменный):     GSC Cloud (S1, новое):
  API v1 (8766, sync)                 /api/v2/* (async)
  SQLite                              PostgreSQL + RLS
  workflows v0.22–v0.26               Redis → worker (CLI subprocess)
```

Ядро сканера не меняется — worker вызывает его как subprocess.

## Блоки S1

| Блок | Файл | Суть |
|---|---|---|
| 0 | — | Состав + принцип совместимости |
| 1 | `Dockerfile` | Образ: python:3.11-slim, non-root, GSC_DB_PATH эфемерный |
| 2 | `gsc_db_backend.py` | SqliteBackend + PgBackend, конвертер ?→%s с учётом кавычек |
| 3 | `cloud/schema_s1.sql` | tenants, api_keys, repos, scans, findings, verdicts, usage + RLS |
| 4 | `cloud/auth.py` | API-ключи: sha256, prefix lookup, hmac.compare_digest |
| 5 | `cloud/queue.py`, `worker.py` | Redis-очередь, SSRF-защита (только github.com), timeout=900 |
| 6 | `cloud/api.py` | /api/v2/* (отдельно от v1), 402 по квоте до enqueue |
| 7 | `cloud/store.py` | check_quota + meter + usage в отчёте сканера |
| 8 | `tests/test_cloud_s1.py` | +7 тестов (74/74): изоляция, SSRF, квоты, RLS |
| 9 | `cloud/docker-compose.yml` | postgres + redis + api + 2 workers |

## Найденные баги (7 шт.)

1. Наивный replace ?→%s ломал литералы в кавычках → конвертер с учётом кавычек
2. API-ключи открытым текстом → sha256, raw разово
3. Timing-сигнал при проверке → prefix + hmac.compare_digest
4. SSRF: произвольный target → allowlist github.com
5. Exit 1 (blocking) = ошибка → 0/1 = успех
6. Async v1 ломала контур → отдельное /api/v2
7. RLS под superuser молча отключён → роль gsc_app + FORCE RLS

## Гейт S1

- 74/74 тестов (PG-изоляция) · Round-trip 202→done · Cross-tenant 404 · Квота 402 · SSRF блок · 17/17 calibration · 0 секретов в образе

См. полный документ: [[inbox/gsc-s1-implementation-2026-08-06]]
