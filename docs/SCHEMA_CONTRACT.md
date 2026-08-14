# GSC Schema Contract — data planes и план унификации (GSC-010)

> Статус: **задокументированный architectural debt**. Полная унификация — отдельный
> проект (migration + adapter layer + contract tests), не быстрый фикс.
> Этот документ фиксирует drift и каноническую схему, чтобы новые consumers
> не добавляли новых расхождений.

## 1. Проблема

GSC содержит несколько независимых data planes с разными storage и разными
именами полей одного и того же finding. Для покупателя это риск неверной
аналитики, дедупликации и audit trail.

| Контур | Storage | Finding identity | Поля severity | Поля path | Tenant |
|---|---|---|---|---|---|
| Core/CLI (`gsc_db.py`) | SQLite `~/.hermes/state/gsc_audit.db` | `finding_key`, `project` | `category` | `file_path`, `line_number` | ❌ нет |
| Legacy API (`gsc_api.py`) | SQLite + `SCANS_DIR/*.json` | `finding_key` | `category` | `file_path` | ❌ (loopback single-tenant) |
| Cloud API (`schema_s1.sql`, `store.py`) | PostgreSQL + RLS | `finding_key`, `scan_id`, `tenant_id` | `severity` | `file`, `line` | ✅ `tenant_id` |
| Agent (`agent_api.py`) | PostgreSQL + Redis | `tenant/agent/finding` keys | — | — | ✅ session→tenant |
| PoF (`gsc_pof_sandbox.py`) | tempdir/venv | `finding/file/poc` | — | — | ❌ not tenant-aware |

## 2. Каноническая схема (целевая)

Единый `Finding` record для ВСЕХ контуров:

```
finding_key   TEXT   — sha256(rule+file+snippet)[:12] (стабилен)
rule_id       TEXT   — GS0XX / YAML-id
severity      TEXT   — CRITICAL|HIGH|MEDIUM|LOW  (НЕ category)
title         TEXT
file          TEXT   — (НЕ file_path)
line          INT    — (НЕ line_number)
snippet       TEXT   — (НЕ detail)
confidence    REAL   — (НЕ confidence_score)
tenant_id     INT    — NULL для single-tenant self-hosted
scan_id       INT    — NULL для локального scan
```

## 3. Adapter layer (план)

1. `gsc_schema.py` — единственный module, экспортирующий канонические имена
   полей и нормализатор `normalize_finding(raw: dict) -> canonical`.
2. Все write-paths (core, legacy API, cloud, worker, export) вызывают
   `normalize_finding()` при записи и `to_canonical()` при чтении.
3. `cloud/store.py` — остаётся единственной точкой входа в PostgreSQL;
   core SQLite остаётся для self-hosted, но с тем же каноническим контрактом.
4. Migration: schema 31 → 32 добавляет `severity`/`file`/`line`/`snippet`
   (копируются из `category`/`file_path`/`line_number`/`detail`), старые
   колонки помечаются deprecated, удаляются в schema 33.

## 4. Contract tests (обязательные)

- Два tenant с одинаковым rule/file/snippet → разные `finding_key` (tenant в scope).
- `normalize_finding()` идемпотентен и обрабатывает оба набора имён полей.
- Finding, записанный через cloud, читается через core adapter с теми же полями.

## 5. Правило для новых детекторов/consumers

**Запрещено** добавлять новые имена полей findings. Использовать только
канонические из §2 через `gsc_schema.py`. Новый detector emits `make_finding()`
с `category=severity`, `title`, `file_path`, `detail` (см. `gsc_detectors/base.py`).
