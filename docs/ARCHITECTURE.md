# ARCHITECTURE.md — GSC

> Компоненты и поток данных. SSOT по числам (детекторы, schema) — `python3 gsc_meta.py`,
> НЕ этот файл.

## 1. Обзор

GSC — AppSec-платформа с полным циклом
`detect → prove → fix → verify → heal → predict`.

Два контура исполнения:

1. **CLI / self-hosted** (`gsc.py`, модули `gsc_*`) — локальный аудит репозитория:
   SAST (38 registry-детекторов), движки (Secrets/SCA/IaC/Invariants = 4 standalone),
   PoC-генерация, Proof-of-Fix, self-healing.
2. **Cloud/SaaS** (`server.py` + `cloud/`) — multi-tenant HTTP API поверх той же
   сканирующей машины: onboarding, очереди сканов, findings, billing.

## 2. Компоненты

```
┌─────────────┐   clone/scan    ┌──────────────────────────────┐
│  server.py  │ ──────────────► │  gsc.py (CLI scan engine)    │
│  FastAPI    │  (subprocess/   │  ├─ SAST registry (38)        │
│  SaaS MVP   │   worker)       │  ├─ движки: Secrets/SCA/IaC/  │
└─────┬───────┘                 │  │   Invariants (4)            │
      │ DB                      │  └─ PoC generator             │
      ▼                         └──────────────┬───────────────┘
  gsc_db_backend                                │
  (Sqlite/Pg)                                    ▼
      ▲                              ┌──────────────────────────┐
      │                              │  gsc_pof_sandbox.py      │
  cloud/ (S1–S4)                     │  PoC execution (isolated)│
  auth, tenancy,                     │  docker/podman container  │
  billing, worker                     └──────────────┬───────────┘
                                                     ▼
                                    gsc_verify_fix.py (PoF: tests + DAST)
```

Ключевые модули:

| Модуль | Роль |
|--------|------|
| `gsc.py` | CLI (50+ команд), entrypoint `gsc` |
| `gsc_orchestrator.py` | master orchestrator |
| `gsc_db.py` / `gsc_db_backend.py` | SQLite (schema 32, auto-migrate) / PgBackend |
| `gsc_pof_sandbox.py` | изолированное исполнение PoC (container-first, fail-closed) |
| `gsc_verify_fix.py` | Proof-of-Fix: tests + DAST, `StageOutcome` NOT_RUN/PASSED/FAILED |
| `gsc_scan_worker.py` | out-of-process scan worker (очередь scan_jobs) |
| `server.py` | SaaS MVP: signup, scan queue, findings, stats, dashboard |
| `cloud/` | enterprise контур S1–S4 (auth, tenancy, billing, SSO, marketplace) |

## 3. Поток данных

**Аудит (CLI):**
```
repo → gsc.py scan → детекторы → findings → (опц.) PoC-генерация → sandbox → evidence → findings (DB)
```

**Cloud scan (SaaS):**
```
POST /api/v2/scan (API key)
  → quota check (atomic UPDATE ... WHERE scans_used < limit)
  → INSERT scan_jobs (status='queued')
  → gsc_scan_worker.py (out-of-process): clone → gsc.py scan → INSERT findings (tenant-scoped)
  → status='done', findings_count
```

**Proof-of-Fix:**
```
finding → fix → gsc_verify_fix:
  Stage 1: rescan (finding still present?)
  Stage 2: tests (PASSED/FAILED/NOT_RUN)
  Stage 3: DAST (nuclei) (PASSED/FAILED/NOT_RUN)
  → _ready_for_pr (нужен positive signal: tests PASSED OR dast PASSED)
```

## 4. Хранение

- **Единый backend-контур** (`gsc_db_backend`): `SqliteBackend` (local-only) и
  `PgBackend` (production) — один интерфейс (`query/fetchone/execute/executescript/
  insert_id/close`), переключается через `GSC_DATABASE_URL`. `server.py` (SQLite
  local) и `cloud/` (PG prod) — один cloud contour на уровне storage.
- **SQLite** (default, dev): `~/.hermes/state/gsc_audit.db` (CLI) и
  `~/.gsc/gsc_cloud.db` (server). WAL, schema 32, auto-migrate v23→v32.
- **PostgreSQL** (production): `GSC_DATABASE_URL`, enterprise схема `cloud/schema_s1.sql`
  (RLS FORCE, FK, composite UNIQUE). Миграция SQLite→PG: `scripts/gsc_pg_migrate.py`.

## 5. Изоляция (security boundary)

`gsc_pof_sandbox.py` запускает hostile PoC:

- **container (docker/podman)** — `--network none`, read-only rootfs, `--cap-drop ALL`,
  `no-new-privileges`, `--pids-limit 64`, `--memory 512m`, non-root (65534), tmpfs /tmp.
- **rlimit** — только как fallback для dev; **не является** security boundary.

Web PoC (TARGET_URL) — container-first: target server + curl PoC в одном контейнере.
`verified=True` только при docker/podman (fail-closed). Детали: `THREAT_MODEL.md`.

## 6. Масштабирование

- HTTP worker (server.py) — stateless per-request DB (`get_db()`), no global conn.
- Scan worker (`gsc_scan_worker.py`) — out-of-process, `--loop` поллит очередь.
- Production: PostgreSQL + отдельный worker deployment (см. `k8s/base/04-worker.yaml`).

## 7. Развёртывание

`DEPLOYMENT.md` (k8s/helm/env). Single-tenant pilot: `PILOT_GUIDE.md`.
