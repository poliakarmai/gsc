# ROADMAP_MATURITY.md — статус дорожной карты зрелости

Сверка `GSC_ROADMAP.pdf` (базовая линия **commit f542fe6**, 14.08.2026) с текущим кодом.
Бо́льшая часть «критического пути» уже закрыта работой по due-diligence v2 + S1
(коммиты 98e20d3 → 45b37eb). Здесь — актуальное состояние и что реально осталось.

Легенда: ✅ готово · 🟡 частично · ⬜ осталось

## 3. Безопасность продукта (4/10 → 7/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 3.1 | PoF fail-closed без Docker → ERROR/NOT_RUN | ✅ | GSC-001: `verify_fix` verified только при docker/podman |
| 3.2 | Web PoC в контейнере (target+PoC в rootless container) | ✅ | `_run_web_poc_container` + `sandbox/Dockerfile` |
| 3.3 | Поле `isolation_backend` в evidence | ✅ | `SandboxResult.isolation` (docker/podman/rlimit) |
| 3.4 | Убрать `\|\| true` из run_tests | ✅ | GSC-002 |
| 3.5 | Различать NOT_RUN/PASSED/FAILED для tests и DAST | ✅ | `StageOutcome` в gsc_verify_fix |
| 3.6 | Единый auth gateway (одна политика) | ✅ | GSC-007 (`GSC_INVITE_ONLY`) + шаг 4 |
| 3.7 | Удалить dead auth helpers | ✅ | GSC-010: `gsk_` унифицирован, legacy помечен |
| 3.8 | JWT secret fail-closed (exit без JWT_SECRET, кроме --dev-mode) | ✅ | exit(1) в production, persist в dev |
| 3.9 | API key только в header (не query param) | ✅ | только Authorization/X-API-Key |
| 3.10 | Security test: PoC читает /etc/passwd, socket, write вне workspace | ✅ | `tests/test_sandbox_security.py` |
| 3.11 | Container policy (network=none, read-only, cap-drop, etc.) | ✅ | `--network`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 64`, `--memory 512m`, `--cpus 1`, user 65534, tmpfs |

## 4. Cloud/SaaS (4/10 → 7/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 4.1 | Один cloud contour (cloud/PG, server.py SQLite → local-only) | 🟡 | auth unified (шаг 4); storage всё ещё два контура |
| 4.2 | FORCE RLS на все tenant-таблицы | ✅ | GSC-005 |
| 4.3 | Отдельная app DB role | ✅ | `bootstrap_roles.sql` → `gsc_app` (LOGIN, не superuser) |
| 4.4 | FK findings.tenant_id → tenants.id, scan_id → scans.id | ✅ | GSC-005 |
| 4.5 | Composite UNIQUE (tenant_id, finding_key) | ✅ | GSC-005 |
| 4.6 | Cross-tenant integration test | ✅ | `tests/test_tenant_isolation.py` |
| 4.7 | Убрать global SQLite connection (request-scoped pool) | ✅ | request-scoped `get_db()`; global conn только startup |
| 4.8 | Worker отдельный процесс | ✅ | `gsc_scan_worker.py` out-of-process + spawn |
| 4.9 | health/readiness с проверкой DB | ✅ | `/health` + `/ready` (SELECT 1) |
| 4.10 | Migration test (fresh DB → все миграции → verify) | ✅ | `tests/test_db_migration.py` |
| 4.11 | Backup/restore drill (процедура + тест) | ✅ | `scripts/gsc_backup.py` + `tests/test_backup_restore.py` |

## 5. Packaging (7/10 → 9/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 5.1 | Убрать import-time side effects (server.py не открывает DB при import) | ✅ | lazy JWT + `init_cloud_db()` (lifespan) |
| 5.2 | Все paths через env/XDG (GSC_DATA_DIR, GSC_DB_PATH) | 🟡 | частично (GSC_DB есть) |
| 5.3 | Pin action по commit SHA | ✅ | GSC-008 |
| 5.4 | release-manifest.json (commit, wheel hash, image digest, detectors, schema, test matrix) | ✅ | `scripts/gsc_release_manifest.py` |
| 5.5 | CI job: build wheel → test install в clean venv → import → smoke | ✅ | `.github/workflows/ci.yml` (wheel job) |
| 5.6 | Dockerfile pin base image digest | ✅ | шаг 5 |
| 5.7 | SBOM (CycloneDX/SPDX) в CI | 🟡 | `scripts/gsc_release_sbom.py` есть; не в CI |
| 5.8 | CI matrix 3.10/3.11/3.12 | ✅ | `.github/workflows/ci.yml` (test matrix) |
| 5.9 | apps/ → wheel или документировать | ⬜ | |

## 6. Testing (4/10 → 8/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 6.1 | 4 corpus failures | ✅ | сейчас 8 passed |
| 6.2 | nuclei_import failure | ✅ | GSC-004 |
| 6.3 | pytest markers (unit/integration/sandbox) | ✅ | `[tool.pytest.ini_options]` |
| 6.4 | Security test suite (10 тестов: cross-tenant, sandbox escape, auth bypass) | 🟡 | tenant-тест есть; sandbox-escape/auth-bypass нет |
| 6.5 | Убрать hardcoded ~/gsc/gsc.py из corpus | ⬜ | |
| 6.6 | Coverage gate ≥60% core | ⬜ | |
| 6.7 | Skip reason policy | 🟡 | частично |
| 6.8 | CI pytest green для merge | ✅ | `.github/workflows/ci.yml` (required check) |
| 6.9 | Отделить smoke/calibration от pytest | ⬜ | |
| 6.10 | conftest.py fixtures (temp DB, workspace, mock keys, two-tenant) | ✅ | `tests/conftest.py` |

## 2. SAST-пайплайн (6/10 → 8/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 2.1 | 4 corpus failures | ✅ | |
| 2.2 | detector_contract.json | ⬜ | |
| 2.3 | Fixtures для 37+4 детекторов | ⬜ | |
| 2.4 | `gsc doctor` (registry + fixtures + coverage matrix) | ⬜ | |
| 2.5 | OWASP Benchmark / Juliet | 🟡 | benchmark/ есть; прогон не зафиксирован |
| 2.6 | Generated DETECTORS.md | ⬜ | |
| 2.7 | Убрать hardcoded standalone=4 (считать динамически) | ✅ | `_count_standalone_engines()` |

## 7. Документация (6/10 → 8/10)

| # | Задача | Статус | Примечание |
|---|--------|--------|------------|
| 7.1 | Generated README section (count/version/schema из gsc_meta) | ✅ | `scripts/gsc_generate_readme.py` |
| 7.2 | ARCHITECTURE.md | ✅ | `docs/ARCHITECTURE.md` |
| 7.3 | THREAT_MODEL.md | ✅ | `docs/THREAT_MODEL.md` |
| 7.4 | DEPLOYMENT.md | ✅ | `docs/DEPLOYMENT.md` |
| 7.5 | CHANGELOG.md (Keep a Changelog) | ✅ | `CHANGELOG.md` |
| 7.6 | Убрать unverified accuracy numbers | ✅ | README disclosure + «does NOT do» таблица |
| 7.7 | PILOT_GUIDE.md | ✅ | `docs/PILOT_GUIDE.md` |
| 7.8 | OpenAPI spec | ✅ | `docs/openapi.json` (14 endpoints) |
| 7.9 | KNOWN_LIMITATIONS.md | ✅ | `docs/KNOWN_LIMITATIONS.md` |
| 7.10 | Inline comments в критических модулях | 🟡 | частично |

## 1. Идея / Positioning (8/10 → 9/10)

| # | Задача | Статус |
|---|--------|--------|
| 1.1 | README positioning (убрать overclaims) | 🟡 |
| 1.2 | One-pager PDF | ⬜ |
| 1.3 | Demo video | ⬜ |
| 1.4 | «What GSC does NOT do» таблица | ⬜ |
| 1.5 | 3 use cases | ⬜ |

## Приоритет внедрения (что делаем дальше)

**Волна A — быстрые P1 (по 0.5–1 день, закрывают оставшийся critical path):**
3.9 (API key → header) · 3.8 (JWT fail-closed exit) · 3.5 (NOT_RUN/PASSED/FAILED) ·
2.7 (standalone динамически) · 4.9 (/ready endpoint)

**Волна B — безопасность/изоляция (1–3 дня):**
3.2 (Web PoC в контейнере) · 3.10 (security test suite) · 4.7 (request-scoped pool)

**Волна C — архитектура/упаковка (1–3 дня):**
4.8 (worker process) · 5.1 (import-time side effects) · 5.4 (release manifest) · 6.3 (markers) · 6.10 (conftest)

**Волна D — документация (0.5–2 дня каждый):**
7.3 (THREAT_MODEL.md) · 7.2 (ARCHITECTURE.md) · 7.4 (DEPLOYMENT.md) · 7.7 (PILOT_GUIDE.md) ·
7.9 (KNOWN_LIMITATIONS.md) · 7.8 (OpenAPI) · 1.4 («does NOT do»)
