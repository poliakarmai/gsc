# Due-Diligence v2 — Response (Manus AI, 14.08.2026)

Сверка независимого аудита (commit `f542fe6`) с текущим кодом и закрытие находок.
Аудит-файл: `GSC_DUE_DILIGENCE_v2.pdf`.

## Итог закрытия

| ID | Приоритет | Находка | Статус |
|----|-----------|---------|--------|
| GSC-001 | **P0** | PoF fail-open (rlimit host fallback) | ✅ fail-closed: `verified` только при docker/podman |
| GSC-002 | P1 | `run_tests()` заканчивается `\|\| true` | ✅ убран `\|\| true` |
| GSC-003 | P1 | corpus 4 failed (SQL/pickle/except/assert) | ✅ уже зелёный (8 passed) |
| GSC-004 | P1 | nuclei import `comment_reactions` | ✅ изолированная DB через GSCDatabase |
| GSC-005 | P1 | RLS без FORCE, нет FK/UNIQUE | ✅ FORCE + FK tenants(id) + UNIQUE(tenant_id,finding_key) |
| GSC-006 | P1 | server.py global SQLite conn | 🟡 backend-фабрика (S1 1.2); per-request `get_db()` |
| GSC-007 | P1 | open signup без invite | ✅ `GSC_INVITE_ONLY=1` → 403 |
| GSC-008 | P1 | action install `@v1.3.0` mutable tag | ✅ pin на commit SHA |
| GSC-009 | P2 | JWT_SECRET random per process | ✅ persist в `.jwt_secret` (env > файл > generate) |
| GSC-010 | P2 | divergent auth (`gsc_` vs `gsk_`) | ✅ унифицировано на `gsk_` |
| GSC-011 | P2 | detector count claim (41 vs 34) | ✅ честный None вместо silent fallback 37/41 |

## План аудита из 6 шагов — прогресс

| Шаг | Что | Статус |
|-----|-----|--------|
| 1 | Fail-closed PoF isolation | ✅ GSC-001 |
| 2 | Verifier semantics (`\|\| true`) | ✅ GSC-002 |
| 3 | Test gate в green | ✅ GSC-003 + GSC-004 (pytest 178 passed, nuclei 7/0) |
| 4 | Один cloud contour | 🟡 частично (GSC-006/007; полное объединение contour'ов — отдельный рефакторинг) |
| 5 | DB + release supply chain | 🟡 частично (GSC-005 + GSC-008; immutable image digest/SBOM — осталось) |
| 6 | Positioning / pilot contract | ⬜ осталось (переписать claim'ы, threat model) |

## Осталось (хвосты шагов 4–6 плана)

- **Шаг 4**: полное объединение server.py (SaaS MVP) и cloud/enterprise (s1–s5) —
  один onboarding, один storage backend. Это крупный рефакторинг (см. ROADMAP S1).
- **Шаг 5**: immutable image digest (Dockerfile `python:3.12-slim` без digest,
  k8s/helm `latest`), SBOM в release.
- **Шаг 6**: переписать позиционирование — «verified remediation» с disclosure
  (strength зависит от backend/тестов/DAST), threat model trusted vs hostile code.

## Проверка изменений

- `pytest tests/ -q` → 178 passed, 5 skipped
- `tests/test_nuclei_import.py` → 7 passed, 0 failed (full gate зелёный)
- `run_tests()` регрессия: намеренно падающий Makefile → `passed=False`
- signup при `GSC_INVITE_ONLY=1` → HTTP 403
- `schema_s1.sql` на postgres:16 → `relforcerowsecurity=t` (findings/verdicts/scans)
