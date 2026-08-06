# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — production security scanner.
> **Версия:** v0.28 | **Детекторов:** 29 | **Тестов:** 78/78 | **Schema:** 25 | **Файлов:** ~40
> **Статус:** SAST+DAST hybrid — blocking-standard (Phase 6: nuclei integration complete)
> **Roadmap:** [GSC_ROADMAP.md](GSC_ROADMAP.md) | **SaaS:** [GSC_SAAS_ROADMAP.md](GSC_SAAS_ROADMAP.md)

## Что это

GSC — статический анализатор безопасности с LLM-ревалидацией (DeepSeek).
25 plugin-детекторов (GS001–GS025 + GS028), PoC Auto-Generation,
Exploit Chain Composer, Temporal Mutation Tracker, Security Invariant Engine,
Blocking Engine с авто-политикой на основе вердиктов сообщества.

## Структура

```
gsc/
├── gsc.py                     ← CLI (30+ команд)
├── gsc_external.py            ← External Scanner v0.26 (ядро)
├── gsc_github_adapter.py      ← GitHub PR Adapter (priority truncation)
├── gsc_blocking.py            ← Blocking Engine (CRITICAL≥0.90, HIGH≥0.85)
├── gsc_poc_generator.py       ← PoC Auto-Generation (curl exploit)
├── gsc_chain_composer.py      ← Exploit Chain Composer (cross-file)
├── gsc_mutation_tracker.py    ← Temporal Mutation Tracker
├── gsc_invariant_engine.py    ← Security Invariant Engine (GS028)
├── gsc_ast_dataflow.py        ← Python AST taint tracking
├── gsc_revalidate.py          ← Structured LLM revalidator
├── gsc_db.py                  ← SQLite wrapper, schema 23
├── gsc_nuclei_export.py       ← Nuclei YAML export (Wave 1)
├── gsc_nuclei_import.py       ← Nuclei template import (Wave 2)
├── gsc_dast_scanner.py        ← DAST scanner via nuclei (Wave 2)
├── gsc_dast_validator.py      ← DAST validation in Proof-of-Fix (Wave 3)
├── gsc_detectors/             ← 25 детекторов (GS001–GS028)
├── calibration/               ← 17 проектов (11 clean + 6 vuln)
├── scripts/                   ← dry-run, feedback, redact, metrics
├── .github/workflows/         ← 5 CI workflows
├── tests/test_nuclei_export.py
├── tests/test_nuclei_import.py
├── tests/test_corpus.py       ← тесты (цель: 67/67)
└── PROJECT.md GSC_APPLY_PLAN.md README.md
```

DB: `~/.hermes/state/gsc_audit.db` (SQLite, WAL, schema 25, 403K fingerprints + nuclei_templates).
Cron: self-learning (04:00 MSK), reactions collector (04:30 MSK).
API: порт 8766, x-api-key auth, эндпоинты scan/feedback/overrides/dryrun.

## Как запускать

```bash
cd ~/gsc

# Основной скан
python3 gsc_external.py scan <repo> --profile developer-review

# Diff-режим (PR)
python3 gsc_external.py scan . --mode diff --base origin/main --head HEAD

# С LLM-фичами
gsc external-scan <repo> --with-poc --with-chains --fail-on-blocking

# GitHub PR
gsc github-scan <pr-url> --post-comment --create-check

# Вердикты
gsc feedback <finding_key> --verdict tp|fp|fixed
# или в PR: /gsc fp <key> причина
# или override: /gsc override <key> причина

# Метрики
gsc metrics --rollout | --detectors
gsc rollout report
python3 tests/test_corpus.py
```

## Архитектура

```
external-scan(target, profile)
  ├── regex detectors (24) → raw findings
  ├── LLM revalidate (DeepSeek) → confirmed/likely/uncertain
  ├── PoC Generator → curl exploit for confirmed findings
  ├── Chain Composer → SQLi→RCE, SSRF→IDOR (cross-file)
  ├── Mutation Tracker → рецидивы «починенных» уязвимостей
  ├── Invariant Engine → policy-as-code, AST taint
  └── Blocking Engine → CRITICAL≥90%, HIGH≥85%, auto-policy
```

**Confidence V3:** ≥0.80 confirmed | 0.55–0.79 likely | 0.35–0.54 uncertain | <0.35 suppressed
**finding_key** = sha256(rule+file+snippet)[:12]
**chain_key** = sha256(sorted finding_keys)[:12]

### Blocking Engine (v0.25/26)

Блокировка = фаза И порог И detector eligibility И нет override/bypass:
- `blocking-critical`: CRITICAL ≥ 0.90
- `blocking-standard`: + HIGH ≥ 0.85, цепочки CRITICAL ≥ 0.90
- Детектор допускается при ≥10 вердиктов и TP-rate ≥ 70% (auto policy)
- Аварийные выходы: `/gsc override` (TTL 30д), лейбл `gsc-bypass`
- Shadow mode: решения вычисляются, но blocking=False

### Profiles

| Profile | LLM | PoC | Chains | Блокировка |
|---|---|---|---|---|
| developer-review | 20 | 5 | 5 | ≥HIGH, 80% |
| pr-gate | 10 | 3 | 3 | ≥HIGH, 80% |
| audit | 50 | 10 | 10 | ≥HIGH, 80% |
| candidate-review | 15 | 3 | 3 | CRITICAL, 85% |

## Детекторы

| Rule | Severity | Category |
|------|:--------:|----------|
| GS001 | CRITICAL | Hardcoded secrets (API keys, tokens, PAN/CVV) |
| GS002 | HIGH | World-readable sensitive files |
| GS003 | LOW | Debug prints in production |
| GS004 | HIGH | Dangerous subprocess (shell=True, eval) |
| GS005 | CRITICAL | SQL injection |
| GS007 | HIGH | BAC/IDOR (35 patterns) |
| GS008 | LOW | Dead code |
| GS009 | HIGH | Supply chain (npm/PyPI/Go) |
| GS010 | CRITICAL | Weak SSH config |
| GS011 | CRITICAL | JWT vulnerabilities |
| GS012 | HIGH | Mass Assignment |
| GS013 | HIGH | GraphQL security |
| GS014 | HIGH | Credential exposure |
| GS015 | INFO | Entry-point coverage |
| GS016 | CRITICAL | Linux priv esc (SUID, cron, sudo) |
| GS017 | CRITICAL | Weak/default passwords |
| GS018 | CRITICAL | Payment logic abuse |
| GS019 | HIGH | Auth/session weaknesses |
| GS020 | CRITICAL | XSS/HTML/SSTI injection |
| GS021 | CRITICAL | CSRF/SSRF |
| GS022 | HIGH | Open Redirect |
| GS023 | HIGH | Race Conditions (TOCTOU) |
| GS024 | — | LLM-based SQLi (pilot) |
| GS025 | HIGH | AI-Code Provenance |
| GS028 | HIGH | Security Invariant Engine |

## Production Rollout (Phase 0–5)

| Phase | Версия | Статус |
|-------|:------:|:------:|
| 0: Readiness | — | ✅ |
| 1: Dry-run CI | v0.22 | ✅ |
| 2: Warn-only comments | v0.23 | ✅ |
| 3: Feedback collection | v0.24 | ✅ |
| 4: Blocking CRITICAL | v0.25 | ✅ |
| 5: Blocking CRITICAL+HIGH | v0.26 | ✅ |

## DB Schema (version 23)

```
findings (+pattern_fingerprint, resolved_at) | feedback (+source, actor)
chains | mutation_alerts | finding_sightings | overrides
published_comments | publication_events | comment_reactions
dry_run_runs | schema_version
```
Миграции: автоматические, с backup `.bak-v0XX-*`, WAL-режим.

## Самодиагностика

При проблемах — смотри в порядке приоритета:
1. `python3 tests/test_corpus.py` — 8 базовых тестов (должны проходить)
2. `gsc doctor --github` — проверка GitHub-интеграции
3. `gsc metrics --rollout` — метрики всех фаз
4. DB: `~/.hermes/state/gsc_audit.db` — schema 23, WAL
5. Ключ: `DEEPSEEK_API_KEY` в `~/.bashrc` — без него LLM отключается, но 24 regex-детектора работают

## Cloud-инфраструктура (спроектирована, закоммичена)

```
cloud/
├── docker-compose.yml       ← Cloud 1.0: PG + Redis + API + Workers + Dashboard
├── k8s/                     ← Kubernetes: StatefulSet PG, Deployments, HPA, Ingress
├── api/                     ← FastAPI-роутеры (/api/v2)
├── db/                      ← SQL-схемы (S1–S4)
└── dashboard/               ← Next.js scaffold
```

Статус: инфраструктура закоммичена, реализация S1–S4 по [GSC_ROADMAP.md](GSC_ROADMAP.md).

## Лицензия

BSL 1.1 с Additional Use Grant (коммерческий SaaS требует лицензии).  
SPDX-заголовки в 40 файлах. Подробности: [LICENSE](LICENSE).

## Ключевые инварианты

1. **finding_key стабилен.** sha256(rule+file+snippet)[:12] — не меняется между сканами.
2. **Blocking Engine — единый источник правды.** Никакой другой код не ставит `f["blocking"] = True`.
3. **Авто-деградация.** Пустой DEEPSEEK_API_KEY → regex-only, не падает.
4. **Shadow mode только в PR-контексте.** Не ломает calibration.
5. **Каждый override оставляет аудит-след.** `publication_events` + обязательный reason.