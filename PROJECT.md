# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы
> **Автор:** Море (Hermes orchestrator, профиль `default`)
> **Дата:** 2026-08-05
> **Версия:** v1.0 — Rollout Complete & Enterprise Track
> **Репозиторий:** `github.com/poliakarmai/gsc`

## 1. Что это

GSC — самообучающийся статический анализатор безопасности:
25 plugin-детекторов + GS024 LLM (DeepSeek), SQLite, замкнутая петля
self-learning. Помимо классического SAST:

- **PoC Auto-Generation** — автогенерация эксплойта для подтверждённых находок
- **AI-Code Provenance (GS025)** — небезопасные дефолты AI-сгенерированного кода
- **Exploit Chain Composer** — композиция находок в цепочки атак (в т.ч. cross-file)
- **Temporal Mutation Tracker** — рецидивы и мутации «починенных» уязвимостей
- **Security Invariant Engine (GS028)** — policy-as-code инварианты, AST taint tracking
- **Blocking Engine** — блокировка только детекторами с доказанной точностью

Production rollout Phase 0–5: ✅ завершён (blocking-standard).

## 2. Версии

| v | Ключевая фича |
|---|---|
| v0.11 | External Scanner MVP |
| v0.12 | Profiles, V3 scoring, policy-as-code, report UX |
| v0.13 | PR Gate: diff mode, fingerprinting, exit codes |
| v0.14 | GitHub PR Adapter + Calibration CI |
| v0.15 | Real GitHub API, fork safe mode, redaction audit |
| v0.16 | finding_key, rollout_phase, feedback loop, REST API |
| v0.17 | PoC Auto-Generation + GS025 AI-Code Provenance |
| v0.18 | Exploit Chain Composer + chains feedback |
| v0.19 | Temporal Mutation Tracker + auto-resolve |
| v0.20 | Security Invariant Engine + GS028 |
| v0.21 | Stabilization: AST taint, cross-file chains, hard calibration |
| v0.22 | Phase 1: Dry-run CI |
| v0.23 | Phase 2: Warn-only comments |
| v0.24 | Phase 3: Feedback collection (/gsc-команды в PR) |
| v0.25 | Phase 4: Blocking CRITICAL + overrides/bypass/shadow |
| v0.26 | Phase 5: Blocking CRITICAL+HIGH + chain blocking + PoC-boost |

## 3. Файловая структура

```
~/gsc/
 ├── gsc.py                        ← CLI (30+ команд)
 ├── gsc_external.py               ← External Scanner v0.26
 ├── gsc_github_adapter.py         ← GitHub Adapter (priority truncation)
 ├── gsc_revalidate.py             ← Structured revalidator
 ├── gsc_blocking.py               ← v0.25/26 Blocking Engine
 ├── gsc_poc_generator.py          ← v0.17 PoC generation
 ├── gsc_chain_composer.py         ← v0.18/v0.21 chains
 ├── gsc_mutation_tracker.py       ← v0.19 mutations
 ├── gsc_invariant_engine.py       ← v0.20 invariants
 ├── gsc_ast_dataflow.py           ← v0.21 Python taint tracking
 ├── gsc_db.py                     ← SQLite wrapper, миграции до schema 23
 ├── gsc_detectors/                ← 25 детекторов + GS024 LLM
 │   ├── gs025_ai_provenance.py    ← v0.17
 │   └── gs028_invariants.py       ← v0.20
 ├── calibration/                  ← 17 проектов (11 clean + 6 vuln)
 ├── scripts/
 │   ├── gsc_calibration.py        ← hard chain assertion 2/3
 │   ├── gsc_backfill_fingerprints.py
 │   ├── gsc_dryrun_summary.py gsc_redact_report.py
 │   ├── gsc_pr_feedback.py        ← парсер /gsc-команд
 │   ├── gsc_report_dryrun.py gsc_rollout_metrics.py
 │   └── gsc_self_learn.py gsc_reactions.py ...
 ├── .github/workflows/
 │   ├── gsc-internal-pr.yml       ← blocking-standard, fail-on-blocking
 │   ├── gsc-fork-safe.yml         ← regex-only
 │   ├── gsc-calibration.yml       ← 17/17 nightly
 │   ├── gsc-dry-run.yml           ← Phase 1
 │   └── gsc-feedback.yml          ← /gsc-команды (injection-safe)
 ├── tests/test_corpus.py          ← 67/67
 └── PROJECT.md AGENTS.md README.md LICENSE
```

```
~/.hermes/scripts/gsc_self_learn.py  ← 04:00, 50 LLM/день
~/.hermes/scripts/gsc_reactions.py   ← 04:30, сбор реакций
~/.hermes/state/gsc_audit.db         ← SQLite, schema 23
```

## 4. Команды

```bash
# Scan
gsc external-scan <target> --profile <p> [--mode diff --base X --head HEAD]
gsc external-scan ... --with-poc --with-chains [--dry-run] [--bypass]

# Feature results
gsc poc list|show <finding_key> --report scan.json
gsc chains list|show <chain_key> --report scan.json
gsc mutations list|show <finding_key>|stats [--days 30]
gsc invariants check|list [--repo .]

# GitHub
gsc doctor --github
gsc github-scan <pr-url> --post-comment --create-check --fail-on-blocking

# Feedback (key = finding_key or chain_key)
gsc feedback <key> --verdict tp|fp|fixed --reason "..."
# or in PR: /gsc fp <key> reason | /gsc override <key> reason

# Metrics and reports
gsc metrics --rollout | --detectors
gsc rollout report                 ← итог Phase 0–5
gsc calibration run --fail-on-regression
python3 tests/test_corpus.py       ← 67/67

# REST API (port 8766, auth x-api-key)
# POST /api/v1/scan  POST /api/v1/feedback  POST /api/v1/overrides
# POST /api/v1/dryrun  GET /api/v1/chains  GET /api/v1/feedback/stats
```

## 5. Profiles + rollout_phase

| Profile | LLM | PoC | Chains | Blocking |
|---|---|---|---|---|
| developer-review | 20 | 5 | 5 | >=HIGH, 80% |
| pr-gate | 10 | 3 | 3 | >=HIGH, 80% |
| audit | 50 | 10 | 10 | >=HIGH, 80% |
| candidate-review | 15 | 3 | 3 | CRITICAL, 85% |

```yaml
# .gsc-audit.yml
rollout_phase: blocking-standard   # текущая (Phase 5)
blocking:
  shadow: false          # теневой режим для новых правил
  poc_boost: true        # +0.05 к effective confidence при валидном PoC
  bypass_label: gsc-bypass
  invariants_enforce: false
  policy: {mode: auto, min_verdicts: 10, min_tp_rate: 0.70}
```

## 6. Blocking Engine (v0.25/26)

Блокировка = фаза И порог И detector eligibility И нет override/bypass:

- **blocking-critical**: CRITICAL >= 0.90
- **blocking-standard**: + HIGH >= 0.85; цепочки CRITICAL >= 0.90
- Детектор допускается при >=10 вердиктов и TP-rate >= 70% (auto policy)
- Аварийные выходы: `/gsc override` (точечный, reason обязателен, TTL 30д),
  лейбл `gsc-bypass` (аудит); всё видно ревьюерам в комментарии

## 7. Confidence V3

```
>=0.80 confirmed | 0.55–0.79 likely | 0.35–0.54 uncertain | <0.35 suppressed
```
`finding_key = sha256(rule+file+snippet)[:12]`
`chain_key = sha256(sorted finding_keys)[:12]`

## 8. CI Workflows

| Workflow | Trigger | Action |
|---|---|---|
| gsc-internal-pr.yml | same-repo PR | blocking-standard + comment + check |
| gsc-fork-safe.yml | fork PR | regex-only, no repo invariants |
| gsc-calibration.yml | paths + nightly | 17/17, hard chains 2/3 |
| gsc-dry-run.yml | all PRs | read-only dry-run + artifacts |
| gsc-feedback.yml | issue_comment | /gsc commands (injection-safe) |

## 9. Calibration: 17/17 ✅

11 clean + 6 vuln: sqli-demo, ai-generated-demo (GS025), vuln-chain-demo
(chain CRITICAL), vuln-invariant-demo (GS028) and others.
Chain assertion: hard, retry 2 of 3, temperature 0.

## 10. DB Schema (version 23)

```
findings (+pattern_fingerprint, resolved_at) | feedback (+source, actor)
chains | mutation_alerts | finding_sightings | overrides
published_comments | publication_events | comment_reactions
dry_run_runs | schema_version
```

Миграции: автоматические, с backup `.bak-v0XX-*`, WAL.

## 11. Self-Learning Engine v2

04:00 MSK: 5 projects → scan → LLM revalidate (50/day) → update stats
→ auto-deactivate (<30% TP at >=10 verdicts, detectors and chains).
04:30: collect comment reactions (counts only, privacy).

## 12. Production Rollout — COMPLETE

| Phase | Status |
|---|---|
| Phase 0: Readiness | ✅ |
| Phase 1: Dry-run CI | ✅ |
| Phase 2: Warn-only | ✅ |
| Phase 3: Feedback | ✅ |
| Phase 4: Blocking CRITICAL | ✅ |
| Phase 5: Blocking std | ✅ |

Итог: `gsc rollout report`. Тесты 67/67, calibration 17/17, schema 23.

## 13. Дорожная карта

| Фаза | Статус |
|---|---|
| CLI, CI/CD, Self-learning, GS024, v0.11–v0.16 | ✅ |
| v0.17–v0.21: уникальные фичи + stabilization | ✅ |
| Production rollout Phase 0–5 | ✅ |
| VSCode extension / Marketplace | 🔜 v0.27 |
| Enterprise (Helm, SSO) | 📋 |
| Cross-repo корреляция секретов | 📋 |
