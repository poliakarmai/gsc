# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-07  
> **Версия:** v1.1 — AppSec Platform (P0/P1 complete)  
> **Репозиторий:** `github.com/poliakarmai/gsc`

## 1. Что это

GSC — самообучающаяся AppSec-платформа: **27 детекторов** + GS024 LLM (DeepSeek),
SQLite, полный цикл `detect → prove → fix → verify → heal → predict → learn`.

### Эксклюзивы (никто кроме GSC)
- **PoC Auto-Generation** — автогенерация эксплойта для подтверждённых находок
- **Proof-of-Fix** — автопатч + верификация re-PoC в sandbox + DAST staging
- **Self-Healing CI** — авто-PR с верифицированными фиксами
- **Security Archaeology** — кто/когда внёс уязвимость, сколько жила
- **Predictive Forecasting** — heatmap риска будущих уязвимостей
- **Federated Learning** — cross-tenant обучение без утечки кода (DP)

### Покрытие AppSec-поверхности (P0)
- **SCA (GS030)** — зависимости на CVE через OSV.dev (бесплатно)
- **Secrets (GS029)** — детектор секретов + cross-repo корреляция
- **Compliance** — CWE/OWASP/PCI-DSS в каждом finding + SARIF

### Приоритизация и доверие (P1)
- **EPSS exploitability** — risk = severity × epss × reachability
- **OWASP Benchmark** — независимая оценка точности (TPR/FPR на 2740 кейсах)
- **Blocking Engine** — блокировка только детекторами с доказанной точностью

### Инфраструктура
- Nuclei интеграция (Waves 1–3): PoC → YAML export, CVE import, DAST validation
- Production rollout Phase 0–5: ✅ (blocking-standard)
- **Schema 28**, WAL, авто-миграции с backup
- **102 теста**, 19/19 calibration, 27 детекторов

## 2. Версии

| v | Ключевая фича |
|---|--------------|
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
| v0.24 | Phase 3: Feedback collection (/gsc-команды) |
| v0.25 | Phase 4: Blocking CRITICAL + overrides/bypass/shadow |
| v0.26 | Phase 5: Blocking CRITICAL+HIGH + chain blocking + PoC-boost |
| v0.27 | Exclusive: PoF, Self-Healing, Archaeology, Forecast, NL Policy, Cross-Repo Secrets |
| v0.28 | SCA: зависимости на CVE (OSV.dev), GS030 |
| v0.29 | Compliance mapping (CWE/OWASP/PCI) + GS029 Secrets detector |
| v0.30 | Federated Self-Learning (cross-tenant, DP) |
| v0.31 | OWASP Benchmark (TPR/FPR scorecard) |
| v0.32 | EPSS exploitability (risk = severity × EPSS × reach) |

## 3. Файловая структура

```
~/gsc/
├── gsc.py                        ← CLI (40+ команд)
├── gsc_external.py               ← External Scanner v0.32
├── gsc_github_adapter.py         ← GitHub Adapter
├── gsc_revalidate.py             ← Structured revalidator
├── gsc_blocking.py               ← Blocking Engine (+ federated guard)
├── gsc_poc_generator.py          ← PoC generation (+ SUCCESS_MARKERS)
├── gsc_chain_composer.py         ← Exploit Chain Composer
├── gsc_mutation_tracker.py       ← Temporal Mutation Tracker
├── gsc_invariant_engine.py       ← Security Invariant Engine
├── gsc_ast_dataflow.py           ← Python taint tracking
├── gsc_compliance.py             ← 🆕 CWE/OWASP/PCI mapping
├── gsc_sca.py                    ← 🆕 SCA (OSV.dev)
├── gsc_epss.py                   ← 🆕 EPSS exploitability
├── gsc_federated.py              ← 🆕 Federated learning
├── gsc_proofoffix.py             ← Proof-of-Fix + DAST validator
├── gsc_selfhealing.py            ← Self-Healing CI
├── gsc_archaeology.py            ← Security Archaeology
├── gsc_forecast.py               ← Predictive Forecasting
├── gsc_nlpolicy.py               ← NL Policy + ReDoS guard
├── gsc_crossrepo_secrets.py      ← Cross-Repo Secrets
├── gsc_nuclei_export.py          ← Nuclei YAML export (Wave 1)
├── gsc_nuclei_import.py          ← Nuclei template import (Wave 2)
├── gsc_dast_scanner.py           ← DAST scanner (Wave 2)
├── gsc_dast_validator.py         ← DAST validation in PoF (Wave 3)
├── gsc_db.py                     ← SQLite wrapper, миграции до schema 28
├── gsc_detectors/                ← 27 детекторов
│   ├── gs025_ai_provenance.py
│   ├── gs028_invariants.py
│   ├── gs029_secrets.py          ← 🆕
│   └── gs030_sca.py              ← 🆕
├── benchmark/                    ← 🆕 OWASP Benchmark
│   ├── cwe_map.py, adapter.py, runner.py, scorer.py, scorecard.py
├── calibration/                  ← 19 проектов (11 clean + 8 vuln)
├── scripts/                      ← dry-run, feedback, redact, metrics...
├── cloud/                        ← SaaS-инфраструктура (S1–S4)
│   └── federated_server.py       ← Aggregation server
├── tests/                        ← 102 теста
└── PROJECT.md, AGENTS.md, README.md, LICENSE

DB: ~/.hermes/state/gsc_audit.db (SQLite, WAL, schema 28)
```

## 4. Команды

```bash
# Scan
gsc external-scan <target> --profile <p> [--mode diff] [--with-poc --with-chains]

# SCA / EPSS / Compliance (P0)
gsc sca --repo .                          # зависимости на CVE
gsc epss --cve CVE-2021-44228            # lookup EPSS  
gsc epss --enrich-report scan.json -o enriched.json

# Federated / Benchmark (P1)
gsc federated status|submit|fetch|weights --rule GS005
gsc benchmark owasp --benchmark-path ./OWASPBenchmark --expected-csv ./expected.csv -o scorecard

# Exclusive features (v0.27)
gsc pof generate|batch <key> [--create-pr]
gsc archaeology trace|report <key> --repo .
gsc forecast predict|heatmap --repo .
gsc policy add|list|test "natural language rule"
gsc secrets correlate|status|report

# Nuclei (Waves 1–3)
gsc export-nuclei scan.json -o templates/
gsc import-nuclei nuclei-templates/cves/
gsc scan-dast https://staging.example.com --severity critical

# Core
gsc poc list|show | gsc chains list|show | gsc mutations list|show|stats
gsc invariants check|list | gsc feedback <key> --verdict tp|fp|fixed
gsc metrics --rollout|--detectors | gsc rollout report
gsc calibration run --fail-on-regression
python3 tests/test_corpus.py             # 102/102
```

## 5. Profiles

| Profile | LLM | PoC | Chains | Блокировка |
|---|---|---|---|---|
| developer-review | 20 | 5 | 5 | ≥HIGH, 80% |
| pr-gate | 10 | 3 | 3 | ≥HIGH, 80% |
| audit | 50 | 10 | 10 | ≥HIGH, 80% |
| candidate-review | 15 | 3 | 3 | CRITICAL, 85% |

`rollout_phase`: `blocking-standard` (Phase 5)

## 6. Blocking Engine

Блокировка = фаза И порог И detector eligibility И нет override/bypass
И правило не деактивировано (локально `auto-deactivate` или federated).

- `blocking-critical`: CRITICAL ≥ 0.90
- `blocking-standard`: + HIGH ≥ 0.85; цепочки CRITICAL ≥ 0.90
- Детектор допускается при ≥10 вердиктов и TP-rate ≥ 70%
- Federated: глобально деактивированные правила (TP<30% при ≥30 вердиктах) не блокируют

## 7. Confidence V3 + Risk Scoring

```
≥0.80 confirmed | 0.55–0.79 likely | 0.35–0.54 uncertain | <0.35 suppressed
finding_key = sha256(rule+file+snippet)[:12]
chain_key = sha256(sorted finding_keys)[:12]
```
SCA risk (v0.32): `risk = severity_weight × EPSS × reachability`  
Активно эксплуатируемые CVE (epss≥0.7 или percentile≥0.99) → confidence-буст.

## 8. DB Schema (version 28)

```
findings (+pattern_fingerprint, resolved_at) | feedback (+source, actor)
chains | mutation_alerts | finding_sightings | overrides
published_comments | publication_events | comment_reactions
dry_run_runs | sca_cache | federated_global_weights
federated_deactivated | federated_log | epss_cache
secret_fingerprints | secret_sightings | nuclei_templates
dast_findings | schema_version
```

### Таблица миграций (единый консолидированный порядок)

| Schema | Модуль | Таблицы |
|:---:|---|---|
| 23 | v1.0 base | findings, feedback, chains, mutation_alerts, overrides... |
| **24** | Cross-Repo Secrets | secret_fingerprints, secret_sightings |
| **25** | Nuclei (Waves 1-3) | nuclei_templates, dast_findings |
| **26** | SCA (v0.28) | sca_cache |
| **27** | Federated (v0.30) | federated_global_weights, federated_deactivated, federated_log |
| **28** | EPSS (v0.32) | epss_cache |

Миграции: автоматические, backup `.bak-v0XX-*`, WAL.

## 9. Self-Learning Engine

- 04:00 MSK: scan → LLM revalidate → auto-deactivate (<30% TP at ≥10 verdicts)
- 04:00 MSK: federated submit (DP-noised TP/FP) + fetch (global weights)
- 04:30 MSK: сбор реакций на комментарии

Federated privacy: передаются только `{tenant_hash, rule_id, tp, fp}`.
Никогда не передаются код, сниппеты, пути, finding_key.

## 10. Calibration: 19/19 ✅

11 clean + 8 vuln: sqli-demo, ai-generated-demo (GS025), vuln-chain-demo,
vuln-invariant-demo (GS028), sca-vuln-demo (GS030), secrets-demo (GS029)...

## 11. Дорожная карта

| Фаза | Статус |
|---|---|
| CLI, CI/CD, Self-learning, v0.11–v0.16 | ✅ |
| v0.17–v0.21: уникальные фичи + stabilization | ✅ |
| Production rollout Phase 0–5 | ✅ |
| v0.27: эксклюзивный цикл (PoF, Self-Healing...) | ✅ |
| P0: SCA + Compliance + Secrets | ✅ |
| P1: Federated + Benchmark + EPSS | ✅ |
| VSCode extension / Marketplace | 🔜 |
| SaaS Cloud (S1–S4) | 📋 спроектировано |
| Enterprise (Helm, SSO) | 📋 |
| P2: Trend-дашборд, SBOM, IaC, контейнеры | 📋 |

## 12. Тестовая матрица

| Модуль | Тесты | Итого |
|---|---|---|
| v1.0 core | 67 | 67 |
| SCA (v0.28) | +7 | 74 |
| Compliance + Secrets (v0.29) | +7 | 81 |
| Federated (v0.30) | +7 | 88 |
| OWASP Benchmark (v0.31) | +7 | 95 |
| EPSS (v0.32) | +7 | **102** |

## 13. Ключевые инварианты

1. **finding_key стабилен.** sha256(rule+file+snippet)[:12] — не меняется между сканами.
2. **Blocking Engine — единый источник правды.** Никакой другой код не ставит `f["blocking"] = True`.
3. **Авто-деградация.** Пустой DEEPSEEK_API_KEY → regex-only, не падает.
4. **Shadow mode только в PR-контексте.** Не ломает calibration.
5. **Каждый override оставляет аудит-след.** `publication_events` + обязательный reason.
6. **Privacy-first Federated.** Export only: `{tenant_hash, rule_id, tp, fp}` + DP noise.
7. **Redaction.** Значения секретов не хранятся и не выводятся — только fingerprint.
