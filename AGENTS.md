# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — AppSec-платформа.
> **Числа → `python3 gsc_meta.py`** (не зафиксированы в этом файле)
> **Версия:** v1.3.0 | **Schema:** 32 | **Статус:** SAST+DAST+SCA+IaC+SBOM+SupplyChain — RELEASE
> **Сверка:** `python3 scripts/gsc_reconcile.py`

## Что это

GSC — самообучающаяся AppSec-платформа: 41 детектор (37 registry + 4 движка: Secrets/SCA/IaC/Invariants),
SQLite, полный цикл `detect → prove → fix → verify → heal → predict`.

**Эксклюзивы:** PoC Auto-Generation, Proof-of-Fix, Self-Healing CI, Security Archaeology,
Predictive Forecasting, Federated Learning.

**P0 (поверхность):** SCA (OSV.dev), GS029 Secrets, Compliance mapping (CWE/OWASP/PCI).
**P1 (доверие):** EPSS exploitability, OWASP Benchmark, Federated Self-Learning.

## Структура v1.0

```
gsc/
├── gsc.py                        ← CLI (50+ команд)
├── gsc_orchestrator.py           ← Master orchestrator (v0.39)
├── gsc_external.py               ← External Scanner
├── gsc_github_adapter.py         ← GitHub PR Adapter
├── gsc_blocking.py               ← Blocking Engine (+ federated guard)
├── gsc_poc_generator.py          ← PoC + SUCCESS_MARKERS
├── gsc_poc_deterministic.py      ← Deterministic PoC (curl/bash fmt)
├── gsc_supply_chain_chains.py    ← Supply-Chain Chain Composer (code flaw × CVE)
├── gsc_exploit_refiner.py        ← Exploit Refinement Loop (feedback-driven PoC)
├── gsc_chain_composer.py         ← Exploit Chain Composer
├── gsc_attack_graph.py           ← 🆕 Attack-path graph (Mermaid)
├── gsc_fix_quality.py            ← 🆕 Fix quality scoring
├── gsc_sla.py                    ← 🆕 MTTFV SLA (time-to-verified-fix)
├── gsc_mutation_tracker.py       ← Temporal Mutation Tracker
├── gsc_invariant_engine.py       ← Security Invariant Engine
├── gsc_ast_dataflow.py           ← Python taint tracking
├── gsc_revalidate.py             ← Structured revalidator
├── gsc_db.py                     ← SQLite, schema 32, auto-migrate
├── gsc_compliance.py             ← 🆕 CWE/OWASP/PCI mapping
├── gsc_sca.py                    ← 🆕 SCA via OSV.dev
├── gsc_epss.py                   ← 🆕 EPSS exploitability
├── gsc_federated.py              ← 🆕 Federated learning (DP)
├── gsc_proofoffix.py             ← Proof-of-Fix + DAST validation
├── gsc_selfhealing.py            ← Self-Healing CI
├── gsc_archaeology.py            ← Security Archaeology
├── gsc_forecast.py               ← Predictive Forecasting
├── gsc_nlpolicy.py               ← NL Policy + ReDoS guard
├── gsc_crossrepo_secrets.py      ← Cross-Repo Secrets + FP fix
├── gsc_nuclei_export.py          ← Nuclei YAML export (Wave 1)
├── gsc_nuclei_import.py          ← Nuclei import (Wave 2)
├── gsc_dast_scanner.py           ← DAST scanner (Wave 2)
├── gsc_dast_validator.py         ← DAST in Proof-of-Fix (Wave 3)
├── gsc_sbom.py                   ← SBOM CycloneDX + VEX
├── gsc_spdx.py                   ← SPDX 2.3 + signing
├── gsc_iac.py                    ← IaC misconfigurations
├── gsc_detectors/                ← 41 детектор (37 registry + 4 движка)
├── benchmark/                    ← 🆕 OWASP Benchmark
├── enterprise/                   ← RBAC, SSO, Audit, Multi-tenancy, Helm
├── gsc-vscode/                   ← VSCode extension (v1.0.0, Open VSX)
├── calibration/                  ← 19 проектов (11 clean + 8 vuln)
├── scripts/                      ← dry-run, feedback, audit, metrics
├── cloud/                        ← SaaS S1–S4 (auth, billing, tenancy, SSO, marketplace, worker, federated_server)
├── tests/                        ← 230 тестов (55 файлов)
└── PROJECT.md AGENTS.md README.md
```

DB: `~/.hermes/state/gsc_audit.db` (SQLite, WAL, schema 32)

## Precision (август 2026)

Первый замер на 10 реальных проектах (160–132K ⭐):
- **2 695 находок** (129 CRITICAL, 244 HIGH)
- **Precision CRITICAL: ~8–12%** (до фикса GS001 extractor)
- Основной шум: GS001 на extractor/конфигах, тестовые секреты
- Подробнее: `benchmark/PRECISION_REPORT.md`

## Быстрый старт

```bash
cd ~/gsc

# Аудит (ground truth)
python3 scripts/gsc_audit_groundtruth.py

# Тесты
python3 tests/test_corpus.py           # базовые
python3 tests/test_exclusive_*.py      # v0.27
python3 tests/test_compliance_audit.py # CWE
python3 tests/test_schema_integrity.py # schema

# Скан
python3 gsc.py external-scan <repo> --profile audit --with-poc --with-chains

# P0/P1
python3 gsc.py sca --repo .            # SCA
python3 gsc.py epss --cve CVE-2021-44228
python3 gsc.py federated status
python3 gsc.py benchmark owasp --benchmark-path ./OWASPBenchmark --expected-csv ...

# Эксклюзивы
python3 gsc.py pof generate|batch <key> [--create-pr]
python3 gsc.py attack-graph --scan scan.json --out attack_paths.md   # Mermaid-граф цепочек
python3 gsc.py fix-quality --evidence fix.json                       # качество патча
python3 gsc.py sla --days 90 --by category                           # MTTFV SLA
python3 gsc.py archaeology trace <key> --repo .
python3 gsc.py forecast heatmap --repo .
python3 gsc.py policy add "no secrets in logs"
```

## DB Schema (v32)

Таблицы: findings, feedback, chains, mutation_alerts, overrides, secret_fingerprints,
secret_sightings, nuclei_templates, dast_findings, sca_cache, federated_global_weights,
federated_deactivated, federated_log, epss_cache, schema_version... (31 таблица)

Миграции: v23→v24→v25→v26→v27→v28→v29→v30→v31→v32, авто, backup, WAL, идемпотентно.

## Self-Learning

04:00 MSK: scan → LLM revalidate → auto-deactivate (<30% TP at ≥10 verdicts)
04:00 MSK: federated submit (DP-noised) + fetch (global weights)

## Ключевые инварианты

1. finding_key = sha256(rule+file+snippet)[:12] — стабилен
2. Blocking Engine — единый источник правды для блокировки
3. Авто-деградация: нет DEEPSEEK_API_KEY → regex-only
4. Override оставляет audit-trail в publication_events
5. Privacy-first federated: только {tenant_hash, rule_id, tp, fp} + DP
6. Redaction: значения секретов не хранятся, только fingerprint
