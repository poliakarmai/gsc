# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — AppSec-платформа.
> **Числа → `python3 gsc_meta.py`** (не зафиксированы в этом файле)
> **Версия:** v1.3.0 | **Schema:** 32 | **Статус:** SAST+DAST+SCA+IaC+SBOM+SupplyChain — RELEASE
> **Сверка:** `python3 scripts/gsc_reconcile.py`

## Что это

GSC — самообучающаяся AppSec-платформа: 42 детектора (38 registry + 4 движка: Secrets/SCA/IaC/Invariants),
SQLite, полный цикл `detect → prove → fix → verify → heal → predict`.

**Эксклюзивы:** PoC Auto-Generation, Proof-of-Fix, Self-Healing CI, Security Archaeology,
Predictive Forecasting, Federated Learning.

**P0 (поверхность):** SCA (OSV.dev), GS029 Secrets, Compliance mapping (CWE/OWASP/PCI).
**P1 (доверие):** EPSS exploitability, OWASP Benchmark, Federated Self-Learning.

## Структура (packages split 0.5.x — core/cli/cloud)

```
gsc/
├── gsc.py                        ← CLI entry (shim → gsc_cli.main:main)
├── server.py                     ← Cloud entry (shim → gsc_cloud.api)
├── gsc_meta.py                   ← SSOT: 147 модулей, 42 детектора, schema 32
├── gsc_core/                     ← движок (13): db, blocking, detectors/, invariant_engine,
│                                   compliance, sca, epss, federated, ast_dataflow, iac,
│                                   secrets_core, yaml_rules
├── gsc_cli/                      ← CLI+сканеры (51 + main.py): orchestrator, external,
│                                   github_adapter, poc_generator/deterministic/watermark,
│                                   chain_composer, exploit_refiner, attack_graph, fix_quality,
│                                   sla, mutation_tracker, proofoffix, selfhealing, archaeology,
│                                   forecast, nlpolicy, crossrepo_secrets, nuclei_*, dast_*,
│                                   sbom, spdx, revalidate, runtime_validator, noise_engine, ...
├── gsc_cloud/                    ← SaaS (39): api, api_v2, auth, billing, tenancy, sso,
│                                   user_auth, worker(s), scan_queue, scan_worker, marketplace,
│                                   federated_server, mcp_server, pr_commands, webhook, ...
├── gsc_*.py (top-level)          ← shim'ы: re-export из gsc_core/cli/cloud (sys.modules alias)
│                                   для обратной совместимости; без __main__ → alias,
│                                   с __main__ → runpy-run + alias
├── _cron_*.py                    ← cron-скрипты (collect, nvd)
├── benchmark/                    ← OWASP Benchmark + perf (benchmark_perf.py)
├── enterprise/                   ← RBAC, SSO, Audit, Multi-tenancy, Helm
├── gsc-vscode/                   ← VSCode extension (v1.0.0, Open VSX)
├── calibration/                  ← 13 проектов (9 clean + 4 vuln)
├── scripts/                      ← dry-run, feedback, audit, metrics, reconcile
├── cloud/                        ← deploy-артефакты (Dockerfile, k8s-манифесты)
├── tests/                        ← 276 тестов (60 файлов)
├── .pre-commit-hooks.yaml        ← pre-commit hook (gsc-scan)
├── .pre-commit-config.yaml       ← self-check pre-commit
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
