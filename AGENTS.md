# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — AppSec-платформа.
> **Числа → `python3 gsc_meta.py`** (не зафиксированы в этом файле)
> **Версия:** v1.4.0 | **Schema:** 33 | **Статус:** SAST+DAST+SCA+IaC+SBOM+SupplyChain — RELEASE
> **Сверка:** `python3 scripts/gsc_reconcile.py`

## Что это

GSC — самообучающаяся AppSec-платформа: 47 детекторов (43 registry + 4 движка: Secrets/SCA/IaC/Invariants),
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
├── gsc_meta.py                   ← SSOT: 184 модулей, 47 детекторов, schema 33
├── gsc_core/                     ← движок (14): db, blocking, detectors/, invariant_engine,
│                                   compliance, sca, epss, federated, ast_dataflow, iac,
│                                   secrets_core, yaml_rules, rule_attribution
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
├── tests/                        ← 673 теста (98 файлов)
├── .pre-commit-hooks.yaml        ← pre-commit hook (gsc-scan)
├── .pre-commit-config.yaml       ← self-check pre-commit
└── PROJECT.md AGENTS.md README.md
```

DB: `~/.hermes/state/gsc_audit.db` (SQLite, WAL, schema 33)

## Precision (август 2026)

Три замера на реальных проектах:
- **Замер 1** (11.08, 10 проектов 160–132K⭐): precision CRIT ~8–12% → ~20–25% (GS001 extractor −41, YAML exec −11).
- **Замер 2** (20.08, 10 проектов ≤200⭐): CRITICAL 54 → 1, recall 4/4.
- **Замер 3** (21.08, **100 проектов**): 64 831 находка, 4 302 CRITICAL, recall 8/10. Precision CRIT ~4–5% (48/90 чистых дают ложный CRIT). Главный шум — голый eval/Function в бандлерах (TS/JS). Починен: `ba4c2d0` (БД+сид) + multi_lang.py CRITICAL→HIGH (`GS036-eval_dynamic`), Java deser `GS008`→`GS046`, taint-guard `eval_user_input` расширен. Перезамер — после чистки rule_id-нулей (GS000-LEGACY).
- Подробнее: `benchmark/PRECISION_REPORT.md`, `benchmark/PRECISION_REPORT_100.md`
- Живая сводка: `python3 scripts/gsc_metrics_dashboard.py` (Precision/FP-rate/TP-rate по детекторам из feedback + fp_log; `--json`)

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

# Threat Intel Interop (STIX 2.1 / TAXII 2.1)
python3 gsc.py export-stix scan.json -o gsc-stix-bundle.json --severity critical,high --max 50
python3 gsc.py export-taxii scan.json --collection-url https://taxii.example.com/collections/<id>/objects/ \
    --username analyst --password "$TAXII_PASS"          # или --api-key "$TAXII_API_KEY"
python3 gsc.py export-taxii scan.json --discover https://taxii.example.com/taxii2/ \
    --api-key "$TAXII_API_KEY"                            # авто-резолв коллекции (Discovery)
python3 gsc.py export-taxii scan.json --collection-url https://taxii.example.com/collections/<id>/objects/ \
    --api-key "$TAXII_API_KEY" --dry-run -o bundle.json  # build+save, без push
python3 gsc.py taxii-ingest https://taxii.example.com/collections/<id>/objects/ \
    --api-key "$TAXII_API_KEY" -o intel-findings.json     # тянуть STIX-фиды в GSC
```

## DB Schema (v33)

Таблицы: findings, feedback, fp_log, chains, feedback, overrides, secret_fingerprints,
secret_sightings, nuclei_templates, dast_findings, sca_cache, federated_global_weights,
federated_deactivated, federated_log, epss_cache, schema_version... (33 таблицы)

Миграции: v23→v24→v25→v26→v27→v28→v29→v30→v31→v32→v33, авто, backup, WAL, идемпотентно.

- **fp_log (v33)** — структурированный FP-лог: {finding_id, finding_key, pattern_id,
  rule_id, reason, comment, action_taken, source, actor, created_at}. Питает
  self-learning и noise-аналитику. Пишется в triage (FP/auto-deactivate) и federated.
- **feedback backfill (v33)** — чинит audit C-05: старые БД, у которых `feedback`
  отсутствовал (создавался только в SCHEMA_BASE при fresh install), получают его в v33.

## Self-Learning

04:00 MSK: scan → LLM revalidate → auto-deactivate (<30% TP at ≥10 verdicts)
04:00 MSK: federated submit (DP-noised) + fetch (global weights)

**Ground-Truth Trainer (0 LLM, бесплатно):** `python3 scripts/gsc_ground_truth_train.py`
— считает per-detector precision на calibration-сете (9 clean + 4 vuln) из findings БД:
`fp_clean >= 20 AND tp_vuln == 0` → FP-генератор. `--apply` деактивирует registry-паттерны
(active=0 + fp_log). Движковые (`GS037-*`) — правка severity/regex в `gsc_core/gsc_detectors/gs037_python.py`.
Детерминированная замена LLM-revalidate (источник вердикта — размеченный ground-truth, не платный LLM).

## Ключевые инварианты

1. finding_key = sha256(rule+file+snippet)[:12] — стабилен
2. Blocking Engine — единый источник правды для блокировки
3. Авто-деградация: нет DEEPSEEK_API_KEY → regex-only
4. Override оставляет audit-trail в publication_events
5. Privacy-first federated: только {tenant_hash, rule_id, tp, fp} + DP
6. Redaction: значения секретов не хранятся, только fingerprint
