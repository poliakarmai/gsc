# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — AppSec-платформа.
> **Числа → `python3 gsc_meta.py`** (не хардкод в этом файле)
> **Версия:** v1.4.0 | **Schema:** 33 | **Сверка:** `python3 scripts/gsc_reconcile.py`

## Что это

GSC — самообучающаяся AppSec-платформа: 50 детекторов (46 registry + 4 движка: Secrets/SCA/IaC/Invariants),
SQLite, полный цикл `detect → prove → fix → verify → heal → predict`.

**Эксклюзивы:** PoC Auto-Generation, Proof-of-Fix, Self-Healing CI, Security Archaeology,
Predictive Forecasting, Federated Learning.

**P0 (поверхность):** SCA (OSV.dev), Secrets, Compliance mapping (CWE/OWASP/PCI).
**P1 (доверие):** EPSS exploitability, OWASP Benchmark, Federated Self-Learning.

## Структура

```
gsc/
├── gsc.py                        ← CLI entry (shim → gsc_cli.main:main)
├── server.py                     ← Cloud entry (shim → gsc_cloud.api)
├── gsc_meta.py                   ← SSOT: 211 модулей, 50 детекторов, schema 33
├── gsc_core/                     ← движок: detectors, sca, secrets, iac, compliance,
│                                   ast_dataflow, invariant_engine, ...
├── gsc_cli/                      ← CLI + сканеры: orchestrator, external, github_adapter,
│                                   poc_generator, proofoffix, archaeology, forecast, ...
├── gsc_cloud/                    ← SaaS: api, auth, workers, webhook, mcp_server, ...
├── gsc_recon/                    ← passive recon: subdomain/tech/dns/http (bug bounty)
├── gsc_*.py (top-level)          ← shim'ы: re-export из gsc_core/cli/cloud
├── enterprise/                   ← RBAC, SSO, Audit, Multi-tenancy, Helm
├── gsc-vscode/                   ← VSCode extension
├── calibration/                  ← 13 проектов (9 clean + 4 vuln)
├── scripts/                      ← reconcile, metrics, audit, ...
├── tests/                        ← pytest
└── PROJECT.md AGENTS.md README.md
    VERIFICATION_RULES.md POF_PARSER_CONTRACT.md (контракты)
```

DB: SQLite (WAL, авто-миграции, schema 33). PostgreSQL — через `GSC_DATABASE_URL`.

## Быстрый старт

```bash
cd ~/gsc

# Тесты
python3 -m pytest tests -q

# Скан
python3 gsc.py external-scan <repo> --profile audit --with-poc --with-chains

# P0/P1
python3 gsc.py sca --repo .            # SCA
python3 gsc.py epss --cve CVE-2021-44228
python3 gsc.py federated status

# Эксклюзивы
python3 gsc.py pof generate|batch <key> [--create-pr]
python3 gsc.py archaeology trace <key> --repo .
python3 gsc.py forecast heatmap --repo .
python3 gsc.py policy add "no secrets in logs"
```

## Self-learning

Ночной цикл: скан → LLM-ревалидация → авто-деактивация шумных паттернов
(<30% TP при ≥10 вердиктах). Federated submit/fetch (DP-noised). Ground-Truth
Trainer (0 LLM) — детерминированная замена ревалидации по calibration-сети.

## Ключевые инварианты

1. finding_key = sha256(rule+file+snippet)[:12] — стабилен
2. Blocking Engine — единый источник правды для блокировки
3. Авто-деградация: нет LLM API-ключа → regex-only
4. Override оставляет audit-trail в publication_events
5. Privacy-first federated: только {tenant_hash, rule_id, tp, fp} + DP
6. Redaction: значения секретов не хранятся, только fingerprint
