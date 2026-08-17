# PROJECT.md — GSC: Git Security Checker

> Для: внешнего AI-агента для аудита кодовой базы
> Автор: Море (Hermes orchestrator, профиль default)
> Дата: 2026-08-13
> Версия: v1.3.0 — AppSec Platform (числа → gsc_meta.py) (P0/P1/P2 + VSCode + Enterprise + SaaS S1–S4)
> Репозиторий: github.com/poliakarmai/gsc

## 1. Что это

GSC — самообучающаяся AppSec-платформа. Полный цикл:
detect → prove → fix → verify → heal → predict → learn.

**Покрытие поверхности:**
- SAST (код) — plugin-детекторы + GS024 LLM (DeepSeek) — точное число: gsc_meta.py
- SCA (зависимости) — OSV.dev бatching, GS030
- Secrets — GS029 + cross-repo корреляция
- IaC — Terraform/K8s/Dockerfile, GS031
- DAST — Nuclei integration (Waves 1–3)
- Supply chain — SBOM CycloneDX 1.5 + SPDX 2.3 + VEX + подпись

**Эксклюзивы (нет у Semgrep/Snyk/CodeQL):**
- PoC Auto-Generation + Proof-of-Fix (верификация патча перезапуском PoC)
- Self-Healing CI (авто-PR с верифицированными фиксами)
- Security Archaeology (кто/когда внёс уязвимость, lifespan)
- Predictive Forecasting (heatmap будущих уязвимостей)
- NL Policy (правила на естественном языке)
- Federated Self-Learning (DP, privacy-first)

## 2. Версии

| v | Ключевая фича |
|---|---|
| v0.11–v0.16 | Ядро: scanner, profiles, PR Gate, GitHub, REST API |
| v0.17–v0.21 | PoC, GS025, Chains, Mutations, Invariants, AST taint |
| v0.22–v0.26 | Production rollout Phase 0–5 (blocking-standard) |
| v0.27 | Эксклюзивы: PoF, Self-Healing, Archaeology, Forecast, NL Policy, Cross-Repo |
| v0.28–v0.32 | P0/P1: SCA, Secrets, Compliance, EPSS, Federated, Benchmark, Nuclei |
| v0.33 | SBOM CycloneDX + VEX |
| v0.34 | IaC (Terraform/K8s/Dockerfile), GS031 |
| v0.35 | SPDX 2.3 + подпись SBOM |
| v0.36 | Стабилизация: +20 интеграционных/регрессионных тестов |
| v0.37 | VSCode extension (diagnostics, CodeLens, tree view, webview) |
| v0.38 | Enterprise: RBAC, SSO/OIDC, Audit, Multi-tenancy, Helm, Air-gap |
| v0.39 | Master Orchestrator + reconciliation |
| v1.0.0 | First stable release |
| v1.1.0 | Polish + SaaS S1 (multi-tenant: api_keys, tenant изоляция, /api/v2) |

## 3. Архитектура (5 слоёв)

```
Слой 5: ИНТЕРФЕЙСЫ   — VSCode, CLI, Enterprise SSO/Helm
Слой 4: ОРКЕСТРАЦИЯ   — gsc_orchestrator.py (единый пайплайн)
Слой 3: ЭКСКЛЮЗИВЫ    — PoF, Self-Healing, Archaeology, Forecast, NL Policy
Слой 2: ПОВЕРХНОСТЬ   — SCA, Secrets, Compliance, IaC, EPSS, Federated, Benchmark, SBOM
Слой 1: ЯДРО          — 41 детектор, PoC, Chains, Mutations, Invariants, Blocking
ФУНДАМЕНТ:            — SQLite, REST API, finding_key
```

> **Packages split 0.5.x:** слои физически разнесены — ядро/поверхность → `gsc_core/`,
> CLI/оркестрация/эксклюзивы → `gsc_cli/`, SaaS/интерфейсы → `gsc_cloud/`.
> Корневые `gsc_*.py` — shim'ы (re-export через `sys.modules`) для обратной совместимости.

## 4. Текущее состояние (v1.3.0)

| Метрика | Значение | Проверено |
|---------|----------|:---:|
| Python-тесты | 276 (60 файлов) | `pytest -q` |
| Enterprise | 10/10 | `enterprise/tests/` |
| VSCode | tsc 0 errors, npm test 7/7 | `gsc-vscode/` |
| Calibration | 13/13 | `calibration run` |
| Schema | 32 | DB verify |
| Детекторы | 41 (37 registry + 4 движка) | registry |
| Модулей | 147 (core 13 + cli 51 + cloud 39) | `gsc_meta.py` |

## 5. Calibration gaps (v1.1.0)

| Gap | Rule | Причина |
|---|---|---|
| IaC (GS031) | GS031-DOCKER-* | IaC-детектор вызывается через `gsc iac`, не встроен в `gsc scan` |
| XSS (GS017) | f-string шаблон | Детектор не матчит `f"<div>{var}"` — нужен расширенный regex |

## 6. Ключевые команды

```bash
gsc scan <repo> --ci --json                    # базовый скан
gsc external-scan <repo> --profile audit       # полный скан
gsc sca --repo .                               # SCA
gsc iac --repo .                               # IaC
gsc sbom --repo . --with-vex                   # SBOM + уязвимости
gsc orchestrate <repo> --profile audit         # полный пайплайн
gsc calibration run --fail-on-regression       # калибровка
gsc reconcile                                  # сверка доков с кодом
```

## 7. Известные ограничения

- SaaS S2–S3 (воркеры, очереди, биллинг) — спроектированы, не реализованы
- Enterprise-модули спроектированы под PostgreSQL, работают на SQLite
- VSCode-тесты standalone (без @vscode/test-electron)
- IaC-детектор не интегрирован в `gsc scan` (отдельная команда `gsc iac`)
- Детекторы выдают rule_id нестабильно — некоторые находки без rule_id

## 8. Дорожная карта

| Фаза | Статус |
|---|---|
| Ядро + Rollout Phase 0–5 | ✅ |
| Эксклюзивы v0.27 | ✅ |
| P0/P1/P2 | ✅ |
| VSCode + Enterprise | ✅ |
| SaaS S1 | ✅ |
| SaaS S2–S3 | 📋 |
| SQLite → PostgreSQL | 📋 |
| Marketplace-публикация VSCode | 📋 |
| IaC в gsc scan | 📋 |
