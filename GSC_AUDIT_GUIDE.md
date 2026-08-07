# GSC Audit Guide — для AI-агента

> **Это актуальный источник правды.** PROJECT.md и AGENTS.md синхронизированы — все числа через `gsc_meta.py`.
> Последнее обновление: 2026-08-07 | Версия кода: v1.2.0+ | Коммит: `6c169bd`

## Назначение

Инструкция для внешнего AI-агента по проверке кодовой базы GSC. Точки входа, ожидаемые результаты, инварианты, известные проблемы, быстрые проверки.

**Источник правды по числам:** `python3 gsc_meta.py` + `python3 scripts/gsc_reconcile.py`. Этот документ описывает структуру и проверки, но конкретные числа сверяются динамически. PROJECT.md и AGENTS.md больше не содержат хардкод-чисел.

---

## 1. Что такое GSC

Самообучающаяся AppSec-платформа: `detect → prove → fix → verify → heal → predict → learn`

**Покрытие:**
- SAST: plugin-детекторы + GS024 LLM (DeepSeek)
- SCA: зависимости через OSV.dev (GS030)
- Secrets: GS029 + cross-repo корреляция
- IaC: Terraform/K8s/Dockerfile (GS031)
- DAST: Nuclei integration
- Supply chain: SBOM CycloneDX 1.5 + SPDX 2.3 + VEX + подпись

**Эксклюзивы:** PoC Auto-Generation + Proof-of-Fix, Self-Healing CI, Security Archaeology, Predictive Forecasting, Federated Self-Learning (DP).

---

## 2. Ключевые файлы и что проверять

### Ядро

| Файл | Назначение | Проверка |
|------|-----------|----------|
| `gsc.py` | CLI (50+ команд), `check_plugin_detectors` | `python3 gsc.py --help` — без ошибок |
| `gsc_external.py` | External Scanner | `grep -c "HARDCODED\|_ECHELON_PATTERNS" gsc_external.py` → 0 |
| `gsc_db.py` | SQLite, schema 28, авто-миграции | `TARGET_VERSION = 28` |
| `gsc_blocking.py` | Blocking Engine + Confidence V3 | CRITICAL≥0.90, HIGH≥0.85 |
| `gsc_compliance.py` | CWE/OWASP/PCI mapping | `COMPLIANCE_MAP` содержит GS001–GS031 |

### Детекторы

| Файл | Назначение |
|------|-----------|
| `gsc_detectors/registry.py` | Реестр: `get_detectors(echelon=...)` |
| `gsc_detectors/base.py` | Контракт: `BaseDetector`, `RegexDetector`, `make_finding()` |

**Динамическая проверка (не хардкод!):**
```bash
python3 -c "from gsc_detectors.registry import get_detectors; d=get_detectors(); print(len(d), sorted(x.rule_id for x in d))"
```
Ожидается: ≥20 детекторов. Точное число — из вывода команды, сверять с `gsc_meta.py`.

### P0/P1/P2

| Файл | Назначение | Проверка |
|------|-----------|----------|
| `gsc_sca.py` | SCA через OSV.dev | `grep -c "Package\|parse_repo_manifests"` > 0 |
| `gsc_secrets_core.py` | Единый источник секретов | `grep -c "PATTERNS\|fingerprint_secret"` ≥ 2 |
| `gsc_crossrepo_secrets.py` | Cross-repo корреляция | `grep -c ORIGINAL_PATTERNS` → 0 |
| `gsc_epss.py` | EPSS exploitability | `CACHE_TTL_HOURS = 24` |
| `gsc_federated.py` | Federated Learning (DP) | `grep -c "differential_privacy\|noise\|dp"` > 0 |
| `gsc_sbom.py` | CycloneDX 1.5 | `grep -c "bomFormat\|CycloneDX"` > 0 |
| `gsc_spdx.py` | SPDX 2.3 + подпись | `grep -c "SPDX-2.3\|sign_sbom\|verify_sbom"` > 0 |
| `gsc_iac.py` | IaC (GS031) | `grep -c "detect_dockerfile\|detect_kubernetes\|detect_terraform"` > 0 |

### Enterprise + SaaS

| Файл | Назначение | Тесты |
|------|-----------|-------|
| `enterprise/rbac.py` | 5 ролей (admin…readonly) | `enterprise/tests/test_enterprise.py` → 10/10 |
| `enterprise/sso.py` | OIDC JWT + JIT provisioning | |
| `enterprise/audit_log.py` | Tamper-evident hash chain | |
| `cloud/tenancy.py` | SaaS S1: api_keys, tenant-изоляция | `tests/test_cloud_s1.py` → 5/5 |

### Оркестрация + мета

| Файл | Назначение |
|------|-----------|
| `gsc_orchestrator.py` | Master orchestrator: scan→enrich→chains→sbom |
| `gsc_meta.py` | Единый источник мета-данных |
| `scripts/gsc_reconcile.py` | Сверка документации с реальностью |
| `scripts/gsc_setup_calibration.py` | Создание calibration-проектов |

---

## 3. Ожидаемые результаты прогона

### Тесты

```bash
cd ~/gsc
python3 tests/test_corpus.py                    # 8/8
python3 tests/test_exclusive_pof.py             # PoF
python3 tests/test_exclusive_arch_forecast.py   # Archaeology + Forecast
python3 tests/test_exclusive_modes_workspace.py # Workspace
python3 tests/test_exclusive_policy_secrets.py  # NL Policy + Secrets
python3 tests/test_compliance_audit.py          # 4/4
python3 tests/test_compliance_secrets.py        # Secrets FP
python3 tests/test_sca.py                       # SCA
python3 tests/test_epss.py                      # EPSS
python3 tests/test_federated.py                 # Federated
python3 tests/test_benchmark.py                 # OWASP Benchmark
python3 tests/test_sbom.py                      # 7/7
python3 tests/test_iac.py                       # 7/7
python3 tests/test_spdx.py                      # 7/7
python3 tests/test_integration.py               # SCA→SBOM→VEX
python3 tests/test_integration_final.py         # Orchestrator
python3 tests/test_pipeline_refactor.py         # 6/6 contract
python3 tests/test_nuclei_import.py             # 7/7
python3 tests/test_nuclei_export.py             # Nuclei export
python3 tests/test_regression.py                # Regression
python3 tests/test_perf.py                      # Performance
python3 tests/test_schema_integrity.py          # Schema
python3 tests/test_agent.py                     # Agent
python3 tests/test_cloud_s1.py                  # 5/5 SaaS S1
python3 tests/test_cloud_s4.py                  # S4
python3 enterprise/tests/test_enterprise.py     # 10/10
```

**SKIP:** `test_cloud_s2.py`, `test_cloud_s3.py` — SaaS S2–S3 не реализованы.

### Калибровка (10/10)

```bash
python3 scripts/gsc_setup_calibration.py
# Precondition: единый пайплайн применён (хардкод-паттернов нет)
grep -rn "_ECHELON_PATTERNS\|HARDCODED" gsc_external.py gsc.py || echo "✅ precondition met"
python3 gsc.py scan /tmp/gsc-calibration/xss-demo --ci --json | python3 -c "
import sys,json; fs=json.load(sys.stdin)
gs020=[f for f in fs if 'GS020' in f.get('rule_id','')]
assert gs020, 'GS020 XSS not detected — check plugin pipeline'
"
```

Ожидаемые rule_id:
- `sqli-demo` → GS005, `xss-demo` → GS020, `secrets-demo` → GS029
- `eval-demo` → GS008, `pickle-demo` → GS007, `bare-except-demo` → GS010
- `assert-demo` → GS018, `hardcoded-secret` → GS029, `iac-demo` → GS031-DOCKER-*
- `clean-pure` → 0 CRITICAL

### VSCode

```bash
cd gsc-vscode && npm install && npm run compile && npx tsc --noEmit && npm test
# Ожидание: 0 TS errors, 7/7 unit tests
```

---

## 4. Ключевые инварианты

| # | Инвариант | Где проверять | 🔴 при нарушении |
|---|----------|---------------|-----------------|
| 1 | `finding_key = sha256(rule+file+snippet)[:12]` | `make_finding()` в `base.py` | Ломает дедупликацию, feedback loop, archaeology |
| 2 | finding без rule_id — не попадает в результаты | `make_finding()`: `if not rule_id: warn + return None` | См. проблему №4: 26 находок от legacy-паттернов |
| 3 | Blocking Engine — единый источник блокировки | `gsc_blocking.py` | |
| 4 | Авто-деградация: нет DEEPSEEK_API_KEY → regex-only | `check_plugin_detectors()` | |
| 5 | Override с audit-trail | `publication_events` таблица | |
| 6 | Federated: только `{tenant_hash, rule_id, tp, fp}` + DP | `gsc_federated.py` | |
| 7 | Секреты: только fingerprint, не raw-значения | `gsc_secrets_core.py` | |
| 8 | Единый fingerprint = sha256[:32] | `fingerprint_secret()` в core и crossrepo | |
| 9 | Schema version = 28 | `gsc_db.py` `TARGET_VERSION` | |

---

## 5. Известные проблемы

| # | Что | Severity | Статус |
|---|-----|:---:|--------|
| 1 | SaaS S2–S3 не реализованы (воркеры, очереди, биллинг) | 🟡 | SKIP в тестах |
| 2 | Enterprise под PostgreSQL, работает на SQLite | 🟡 | MVP-ограничение |
| 3 | VSCode-тесты standalone (без @vscode/test-electron) | 🟡 | Не проверяют UI |
| 4 | 🔴 26 находок без rule_id от legacy-паттернов | 🔴 | **Guard skip + `scripts/gsc_audit_detectors.py`**. Корень: `check_source_driven`/`check_security` не проставляют rule_id. Фикс — миграция паттернов в DETECTORS |
| 5 | Calibration-проекты — заглушки в `/tmp/gsc-calibration/` | 🟡 | Не полный набор |
| 6 | GS024 LLM требует DEEPSEEK_API_KEY | 🟡 | Деградация в regex-only |

---

## 6. Быстрые проверки целостности

```bash
# CLI жив
python3 gsc.py --help | grep -c "scan\|sca\|sbom\|iac\|enterprise"  # → ≥8

# Детекторы из реестра (динамически, не хардкод!)
python3 -c "from gsc_detectors.registry import get_detectors; d=get_detectors(); print(len(d), sorted(x.rule_id for x in d))"

# Нет мёртвого кода
grep -rn "ORIGINAL_PATTERNS" gsc_crossrepo_secrets.py && echo "❌" || echo "✅"
grep -rn "poc_before_exit != 0" gsc_proofoffix.py 2>/dev/null && echo "❌" || echo "✅"
grep -rn "_ECHELON_PATTERNS\|HARDCODED" gsc_external.py gsc.py && echo "❌" || echo "✅"

# Schema 28
python3 -c "import sqlite3; c=sqlite3.connect('$HOME/.hermes/state/gsc_audit.db'); print(c.execute('SELECT MAX(version) FROM schema_version').fetchone()[0])"

# Fingerprint identity (устойчиво к ImportError)
python3 -c "
from gsc_secrets_core import fingerprint_secret as f1
import gsc_crossrepo_secrets as cr
f2 = getattr(cr, 'fingerprint_secret', None)
assert f2 is not None, 'crossrepo не ре-экспортирует fingerprint_secret'
assert f1('test') == f2('test'), 'fingerprint differs'
print('✅ match')
"

# VSCode компилируется
cd gsc-vscode && npx tsc --noEmit 2>&1 | grep -c "error"  # → 0
```

---

## 7. Git-состояние

```bash
git log --oneline -5
git tag --list                 # v1.0, v1.1, v1.1.1, v1.2.0
git status                     # должно быть чисто
```

---

## 8. Что делать, если что-то красное

| Симптом | Действие |
|---------|----------|
| Тест упал | `python3 tests/<test>.py` — смотреть traceback |
| gsc.py не стартует | Проверить `NameError` — пропавшие функции `cmd_*` |
| Калибровка <10/10 | Проверить `expected.json` rule_id vs фактические |
| VSCode tsc ошибки | `npm install && npx tsc --noEmit 2>&1 \| head -20` |
| Fingerprint не совпадает | Сверить `sha256(value.strip().encode()).hexdigest()[:32]` |
| **🔴 Находки без rule_id** | `python3 scripts/gsc_audit_detectors.py` — найдёт legacy-паттерны без rule_id. Guard в `make_finding()` пропускает их (warning), не роняет скан. Корень: `check_source_driven`/`check_security` в `gsc.py` |
