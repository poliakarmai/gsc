# GSC — Packages Split (трек 0.5) — ПЛАН РЕАЛИЗАЦИИ

> Статус: **✅ ЗАВЕРШЁН (0.5.1–0.5.5)** — 0.5.1 `78222dc`, 0.5.2 `e821e62`, 0.5.3 `b29af60`, 0.5.4 dev-изоляция + 0.5.5 shim-cleanup (см. CHANGELOG). План ниже оставлен как историческая справка.
> Дата: 2026-08-17
> Автор: Море (Hermes)
> SSOT чисел: `python3 gsc_meta.py` (v1.4.0, 47 детекторов, schema 33, 165 модулей)

---

## 1. Цель

Разнести монолит (~66 `gsc_*.py` в корне + `cloud/` 33 файла + `scripts/` 51 файл)
по трём пакетам с чистыми границами зависимостей:

| Порция | Пакет | Что переезжает |
|--------|-------|----------------|
| 0.5.1 | `gsc_core/` | движок: gsc_db, gsc_blocking, gsc_detectors/, gsc_invariant_engine, gsc_ast_dataflow, gsc_compliance, gsc_sca, gsc_epss, gsc_federated |
| 0.5.2 | `gsc_cli/` | gsc.py, gsc_external, gsc_orchestrator, PoC/Chain/Mutation/… + scripts/; entry `gsc = "gsc_cli.main:main"` |
| 0.5.3 | `gsc_cloud/` | server.py + cloud/ |
| 0.5.4 | dev-изоляция | gsc_collector/ → core; tests/+benchmark/+calibration/ — только dev (не в wheel) |
| 0.5.5 | shim + cleanup | корневые shim → re-export, обновить cron-скрипты, удалить build/lib |

**Этот документ — детальный план 0.5.1.** 0.5.2–0.5.5 — обзорно (раздел 8).

---

## 2. Текущее состояние (факт, сверено с диском 17.08.2026)

- ✅ `gsc_core/` создан — внутри `gsc_ast_dataflow.py` (полная, 6.8KB) + `__init__.py`.
- ✅ Корневой `gsc_ast_dataflow.py` = shim 540B (`sys.modules` alias) — proof-of-pattern, 272 теста зелёные.
- ❌ `gsc_cli/`, `gsc_cloud/` — не существуют.
- ❌ 8 движков ещё полными модулями в корне: `gsc_db` (45KB), `gsc_blocking` (11.8KB), `gsc_detectors/` (47 файлов), `gsc_invariant_engine`, `gsc_compliance`, `gsc_sca`, `gsc_epss`, `gsc_federated`.
- ❌ Абсолютные импорты `from gsc_detectors import ...` внутри детекторов — не тронуты.

---

## 3. Граф зависимостей core-модулей (из ast-анализа)

```
                    gsc_db (фундамент, 0 core-зависимостей)
                     ▲   ▲
        ┌────────────┘   └────────────┐
   gsc_epss                      gsc_federated

   gsc_ast_dataflow (0 deps) ←── gsc_invariant_engine
   gsc_sca (0 deps)          ←── gsc_detectors/gs030_sca
   gsc_blocking (0 deps)
   gsc_compliance (0 deps)
```

**Вывод: циклов между core-модулями НЕТ.** Порядок переноса определяется
зависимостями снизу вверх.

### Blast radius (кто импортирует каждый движок)

| Модуль | Импортёров | Самые тяжёлые потребители |
|--------|-----------|---------------------------|
| gsc_db | 23 | gsc.py, server.py, gsc_api, gsc_meta, cron (_cron_collect, _cron_nvd), gsc_github_adapter, gsc_federated, gsc_epss |
| gsc_detectors | 46 | gsc.py, gsc_external, gsc_meta, gsc_proofoffix, benchmark×4, scripts×8, tests×7 |
| gsc_sca | 11 | gsc.py, gsc_orchestrator, gsc_supply_chain_chains, tests×7 |
| gsc_compliance | 9 | gsc_orchestrator, benchmark, scripts, tests×5 |
| gsc_epss | 5 | gsc_forecast, gsc_orchestrator, tests×3 |
| gsc_blocking | 3 | gsc_external, tests×2 |
| gsc_federated | 3 | tests×3 |
| gsc_invariant_engine | 2 | gsc.py, gsc_detectors/gs028_invariants |
| gsc_ast_dataflow | 1 | gsc_invariant_engine (✅ уже shim) |

---

## 4. Стратегия shim (единая, без вариантов)

### 4.1 Модули (8 шт): перенос + корневой shim-модуль

Для `gsc_db`, `gsc_blocking`, `gsc_compliance`, `gsc_sca`, `gsc_epss`,
`gsc_federated`, `gsc_invariant_engine` — паттерн уже доказан на `gsc_ast_dataflow`:

```
gsc_core/gsc_X.py      ← полная реализация (переезжает, правится import'ы внутри)
gsc_X.py (корень)       ← shim 5 строк: sys.modules alias → gsc_core.gsc_X
```

Внешние потребители **НЕ трогаем** — `import gsc_X` / `from gsc_X import Y`
продолжают работать через shim.

### 4.2 Пакет gsc_detectors (47 файлов): перенос + правка на относительные импорты

Это **пакет**, не модуль — shim сложнее. Правило:

1. Переносим `gsc_detectors/` → `gsc_core/gsc_detectors/` целиком (включая `yaml_rules/`).
2. **Внутри** детекторов правим ВСЕ абсолютные импорты на относительные:
   - `from gsc_detectors import AuditContext, Finding` → `from . import AuditContext, Finding`
   - `from gsc_detectors.base import make_finding` → `from .base import make_finding`
   - `import gsc_detectors.gsXXX` (registry.py, 39 строк) → `from . import gsXXX`
   - `from gsc_detectors.base import RegexDetector` (yaml_rules, 5 файлов) → `from ..base import RegexDetector`
   - `from gsc_invariant_engine import ...` (gs028) → `from gsc_core.gsc_invariant_engine import ...`
   - `from gsc_sca import ...` (gs030) → `from gsc_core.gsc_sca import ...`
3. **В корне** оставляем shim-пакет `gsc_detectors/` с `__init__.py`, который через
   `pkgutil.walk_packages` рекурсивно алиасирует все подмодули
   `gsc_core.gsc_detectors.*` → `sys.modules["gsc_detectors.*"]`. Внешние потребители
   (`gsc.py`, `gsc_external`, `gsc_meta`, `scripts/*`, `tests/*`, `benchmark/*`)
   работают без изменений.

---

## 5. Пошаговый план 0.5.1 (порядок = зависимостям)

Каждый шаг = **перенос + shim + правка импортов + проверка**. После каждого шага —
зелёный тест, иначе откат (`git checkout`).

### Шаг 0. Подготовка
- [ ] `git -C ~/gsc status` — чисто, либо зафиксировать текущее.
- [ ] Снимок baseline: `python3 gsc_meta.py` (сохранить 165 модулей) + `pytest -q` (426 passed).
- [ ] Бэкап: `scripts/gsc_backup.py` (или tar корня без .git).

### Шаг 1. `gsc_db` (фундамент, 23 импортёра)
- Перенести `gsc_db.py` → `gsc_core/gsc_db.py`.
- Создать корневой shim `gsc_db.py` (5 строк).
- Правок импортов внутри нет (gsc_db самодостаточен).
- **Проверка:** `python3 -c "import gsc_db; print(gsc_db.__file__)"` → указывает на gsc_core.
  `pytest -q tests/test_db_migration.py tests/test_schema_integrity.py tests/test_federated.py tests/test_nuclei_import.py tests/test_mcp_server.py` → зелёные.

### Шаг 2. Листья без зависимостей (3 модуля, независимы)
- `gsc_blocking` → `gsc_core/` + shim. Проверка: `tests/test_regression.py tests/test_shadow_blocking.py`.
- `gsc_compliance` → `gsc_core/` + shim. Проверка: `tests/test_compliance_audit.py tests/test_compliance_secrets.py`.
- `gsc_sca` → `gsc_core/` + shim. Проверка: `tests/test_sca.py tests/test_sbom.py tests/test_spdx.py tests/test_reachability.py`.

### Шаг 3. Зависимые от gsc_db (2 модуля)
- `gsc_epss` → `gsc_core/` + shim (внутри `import gsc_db` остаётся — резолвится через shim). Проверка: `tests/test_epss.py`.
- `gsc_federated` → `gsc_core/` + shim. Проверка: `tests/test_federated.py tests/test_federated_privacy.py`.

### Шаг 4. `gsc_invariant_engine` (зависит от ast_dataflow — уже в core)
- Перенести → `gsc_core/` + shim. Внутри `from gsc_ast_dataflow import` → `from gsc_core.gsc_ast_dataflow import` (или оставить через shim; решить на шаге, приоритет — `gsc_core.`).
- Проверка: `import gsc_invariant_engine`, полный smoke `python3 gsc.py --version`.

### Шаг 5. `gsc_detectors/` (последний, 47 файлов, массовая правка импортов)
- `mv gsc_detectors → gsc_core/gsc_detectors`.
- Скрипт-правка (авто, потом ручная сверка) относительных импортов во всех 47 файлах.
- registry.py: 39 строк `import gsc_detectors.gsXXX` → `from . import gsXXX`.
- yaml_rules/ (5 файлов): `from gsc_detectors.base` → `from ..base`.
- gs028: `from gsc_invariant_engine` → `from gsc_core.gsc_invariant_engine`.
- gs030: `from gsc_sca` → `from gsc_core.gsc_sca`.
- Корневой shim-пакет `gsc_detectors/__init__.py` (авто-алиас подмодулей через pkgutil).
- **Проверка:** `pytest -q tests/test_detector_registry.py tests/test_pipeline_refactor.py tests/test_regression.py tests/test_integration.py` + `python3 -c "from gsc_detectors.registry import get_detectors; print(len(get_detectors()))"` → 41.

### Шаг 6. Финальная верификация 0.5.1
- [ ] `python3 -m compileall gsc_core/` — без ошибок.
- [ ] `pytest -q` — полный прогон (426 tests, ожидание 0 failed).
- [ ] `python3 scripts/gsc_reconcile.py` — version/detectors/schema совпадают.
- [ ] Живой smoke: `python3 gsc.py --version`, `python3 gsc.py external-scan --help`.
- [ ] `python3 gsc_meta.py` → modules остаётся 153 (shim не создаёт новых, перенос не теряет).
- [ ] Проверить cron-скрипты `_cron_collect.py`, `_cron_nvd.py` (`import gsc_db` работает).

---

## 6. Что НЕ трогаем в 0.5.1

- `gsc_cli/`, `gsc_cloud/` — не создаём (0.5.2/0.5.3).
- `server.py`, `cloud/` — остаются на месте.
- `scripts/`, `benchmark/`, `calibration/`, `tests/` — не двигаем (0.5.4).
- `gsc.py`, `gsc_external`, `gsc_orchestrator` — остаются в корне (0.5.2).
- `gsc_meta.py` — остаётся в корне (SSOT, используется reconcile).
- `pyproject.toml` — не трогаем в 0.5.1 (extras правка — в 0.5.4/0.5.5).

---

## 7. Риски и откат

| Риск | Митигация |
|------|-----------|
| Циклический импорт через shim-пакет gsc_detectors | Относительные импорты внутри детекторов устраняют самовызов через shim. Проверка `import gsc_detectors` на каждом шаге. |
| Сломанный `import gsc_db` у 23 потребителей | Shim-модуль = прозрачный alias, потребители не правятся. Проверка `python3 -c "import gsc_db"`. |
| registry.py пропустит детектор при правке | Авто-скрипт + ручная сверка списка 39 импортов + `len(get_detectors())==41`. |
| Регрессия в 426 тестах | Полный pytest после каждого шага; при падении — `git checkout` конкретного файла. |

**Откат:** любой шаг обратим через `git checkout -- <файлы>` (перенос = `git mv`, shim = новый файл). Полный откат = `git reset --hard` до снапшота Шага 0.

---

## 8. Обзор 0.5.2–0.5.5 (для контекста, отдельный план позже)

- **0.5.2 `gsc_cli/`**: gsc.py, gsc_external, gsc_orchestrator, все PoC/Chain/Mutation/… + `scripts/`. Entry `gsc = "gsc_cli.main:main"`. Держатели: cron-скрипты, `python3 gsc.py ...`.
- **0.5.3 `gsc_cloud/`**: `server.py` + `cloud/` (33 файла). Блокирующая для S1 PostgreSQL.
- **0.5.4 dev-изоляция**: `gsc_collector/` → core; `tests/`+`benchmark/`+`calibration/` — только dev-зависимости (не в wheel).
- **0.5.5 shim+cleanup**: корневые shim → re-export из core/cli/cloud; обновить cron-скрипты (`_cron_*`); удалить `build/lib`; `pyproject.toml` extras.

---

## 9. Критерии готовности 0.5.1

- [ ] Все 9 движков физически в `gsc_core/`, корневые shim на месте.
- [ ] `from gsc_detectors.registry import get_detectors` возвращает 41.
- [ ] Полный `pytest -q` = 426 passed, 0 failed.
- [ ] `gsc_reconcile.py` — OK (version/detectors/schema).
- [ ] `compileall gsc_core/` — чисто.
- [ ] Живой smoke `gsc.py` и cron-скрипты не сломаны.
- [ ] `gsc_meta.py` modules = 153.
