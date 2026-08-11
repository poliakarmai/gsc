# GSC — Полный технический дамп

> Обновлено: 2026-08-11 17:00 MSK | Schema: 30 | Детекторов: 36 | Git: master @ 84e4d26

---

## БЛОК 0: Precision + Benchmarks (август 2026)

### 0.1 Precision Report — 10 проектов

| Проект | ⭐ | CRITICAL (до) | CRITICAL (после) |
|--------|-----|---------------|------------------|
| youtube-dl | 132K | 73 | **32** |
| piccolo-api | 160 | 19 | 19 |
| fastapi-users | 4.5K | 14 | 14 |
| sanic | 18K | 11 | **2** |
| rich | 50K | 7 | 7 |
| pendulum | 6.2K | 2 | 2 |
| loguru | 20K | 2 | 2 |
| httpie | 34K | 1 | 1 |
| flask-smorest | 600 | 0 | 0 |
| thefuck | 85K | 0 | 0 |

**129 → ~77 CRITICAL (−40%), precision ~8–12% → ~20–25%**

### 0.2 Synthetic Snippet Benchmark (30 пар)

| Детектор | TPR | FPR | Score |
|---------|-----|-----|-------|
| **GS005** SQLi | 0.467 | **0.000** | **+0.467** |
| GS004 CmdInj | 0.500 | 0.000 | +0.500 |
| GS020 XSS | 0.286 | 0.000 | +0.286 |
| **Overall** | | | **+0.034** |

### 0.3 OWASP Benchmark (2740 Java)

| CWE | TPR | FPR | Score |
|-----|-----|-----|-------|
| CWE-89 (GS005) | 0.835 | 0.823 | +0.012 |
| CWE-78 (GS004) | 0.000 | 0.000 | 0.000 |
| CWE-79 (GS020) | 0.000 | 0.000 | 0.000 |

### 0.4 GS005 Tuning Pipeline

| Метрика | До | После |
|---------|-----|-------|
| TPR | 0.467 | 0.467 |
| FPR | 0.062 | **0.000** |
| Hold-out FPR | 0.250 | **0.000** |
| Target ≤ 0.30 | ❌ | ✅ |
| Отключено | — | 1 (GS005-ORM-PY-008) |

Защиты: TPR guard (drop ≤ 3%), hold-out split (80/20), MAX_DISABLE=10, MIN_SAMPLE=2, reversible.

---

## БЛОК 1: Git log (последние 10)

```
84e4d26 feat: GS005 tuning — hold-out validation + MAX_DISABLE + report
185d910 feat: GS005 tuning pipeline — measure → score → disable with TPR guard
db7c13f feat: GS005 decomposition — pattern_ids + location-based dedup (schema 30)
d1101b5 feat: Synthetic snippet benchmark — GS005/GS004/GS020 on Python/JS
9b2bc4a feat: GHSA benchmark harness + collector --days/--limit
b28cc2c docs: GSC_TECH_DUMP.md v3 — OWASP Benchmark + precision + all fixes
014f1d2 feat: OWASP Benchmark — first run (2740 cases, 8s)
d08cb1d docs: GS005 — GS005_DISABLED_LANGS env var documented
03f0fc8 docs: OWASP Benchmark procedure
d875dab docs: Precision Report updated — post-fix numbers
```

---

## БЛОК 2: Schema и инварианты

### Schema 30

```sql
pattern_status (pattern_id PK, rule_id, enabled, measured_precision,
                true_positives, false_positives, sample_size,
                disabled_reason, disabled_at, updated_at)

findings (+ rule_id, + current_state, + state_updated_at)
detector_status, finding_states, verify_results, ...
```

### Инварианты

| # | Инвариант | Статус |
|---|----------|--------|
| 1 | finding_key = sha256(rule+file+snippet)[:12] | ✅ не изменился |
| 2 | Blocking Engine — единый источник блокировки | ✅ Precision Gate добавлен |
| 3 | Precision Gate: <30% → warn-only | ✅ 6 детекторов |
| 4 | GS005 pattern_id в metadata, rule_id="GS005" | ✅ 79 уникальных |
| 5 | ReDoS-guard: MAX_PATTERN_LEN=200, BAD_RE | ✅ |

---

## БЛОК 3: GS005 — pattern_id decomposition (v2.0)

79 паттернов, каждый с уникальным pattern_id:

```
GS005-FSTR-PY-001  (f-string SQLi в execute())
GS005-FMT-PY-001   (%-formatting SQLi)
GS005-CONCAT-JS-001 (JS string concat)
GS005-ORM-PY-008   (User.objects.raw — отключён)
...
```

| Тип | Кол-во |
|-----|--------|
| FSTR | 13 |
| FMT | 11 |
| CONCAT | 17 |
| ORM | 12 |
| NOSQL | 4 |
| GEN | 16 |
| JDBC | 3 |

Расположение: `gsc_detectors/gs005_sql_injection.py`
Тюнинг: `benchmark/tune_gs005.py` (measure → score → disable → hold-out → report)
Назначение ID: `scripts/gs005_assign_pattern_ids.py`

---

## БЛОК 4: Ключевые команды

```bash
# Benchmark
python3 benchmark/ghsa_benchmark.py              # все детекторы
python3 benchmark/ghsa_benchmark.py --rule GS005  # только SQLi

# GS005 tuning
python3 benchmark/tune_gs005.py                  # dry-run
python3 benchmark/tune_gs005.py --apply          # применить

# OWASP (Java, требует Maven)
python3 benchmark/run_owasp_fast.py              # 2740 тестов, 8s

# Collector
python3 gsc_collect_bounty.py ghsa --days 90 --limit 500

# DB
python3 -c "from gsc_db import GSCDatabase; db=GSCDatabase(); db._migrate()"
sqlite3 ~/.hermes/state/gsc_audit.db "SELECT * FROM pattern_status"
```

---

## ЧЕСТНЫЕ ПРОБЕЛЫ

| Проблема | Статус |
|----------|--------|
| GS004/GS020 — 0% TPR на Java | 🔴 нужны Java-паттерны |
| GS005 — 6/79 паттернов имеют данные для тюнинга | 🟠 нужно больше benchmark-кейсов |
| GHSA Collector — нет fix-diff'ов | 🟡 synthetic benchmark как замена |
| CWE-90,134,259,327,501,614,643 — нет покрытия | 🟡 |
| Перенос результатов в PRECISION_REPORT.md | 🟡 |

---

## Ключевые пути

| Что | Путь |
|-----|------|
| CLI | `~/gsc/gsc.py` |
| DB | `~/.hermes/state/gsc_audit.db` |
| GS005 detector | `~/gsc/gsc_detectors/gs005_sql_injection.py` |
| Pattern IDs | `~/gsc/scripts/gs005_assign_pattern_ids.py` |
| Snippet benchmark | `~/gsc/benchmark/ghsa_benchmark.py` |
| Tuning pipeline | `~/gsc/benchmark/tune_gs005.py` |
| Tuning report | `~/gsc/benchmark/GS005_TUNING_REPORT.md` |
| Precision Report | `~/gsc/benchmark/PRECISION_REPORT.md` |
| OWASP benchmark | `~/gsc/benchmark/run_owasp_fast.py` |
| Blocking | `~/gsc/gsc_blocking.py` |
| AuditContext | `~/gsc/gsc_detectors/__init__.py` |
