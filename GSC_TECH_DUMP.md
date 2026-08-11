# GSC — Полный технический дамп

> Обновлено: 2026-08-11 15:00 MSK | Schema: 29 | Детекторов: 36 + 2 OWASP Java | Git: master @ 014f1d2

---

## БЛОК 0: Precision + OWASP Benchmark (август 2026)

### 0.1 Precision Report — 10 реальных проектов

| Проект | ⭐ | CRITICAL (до) | CRITICAL (после фиксов) |
|--------|-----|---------------|------------------------|
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

**До фиксов:** 129 CRITICAL, precision ~8–12%.  
**После фиксов:** ~77 CRITICAL (−40%), precision ~20–25%.

| Фикс | Эффект |
|------|--------|
| GS001: исключены `extractor/spider/crawler` пути | −41 CRITICAL (youtube-dl) |
| YAML-36ACF0AD: `exec()` CRITICAL→HIGH, conf 0.9→0.6 | −11 CRITICAL (sanic) |
| Precision Gate: 6 шумных детекторов → warn-only | не блокируют CI/CD |
| FP классификация: 57% extractor, 14% hardcoded, 12% SQLi | целевой анализ |

### 0.2 OWASP Benchmark — первый прогон (2740 тестов, 8.0s)

| CWE | Детектор | TP | FP | FN | TN | TPR | FPR | OWASP |
|-----|---------|-----|-----|-----|-----|-----|-----|-------|
| CWE-89 SQLi | GS005 | 227 | 191 | 45 | 41 | **0.835** | 0.823 | +0.012 |
| CWE-78 CmdInj | GS004 | 0 | 0 | 126 | 125 | 0.000 | 0.000 | 0.000 |
| CWE-79 XSS | GS020 | 0 | 0 | 246 | 209 | 0.000 | 0.000 | 0.000 |
| **Overall** | | | | | | | | **0.004** |

**Вывод:** GS005 имеет хороший recall на Java (83.5%) благодаря новым OWASP-паттернам, но плохой precision (FPR 82% — паттерны слишком широкие). GS004/GS020 не покрывают Java.

### 0.3 Ручная верификация

| Находка | Вердикт |
|---------|---------|
| piccolo-api GS019: OTP без rate limiting | ✅ **TP** — реальная уязвимость |
| sanic YAML-36ACF0AD: exec() в livereload.js (×9) | ❌ FP — исправлено (CRITICAL→HIGH) |
| GS024 LLM: калибровка sqli-demo | ✅ conf=1.0, на реальных проектах 0 FP |

---

## БЛОК 1: Реальное состояние кодовой базы

### 1.1. Git log (последние 10)

```
014f1d2 feat: OWASP Benchmark — first run (2740 cases, 8s)
d08cb1d docs: GS005 — document per-language tuning via GS005_DISABLED_LANGS
03f0fc8 docs: OWASP Benchmark procedure — ready for next run
d875dab docs: Precision Report updated — post-fix numbers
95e0c57 fix: YAML-36ACF0AD — CRITICAL→HIGH, conf 0.9→0.6
b17fe6a fix: clarify GS034 — npm Malware Patterns
fdbff30 feat: Precision-gated Blocking Engine
581ed03 docs: GS005 pattern breakdown + AUDIT_GUIDE sync
68e8b3c docs: GSC_TECH_DUMP.md v2
1220f08 docs: update AGENTS.md with precision metrics
```

### 1.2. Что исправлено

| # | Проблема | Статус |
|---|---------|--------|
| 1 | XSS calibration GS017→GS020 | ✅ |
| 2 | `run_detectors()` не фильтрует None | ✅ |
| 10 | `rule_id` не колонка в findings | ✅ ALTER TABLE + 98K backfill |
| 11 | Пороги pr-gate 0.80 ↔ Blocking 0.85 | ✅ оба 0.85 |
| 4-5 | Precision Report не завершён | ✅ 10 проектов, 2654 находки |
| OWASP | Benchmark не прогонялся | ✅ 2740 тестов, TPR/FPR |
| GS005 | 76 паттернов — категоризация | ✅ по языкам и типам |
| GS024 | LLM не проверен | ✅ conf=1.0, 0 FP на реальных |

### 1.3. Модули GSC

```
gsc.py              — CLI (50+ команд)
gsc_db.py           — SQLite + миграции, schema 29
gsc_blocking.py     — Blocking Engine + Precision Gate
gsc_external.py     — External Scanner (профили: audit, pr-gate, developer-review)
gsc_poc_generator.py — PoC генератор + Rejudge integration
gsc_proofoffix.py    — Proof-of-Fix + PoF sandbox (2 уровня)
gsc_rejudge.py       — Rejudge multi-model (3 модели DeepSeek)
gsc_shadow_manager.py — Shadow lifecycle (shadow→full→deactivated)
gsc_bounty_loader.py  — Bounty retrieval (few-shot PoF)
gsc_collect_bounty.py — GHSA collector
gsc_compliance.py     — CWE/OWASP/PCI mapping
gsc_pof_sandbox.py    — Изолированный venv для PoF-верификации
gsc_nlpolicy.py       — NL Policy + ReDoS guard
gsc_detectors/        — 36 детекторов (GS001–GS039)
benchmark/            — OWASP Benchmark + Precision Report
scripts/              — 40+ скриптов
```

---

## БЛОК 2: Контракт детектора

### 2.1. `gsc_detectors/base.py`

```python
def make_finding(rule_id, title, severity, confidence, file, line, snippet, metadata=None):
    if not rule_id: return None  # caller must filter
    key = hashlib.sha256(f"{rule_id}{file}{snippet}".encode()).hexdigest()[:12]
    return {"finding_key": key, "rule_id": rule_id, "title": title,
            "severity": severity, "confidence": confidence, "file": file,
            "line": line, "snippet": snippet[:200], "metadata": metadata or {}}

class RegexDetector(BaseDetector):
    def __init__(self, rule_id, name, patterns, severity, confidence, languages=()):
        self._compiled = [(re.compile(p), desc) for p, desc in patterns]
    def detect(self, file_path, content, language="auto"):
        # iterates patterns, calls make_finding() for each match
```

### 2.2. Формат Finding

| Поле | Тип | Инвариант |
|------|-----|----------|
| `finding_key` | str(12) | `sha256(rule_id + file + snippet)[:12]` |
| `rule_id` | str | GSxxx / GSAUTO-xxx / YAML-xxxxxxxx |
| `severity` | CRITICAL/HIGH/MEDIUM/LOW | |
| `confidence` | float 0-1 | |
| `file` / `line` / `snippet`(200) | | |

---

## БЛОК 3: Детекторы (36 + 2 OWASP Java)

| rule_id | Что детектит | Languages | Echelon |
|---------|-------------|-----------|---------|
| GS001 | Hardcoded secrets (искл. extractor) | все | 1 |
| GS004 | Shell-инъекции | py/js/go | 2 |
| GS005 | SQL/NoSQL — 78 паттернов (🆕 +2 Java OWASP) | 9 языков | 2 |
| GS020 | XSS injection | py/js/php/rb | 2 |
| GS024 | **LLM SQLi** (DeepSeek, lazy) | py | 2 |
| GS029 | Cross-repo secrets | все | 2 |
| GS030 | SCA (OSV.dev) | все | 2 |
| GS031 | IaC (Docker/K8s/TF) | Dockerfile/yml/tf | 2 |
| GS032 | Prompt injection | md/txt/py/js/ts | 2 |
| GS034 | npm Malware (ChainDrop) | js/json | 1 |
| GS035–GS039 | Языковые (PHP/Node/Python/Go/Ruby) | | 2 |
| GS001–GS039 | ... ещё 25 детекторов | | |

---

## БЛОК 4: Пайплайн

```python
# registry.py — обход с фильтрацией None
def run_detectors(ctx, echelons=None):
    for det in ALL_DETECTORS:
        for f in det.detect(ctx):
            if f is not None: all_findings.append(f)
```

### Precision Gate (gsc_blocking.py)

```python
PRECISION_GATE = {
    "GS001": 0.15, "GS005": 0.25, "GS025": 0.10,
    "GS037": 0.20, "GS007": 0.05, "GS015": 0.15,
    "GS004": 0.70, "GS029": 0.60,
}
PRECISION_WARN_THRESHOLD = 0.30   # < 30% → warn-only, NEVER block
PRECISION_BLOCK_THRESHOLD = 0.70  # ≥ 70% → full blocking
```

### Blocking Engine пороги

```python
PHASE_THRESHOLDS = {
    "blocking-critical": [("CRITICAL", 0.90)],
    "blocking-standard": [("CRITICAL", 0.90), ("HIGH", 0.85)],
}
SHADOW_TO_FULL_VERDICTS = 10; SHADOW_TO_FULL_TP = 0.70; DEACTIVATE_TP = 0.30
```

---

## БЛОК 5: Тестирование и бенчмарки

### 5.1. Калибровка

```python
VULN = {
    "sqli-demo" → GS005, "xss-demo" → GS020,
    "pickle-demo" → GS004, "bare-except-demo" → GS003,
    "assert-demo" → GS015, "secrets-demo" → GS029, ...
}
```

### 5.2. Precision Benchmark

```bash
python3 scripts/gsc_benchmark_real.py --fetch   # 10 проектов
python3 scripts/gsc_benchmark_real.py --scan    # прогнать GSC
python3 scripts/gsc_benchmark_real.py --report  # сводка
```

### 5.3. OWASP Benchmark

```bash
# Требуется: Java 21, Maven 3.8.7, OWASP Benchmark Suite в /tmp/OWASP-Benchmark
python3 benchmark/run_owasp_fast.py              # 2740 тестов, 8s
python3 benchmark/run_owasp_fast.py --limit 100  # быстрый тест
```

---

## БЛОК 6: БД и инварианты

### 6.1. Schema 29 — таблица findings

```sql
findings (470K+ строк, 98K с rule_id):
  id, project, echelon, category, title, file_path,
  line_number, detail, rule_id, pattern_title,
  finding_key, status, confidence_score, noise_tier, ...
```

### 6.2. Инварианты

| # | Инвариант | Где |
|---|----------|-----|
| 1 | `finding_key = sha256(rule+file+snippet)[:12]` | `make_finding()` |
| 2 | Blocking Engine — единый источник блокировки | `gsc_blocking.py` |
| 3 | Precision Gate: <30% → warn-only | `_is_low_precision()` |
| 4 | Shadow: ≥10 вердиктов, TP≥70% → full | `gsc_shadow_manager.py` |
| 5 | ReDoS-guard: MAX_PATTERN_LEN=200, BAD_RE | `gsc_nlpolicy.py` |
| 6 | Schema = 29 | `gsc_db.py TARGET_VERSION` |

---

## БЛОК 7: Самообучение

```
04:00 MSK → gsc_nightly_pipeline.py (6 шагов):
  1. Self-learning revalidate
  2. NVD + GitHub patterns
  3. Bounty Collector (GHSA + VRT + negatives)
  4. Auto-Detector gate → ShadowManager.register_shadow()
  5. Batch Revalidate (BountyLoader context)
  6. Federated Submit (DP)
```

### PoC → PoF цикл

```
Finding → PoC-gen (DeepSeek) → Rejudge (3 модели) → вердикт
  EXPLOITABLE → +0.10 boost | FALSE_POSITIVE → -0.30 penalty
  ↓
PoF generator → patch → sandbox (2 уровня: быстрый + venv)
  PoC BEFORE fix = SUCCESS + PoC AFTER fix = FAILURE → verified ✅
```

---

## ЧЕСТНЫЕ ПРОБЕЛЫ

| Проблема | Статус |
|----------|--------|
| OWASP Benchmark: GS004/GS020 — 0% TPR на Java | 🔴 нужны Java-паттерны |
| OWASP Benchmark: GS005 FPR=82% | 🟠 тюнить Java-паттерны |
| OS Command Injection (CWE-78): нет Java | 🟡 |
| XSS (CWE-79): нет Java | 🟡 |
| CWE-90,134,259,327,501,614,643 — нет покрытия | 🟡 70% uncovered |
| EPSS не встроен в scan | 🟡 отдельная команда |
| VSCode extension не обновлялся | 🟡 |

---

## Ключевые пути

| Что | Путь |
|-----|------|
| CLI | `~/gsc/gsc.py` |
| DB | `~/.hermes/state/gsc_audit.db` |
| Detectors | `~/gsc/gsc_detectors/` |
| OWASP Benchmark | `~/gsc/benchmark/run_owasp_fast.py` |
| Precision Report | `~/gsc/benchmark/PRECISION_REPORT.md` |
| Blocking | `~/gsc/gsc_blocking.py` |
| API key | `~/.hermes/.env` → `DEEPSEEK_API_KEY` |
