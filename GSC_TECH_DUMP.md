# GSC — Полный технический дамп

> Обновлено: 2026-08-11 13:00 MSK | Schema: 29 | Детекторов: 36 | Git: master @ 1220f08

---

## БЛОК 0: Precision Report (август 2026)

Первый замер на 10 реальных проектах (160–132K ⭐):

| Проект | ⭐ | Всего | CRITICAL | HIGH | Время |
|--------|-----|-------|----------|------|-------|
| flask-smorest | 600 | 4 | 0 | 3 | 7.9s |
| fastapi-users | 4.5K | 50 | 14 | 5 | 10.1s |
| piccolo-api | 160 | 106 | 19 | 24 | 15.7s |
| sanic | 18K | 243 | 11 | 50 | 38.4s |
| httpie | 34K | 131 | 1 | 10 | 13.9s |
| thefuck | 85K | 123 | 0 | 101 | 12.5s |
| youtube-dl | 132K | 1 843 | **32** | 25 | 99.2s |
| pendulum | 6.2K | 12 | 2 | 2 | 14.7s |
| loguru | 20K | 19 | 2 | 10 | 10.4s |
| rich | 50K | 123 | 7 | 14 | 45.0s |
| **ИТОГО** | | **2 654** | **88** | **244** | 268s |

**Precision CRITICAL: ~15–20%** (после фикса GS001 extractor).  
До фикса было 129 CRITICAL, GS001 исключение extractor/spider/crawler убрало 41 FP.  
Подробнее: `benchmark/PRECISION_REPORT.md`

---

## БЛОК 1: Реальное состояние кодовой базы

### 1.1. Git log (последние 10)

```
1220f08 docs: update AGENTS.md with precision metrics
6417baa fix: GS001 — exclude extractor/spider/crawler paths
28dddb1 feat: First real-world Precision Report — 10 projects scanned
b507faa fix: benchmark scan — remove unsupported --profile flag
c6ee33d fix: #10 rule_id column, #11 blocking thresholds, #6 PoF sandbox e2e
cc010c9 fix: 3 critical bugs from GSC_TECH_DUMP review
ef34ae5 (reverted) feat: First real-world Precision Report (blocked by GH push protection)
081f1cb (reverted) feat: First real-world Precision Report (GH push protection — secrets in scan)
7e72ac0 docs: add GSC_TECH_DUMP.md to repo
1d22431 fix: benchmark_real.py — handle list-format scan output
```

### 1.2. Что исправлено после первой версии дампа

| # | Проблема | Статус |
|---|---------|--------|
| 1 | XSS calibration: expected GS017, реальный GS020 | ✅ GS017→GS020 |
| 2 | `run_detectors()` не фильтрует None | ✅ `if f is not None` |
| 9 | GS024 в файле gs020 (путаница) | ✅ `gs020_llm_sqli.py` → `gs024_llm_sqli.py` |
| 10 | `rule_id` не колонка в findings | ✅ ALTER TABLE + backfill 98K строк |
| 11 | pr-gate 0.80 ↔ Blocking Engine 0.85 | ✅ pr-gate → 0.85 |
| 6 | PoF sandbox не e2e | ✅ интеграция в `gsc_proofoffix.py` |
| 4-5 | Precision Report не завершён | ✅ 10 проектов, 2654 находки |

### 1.3. Модули GSC (корень)

```
gsc.py              — CLI (2654 строк)
gsc_db.py           — SQLite + миграции (928 строк)
gsc_external.py     — External Scanner (1532 строк)
gsc_blocking.py     — Blocking Engine (223 строки)
gsc_poc_generator.py — PoC генератор
gsc_proofoffix.py    — Proof-of-Fix
gsc_rejudge.py       — Rejudge multi-model (3 модели DeepSeek → вердикт)
gsc_shadow_manager.py — Shadow lifecycle (shadow→full→deactivated)
gsc_bounty_loader.py  — Bounty retrieval (few-shot + Deep Reduce)
gsc_collect_bounty.py — GHSA collector
gsc_compliance.py     — CWE/OWASP/PCI map
gsc_pof_sandbox.py    — Изолированный Python venv для PoF-верификации
gsc_nlpolicy.py       — NL Policy + ReDoS guard
gsc_detectors/        — 36 детекторов (GS001–GS039)
scripts/              — 40+ скриптов (pipeline, benchmark, auto-detector, ...)
cloud/                — SaaS (tenancy, api_v2, billing, workers)
enterprise/           — RBAC, SSO, Audit, Helm
```

---

## БЛОК 2: Контракт детектора

### 2.1. `gsc_detectors/base.py` — ПОЛНЫЙ КОД

```python
"""Unified detector contract (refactor #1). All detectors implement BaseDetector."""
from __future__ import annotations
import hashlib, re
from typing import Dict, List, Tuple

def make_finding(rule_id: str, title: str, severity: str, confidence: float,
                 file: str, line: int, snippet: str,
                 metadata: Dict | None = None) -> Dict:
    if not rule_id or not str(rule_id).strip():
        import warnings
        warnings.warn(f"make_finding: empty rule_id — skipped. title={title!r} file={file!r}")
        return None  # caller must handle: if f is None → skip
    key = hashlib.sha256(f"{rule_id}{file}{snippet}".encode()).hexdigest()[:12]
    return {"finding_key": key, "rule_id": rule_id, "title": title,
            "severity": severity, "confidence": confidence, "file": file,
            "line": line, "snippet": snippet[:200], "metadata": metadata or {}}


class BaseDetector:
    rule_id: str = "GS000"
    requires_llm: bool = False
    languages: Tuple[str, ...] = ()

    def detect(self, file_path: str, content: str, language: str = "auto") -> List[Dict]:
        raise NotImplementedError


class RegexDetector(BaseDetector):
    def __init__(self, rule_id: str, name: str, patterns: List[Tuple[str, str]],
                 severity: str, confidence: float, languages: Tuple[str, ...] = ()):
        self.rule_id = rule_id; self.name = name
        self.severity = severity; self.confidence = confidence
        self.languages = languages
        self._compiled = [(re.compile(p), desc) for p, desc in patterns]

    def detect(self, file_path, content, language="auto") -> List[Dict]:
        findings = []
        for pattern, title in self._compiled:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append(make_finding(
                    rule_id=self.rule_id, title=title, severity=self.severity,
                    confidence=self.confidence, file=file_path,
                    line=line_no, snippet=m.group(0)[:200]))
        return findings
```

**Ключевой контракт:**
- `make_finding()` — **единственный способ создать Finding** (инвариант #1)
- `finding_key = sha256(rule_id + file + snippet)[:12]` — стабилен
- `rule_id` обязателен: пустой → `return None`
- **`run_detectors()` теперь фильтрует None**: `if f is not None: all_findings.append(f)`

### 2.2. Формат Finding

| Поле | Тип | Как считается |
|------|-----|-------------|
| `finding_key` | str (12 chars) | `sha256(rule_id + file + snippet)[:12]` |
| `rule_id` | str | GSxxx / GSAUTO-xxx |
| `title` | str | Человеко-читаемое описание |
| `severity` | str | CRITICAL / HIGH / MEDIUM / LOW |
| `confidence` | float | 0.0–1.0 |
| `file` | str | Путь к файлу |
| `line` | int | Номер строки (1-based) |
| `snippet` | str (max 200) | Обрезанный matched text |
| `metadata` | dict | Опциональный (poc, compliance, rejudge, etc.) |

### 2.3. Registry — как добавить детектор

```python
class DetectorEntry:
    def __init__(self, rule_id, echelon, detect_fn, description, noise_tier="normal"):

# Echelons: 1=fast(regex), 2=standard(regex+context), 3=deep(LLM/full-repo)

# Добавление:
# 1. gsc_detectors/gsXXX_name.py с RULE_ID, ECHELON, description, detect(ctx)
# 2. import в registry.py
# 3. DetectorEntry(...) в ALL_DETECTORS
```

---

## БЛОК 3: Все детекторы

| rule_id | Файл | Что детектит | Languages | Echelon |
|---------|------|-------------|-----------|---------|
| GS001 | gs001_hardcoded_secret | Hardcoded secrets | все (искл. extractor/spider/crawler) | 1 |
| GS002 | gs002_world_readable | World-readable files | все | 2 |
| GS003 | gs003_debug_prints | Debug-вывод | все | 1 |
| GS004 | gs004_dangerous_subprocess | Shell-инъекции | py/js/go | 2 |
| GS005 | gs005_sql_injection | SQL/NoSQL-инъекции (87 паттернов) | py/rb/js/php/java/go/cs/rs | 2 |
| GS007 | gs007_idor | IDOR/BAC | py/js | 2 |
| GS008 | gs008_dead_code | Dead code | все | 1 |
| GS009 | gs009_supply_chain | Supply chain | все | 2 |
| GS010 | gs010_ssh_hardening | SSH hardening | все | 2 |
| GS011 | gs011_jwt_vulnerabilities | JWT | все | 2 |
| GS012 | gs012_mass_assignment | Mass assignment | py/js | 2 |
| GS013 | gs013_graphql_security | GraphQL | все | 2 |
| GS014 | gs014_credential_exposure | Credential exposure | все | 2 |
| GS015 | gs015_entry_points | Entry points | все | 2 |
| GS016 | gs016_linux_priv_esc | Linux priv esc | все | 2 |
| GS017 | gs017_weak_passwords | Weak passwords | все | 2 |
| GS018 | gs018_payment_abuse | Payment abuse | все | 2 |
| GS019 | gs019_auth_session | Auth/session | py/js | 2 |
| GS020 | gs020_xss_injection | XSS injection | py/js/php/rb | 2 |
| GS021 | gs021_csrf_ssrf | CSRF/SSRF | py/js | 2 |
| GS022 | gs022_open_redirect | Open redirect | py/js | 2 |
| GS023 | gs023_race_conditions | Race conditions | все | 2 |
| GS024 | gs024_llm_sqli | **LLM SQLi (lazy)** | py | 2 |
| GS025 | gs025_ai_provenance | AI provenance | все | 2 |
| GS028 | gs028_invariants | Invariants (opt-in) | все | 2 |
| GS029 | gs029_secrets | Cross-repo secrets | все | 2 |
| GS030 | gs030_sca | SCA (OSV.dev) | все | 2 |
| GS031 | gs031_iac | IaC (Docker/K8s/TF) | Dockerfile/yml/tf | 2 |
| GS032 | gs032_prompt_injection | Prompt injection | md/txt/py/js/ts | 2 |
| GS033 | gs033_cicd | CI/CD anti-patterns | yml/yaml | 2 |
| GS034 | gs034_supply_chain | npm supply chain | js/json | 2 |
| GS035 | gs035_php | PHP vulns | php | 2 |
| GS036 | gs036_nodejs | Node.js vulns | js/ts | 2 |
| GS037 | gs037_python | Python vulns | py | 2 |
| GS038 | gs038_go | Go vulns | go | 2 |
| GS039 | gs039_ruby | Ruby vulns | rb | 2 |

**Пропущены:** GS006, GS026, GS027  
**⚠️ Дублирование:** GS009/GS030/GS034 — три supply-chain детектора; GS035–GS039 поверх тематических

---

## БЛОК 4: Пайплайн — как детектор вызывается

### 4.1. `gsc.py scan` → `run_audit_echelons()`

Пайплайн: `clone → inventory → exclude → scan → LLM revalidate → score → report`

```python
# registry.py — обход детекторов с фильтрацией None
def run_detectors(ctx, echelons=None) -> list[Finding]:
    all_findings = []
    for det in ALL_DETECTORS:
        if echelons and det.echelon not in echelons: continue
        if det.rule_id in ctx.skipped_detectors: continue
        for f in det.detect(ctx):
            if f is not None:
                all_findings.append(f)
    return all_findings
```

### 4.2. Как finding сохраняется в БД

```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL, echelon INTEGER NOT NULL,
    category TEXT NOT NULL, title TEXT NOT NULL,
    file_path TEXT, line_number INTEGER, detail TEXT,
    rule_id TEXT,                -- 🆕 добавлено (schema 29, 98K строк backfilled)
    pattern_title TEXT,          -- оригинальное хранение rule_id
    status, pattern_fingerprint, noise_tier,
    revalidation_verdict, confidence_score,
    current_state, state_updated_at, ...
);
```

### 4.3. Где подключаются Blocking Engine / Compliance / EPSS

- **Blocking Engine**: `apply(findings)` — после скана. Пороги: CRITICAL≥0.90, HIGH≥0.85
- **Compliance**: `enrich_finding()` — CWE/OWASP/PCI в metadata
- **EPSS**: отдельная команда `gsc epss --cve ...`
- **Shadow Manager**: `detector_allowed()` → shadow=scan without block, deactivated=skip

---

## БЛОК 5: Тестирование и калибровка

### 5.1. Тест на детектор — образец

```python
def scan_file(code, filename="test.py"):
    d = tempfile.mkdtemp()
    fpath = Path(d) / filename
    fpath.write_text(code)
    subprocess.run(["git", "-C", d, "init", "-q"], ...)
    r = subprocess.run([sys.executable, GSC, "scan", d, "--ci", "--json"], ...)
    return json.loads(r.stdout)

def test_sql_injection():
    findings = scan_file('query = f"SELECT * FROM users WHERE id={uid}"\n')
    assert has_finding(findings, "sql", "CRITICAL")
```

### 5.2. Калибровка (`scripts/gsc_setup_calibration.py`)

```python
VULN = {
    "sqli-demo":  ("py", ..., "GS005"),
    "xss-demo":   ("py", ..., "GS020"),   # ✅ исправлено: было GS017
    "secrets-demo": ("py", ..., "GS029"),
    "eval-demo":  ("py", ..., "GS008"),
    "pickle-demo": ("py", ..., "GS004"),  # ✅ исправлено
    "bare-except-demo": ("py", ..., "GS003"),
    "assert-demo": ("py", ..., "GS015"),
    "hardcoded-secret": ("py", ..., "GS029"),
    "iac-demo": ("dockerfile", ..., "GS031"),
}
CLEAN = {"clean-pure": ("py", 'def add(a,b): return a+b\n')}
```

### 5.3. Precision Benchmark

```bash
python3 scripts/gsc_benchmark_real.py --fetch   # клонировать 10 проектов
python3 scripts/gsc_benchmark_real.py --scan    # прогнать GSC
python3 scripts/gsc_benchmark_real.py --report  # сводный отчёт
```

---

## БЛОК 6: БД и инварианты в коде

### 6.1. Схема БД (31 таблица)

```
findings (470K+ строк, 98K с rule_id)     detector_status
bounty_examples   negative_examples        vrt_categories
feedback          overrides                chains
secret_fingerprints  secret_sightings      mutation_alerts
sca_cache         epss_cache               nuclei_templates
dast_findings     federated_*              verify_results
finding_states    finding_sightings        schema_version (29)
```

### 6.2. Инварианты

```python
# Инвариант #1 — finding_key
key = hashlib.sha256(f"{rule_id}{file}{snippet}".encode()).hexdigest()[:12]

# Инвариант #2 — guard rule_id
if not rule_id: return None  # run_detectors фильтрует

# Инвариант #3 — Blocking Engine
PHASE_THRESHOLDS = {
    "blocking-critical": [("CRITICAL", 0.90)],
    "blocking-standard": [("CRITICAL", 0.90), ("HIGH", 0.85)],
}
POC_BOOST = 0.05; POC_BOOST_CAP = 0.95

# Инвариант Shadow
SHADOW_TO_FULL_VERDICTS = 10; SHADOW_TO_FULL_TP = 0.70; DEACTIVATE_TP = 0.30

# Инвариант Auto-degrade
NON_CODE_GLOBS = ("*.svg", "*.png", ..., "*.min.js", "*.map")
TEST_GLOBS = ("test_*.py", "*_test.py", ...)
```

### 6.3. ReDoS-guard (NL Policy)

```python
from gsc_nlpolicy import MAX_POLICY_PATTERN_LEN, BAD_RE
MAX_POLICY_PATTERN_LEN = 200  # chars
BAD_RE = re.compile(r'\(\?[^)]*\+\)|\+\+|\*\+|\+\*|\{[^}]*,[^}]*\}[+*]')
```

---

## БЛОК 7: Самообучение (Self-Learning)

### 7.1. Ночной пайплайн

```
04:00 MSK → gsc_nightly_pipeline.py (6 шагов):
  1. Self-learning revalidate
  2. NVD + GitHub patterns
  3. Bounty Collector (GHSA + VRT + negatives)
  4. Auto-Detector gate → ShadowManager.register_shadow()
  5. Batch Revalidate (BountyLoader context)
  6. Federated Submit (DP)
```

### 7.2. Shadow-цикл

```
BountyCollector → AutoDetector gate → register_shadow() → detector_status (shadow)
  ↓ день
gsc scan → shadow detector находит (conf=0.75, НЕ блокирует)
  ↓
gsc feedback tp|fp → ShadowManager.record_verdict()
  ↓ ≥10 вердиктов
TP≥70% → promote → full | TP<30% → deactivate
```

### 7.3. PoC → Proof-of-Fix цикл

```
Finding → PoC-gen (DeepSeek) → Rejudge (3 модели) → вердикт
  EXPLOITABLE → +0.10 confidence boost
  FALSE_POSITIVE → -0.30 penalty
  ↓
PoF generator → patch → sandbox execute
  PoC BEFORE fix = SUCCESS, PoC AFTER fix = FAILURE → verified ✅
  (два уровня: быстрый sandbox + глубокий venv-sandbox через gsc_pof_sandbox.py)
```

---

## ЧЕСТНЫЕ ПРОБЕЛЫ (обновлено)

| Проблема | Статус |
|----------|--------|
| XSS calibration GS017/GS020 | ✅ исправлено |
| None в run_detectors | ✅ исправлено |
| GS024 в gs020 (путаница) | ✅ исправлено |
| rule_id не колонка в БД | ✅ ALTER TABLE + backfill |
| Пороги pr-gate ≠ Blocking Engine | ✅ синхронизированы (0.85) |
| PoF sandbox не e2e | ✅ интегрирован |
| Precision Report не завершён | ✅ 10 проектов, 2654 находки |
| GS001 extractor FP | ✅ исключены extractor/spider/crawler |
| OWASP Benchmark Suite | ❌ не прогонялся |
| GS024 LLM не проверен на реальных данных | ❌ |
| EPSS не встроен в scan | ❌ отдельная команда |
| GS005 = 87 паттернов = монстр | ❌ требует декомпозиции |
| Дублирование детекторов (GS009/30/34) | ❌ |

---

## Ключевые пути

| Что | Путь |
|-----|------|
| CLI | `~/gsc/gsc.py` |
| DB | `~/.hermes/state/gsc_audit.db` |
| Detectors | `~/gsc/gsc_detectors/` |
| Registry | `~/gsc/gsc_detectors/registry.py` |
| Base class | `~/gsc/gsc_detectors/base.py` |
| Blocking | `~/gsc/gsc_blocking.py` |
| Compliance | `~/gsc/gsc_compliance.py` |
| Precision Report | `~/gsc/benchmark/PRECISION_REPORT.md` |
| Benchmark scans | `~/gsc/benchmark/real_world/` (10 проектов, 42MB локально) |
| Tests | `~/gsc/tests/` |
| Calibration | `/tmp/gsc-calibration/` |
| API key | `~/.hermes/.env` → `DEEPSEEK_API_KEY` |
