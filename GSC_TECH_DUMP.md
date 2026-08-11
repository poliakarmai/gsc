# GSC — Полный технический дамп

> Сгенерировано: 2026-08-11 | Schema: 29 | Детекторов: 36 | Git: master @ 1d22431

---

## БЛОК 1: Реальное состояние кодовой базы

### 1.1. Git log (последние 10)

```
1d22431 fix: benchmark_real.py — handle list-format scan output
70b5b77 chore: add .gitignore for benchmark/real_world cloned projects
7fef4bd feat: PoF Sandbox — real execution in isolated venv (Stage 2)
00c7c08 fix: PoC cross-model verification — Rejudge integration deepened
3670176 feat: Nightly pipeline orchestrator + full self-learning loop closed
0ceaf39 feat: Shadow in Blocking Engine + BountyLoader→PoF few-shot
e470afa feat: Auto-Detector v4 — complete validation gate (per review design)
6ab047b feat: Bounty Collector v3 — ReDoS-guard, LOO validation, GSAUTO schema
4d65f01 feat: Bounty Collector v2 — all review items addressed
d4d0741 feat: bounty collector + Deep Reduce enrichment + revalidator context + auto-detector
```

### 1.2. Расхождение AGENTS.md ↔ код

| AGENTS.md говорит | Реальность |
|---|---|
| "28 детекторов + GS024 LLM" | 36 файлов детекторов, 33 в registry |
| "schema 28" | schema **29** (в коде `TARGET_VERSION = 29`) |
| "23 таблицы" | 31 таблица (`sqlite3 .tables`) |
| `gsc_secrets.py` | `gsc_secrets_core.py` + `gsc_crossrepo_secrets.py` |

### 1.3. Модули GSC (корень)

```
gsc.py          — CLI (2654 строк)
gsc_db.py       — SQLite + миграции (928 строк)
gsc_external.py — External Scanner (1532 строк)
gsc_blocking.py — Blocking Engine (223 строки)
gsc_poc_generator.py — PoC генератор (223 строки)
gsc_proofoffix.py    — Proof-of-Fix (510 строк)
gsc_rejudge.py       — Rejudge multi-model (163 строки)
gsc_shadow_manager.py — Shadow lifecycle (137 строк)
gsc_bounty_loader.py  — Bounty retrieval (336 строк)
gsc_collect_bounty.py — GHSA collector (815 строк)
gsc_compliance.py     — CWE/OWASP/PCI map (94 строки)
gsc_deep_reducer.py   — Deep Reduce (375 строк)
gsc_pof_sandbox.py    — PoF sandbox (новый)
gsc_nlpolicy.py       — NL Policy + ReDoS guard (344 строки)
gsc_sca.py / gsc_iac.py / gsc_sbom.py / gsc_spdx.py — P0 поверхность
gsc_archaeology.py / gsc_forecast.py / gsc_federated.py — эксклюзивы
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

### 2.2. Формат Finding

**`make_finding()` возвращает dict с полями:**

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
| `metadata` | dict | Опциональный (poc, compliance, etc.) |

**`Finding` класс (из `__init__.py`) добавляет:**
- `category` = `severity` (для обратной совместимости)
- `line_number` = `line`
- `file_path` = переданный при создании
- `detail`, `fix_suggestion`, `references`, `noise_tier`

**Критично:** `Finding` — это `dict`. `make_finding()` создаёт dict с "severity", `Finding.__init__()` дублирует в "category".

### 2.3. Registry — как добавить детектор

```python
# registry.py
class DetectorEntry:
    def __init__(self, rule_id, echelon, detect_fn, description, noise_tier="normal"):

# Echelons:
#   1 = fast (regex)
#   2 = standard (regex + context)
#   3 = deep (LLM / full-repo analysis)

# Добавление:
# 1. Создать gsc_detectors/gsXXX_name.py с RULE_ID, ECHELON, description, detect(ctx)
# 2. import gsc_detectors.gsXXX_name as _gsXXX в registry.py
# 3. DetectorEntry(rule_id=_gsXXX.RULE_ID, echelon=_gsXXX.ECHELON, ...) в ALL_DETECTORS
```

---

## БЛОК 3: Все детекторы

| rule_id | Файл | Что детектит | Languages | Echelon | requires_llm |
|---------|------|-------------|-----------|---------|-------------|
| GS001 | gs001_hardcoded_secret | Hardcoded secrets/tokens | все | 2 | нет |
| GS002 | gs002_world_readable | World-readable файлы | все | 2 | нет |
| GS003 | gs003_debug_prints | Debug-вывод | все | 1 | нет |
| GS004 | gs004_dangerous_subprocess | Shell-инъекции | py/js/go | 2 | нет |
| GS005 | gs005_sql_injection | SQL/NoSQL-инъекции (87 паттернов) | py/rb/js/php/java/go/cs/rs | 2 | нет |
| GS007 | gs007_idor | IDOR/BAC | py/js | 2 | нет |
| GS008 | gs008_dead_code | Dead code | все | 1 | нет |
| GS009 | gs009_supply_chain | Supply chain | все | 2 | нет |
| GS010 | gs010_ssh_hardening | SSH hardening | все | 2 | нет |
| GS011 | gs011_jwt_vulnerabilities | JWT misc | все | 2 | нет |
| GS012 | gs012_mass_assignment | Mass assignment | py/js | 2 | нет |
| GS013 | gs013_graphql_security | GraphQL | все | 2 | нет |
| GS014 | gs014_credential_exposure | Credential exposure | все | 2 | нет |
| GS015 | gs015_entry_points | Entry points | все | 2 | нет |
| GS016 | gs016_linux_priv_esc | Linux priv esc | все | 2 | нет |
| GS017 | gs017_weak_passwords | Weak passwords | все | 2 | нет |
| GS018 | gs018_payment_abuse | Payment abuse | все | 2 | нет |
| GS019 | gs019_auth_session | Auth/session | py/js | 2 | нет |
| GS020 | gs020_xss_injection | XSS injection | py/js/php/rb | 2 | нет |
| GS021 | gs021_csrf_ssrf | CSRF/SSRF | py/js | 2 | нет |
| GS022 | gs022_open_redirect | Open redirect | py/js | 2 | нет |
| GS023 | gs023_race_conditions | Race conditions | все | 2 | нет |
| GS024 | gs020_llm_sqli | **LLM SQLi (lazy)** | py | 2 | **ДА** |
| GS025 | gs025_ai_provenance | AI provenance | все | 2 | нет |
| GS028 | gs028_invariants | Invariants (opt-in) | все | 2 | нет |
| GS029 | gs029_secrets | Cross-repo secrets | все | 2 | нет |
| GS030 | gs030_sca | SCA (OSV.dev) | все | 2 | нет |
| GS031 | gs031_iac | IaC (Docker/K8s/TF) | Dockerfile/yml/tf | 2 | нет |
| GS032 | gs032_prompt_injection | Prompt injection | md/txt/py/js/ts | 2 | нет |
| GS033 | gs033_cicd | CI/CD anti-patterns | yml/yaml | 2 | нет |
| GS034 | gs034_supply_chain | npm supply chain | js/json | 2 | нет |
| GS035 | gs035_php | PHP vulns | php | 2 | нет |
| GS036 | gs036_nodejs | Node.js vulns | js/ts | 2 | нет |
| GS037 | gs037_python | Python vulns | py | 2 | нет |
| GS038 | gs038_go | Go vulns | go | 2 | нет |
| GS039 | gs039_ruby | Ruby vulns | rb | 2 | нет |

**Пропущены:** GS006, GS026, GS027

### 3.3. Структура GS005 (regex-образец, 463 строки)

```python
RULE_ID = "GS005"
ECHELON = 2
NOISE_TIER = "precise"

_PATTERNS: list[tuple[str, str, str, bool]] = [
    # (regex, title, language, needs_user_input_context)
    (r'(?:execute|cursor\.execute|conn\.execute)\s*\(\s*f[\"\']',
     "SQL f-string injection in execute()", "python", False),
    # ... 86 more patterns ...
]

def detect(ctx: AuditContext) -> list[Finding]:
    for fp in ctx.get_source_files():
        content = ctx.read_file(fp)
        for lineno, line in enumerate(lines, 1):
            line_findings = _detect_line(line, fp.name, fp)
            for f in line_findings:
                f["line_number"] = lineno
                # Downgrade CRITICAL if sanitizer present
                if f["severity"] == "CRITICAL" and "f-string" in f["title"]:
                    if _has_sanitizer(context): f["severity"] = "LOW"
                    elif not _has_taint_source(context): f["severity"] = "MEDIUM"
```

---

## БЛОК 4: Пайплайн — как детектор вызывается

### 4.1. `gsc.py scan` → `run_audit_echelons()` (в `gsc_external.py`)

Пайплайн: `clone → inventory → exclude → scan → LLM revalidate → score → report`

**Профили сканирования** (из `gsc_external.py:PROFILES`):
- `developer-review`: full, LLM 20 calls, CRITICAL+HIGH, disabled GS003/GS008/GS015
- `pr-gate`: diff-only, LLM 10 calls, blocking HIGH≥0.80
- `audit`: full, LLM 50 calls, all severities, all rules
- `precision-hunt`: full, только высокоточные детекторы

### 4.2. `registry.run_detectors(ctx, echelons)`

```python
def run_detectors(ctx, echelons=None) -> list[Finding]:
    all_findings = []
    for det in ALL_DETECTORS:
        if echelons and det.echelon not in echelons: continue
        if det.rule_id in ctx.skipped_detectors: continue
        all_findings.extend(det.detect(ctx))
    return all_findings
```

### 4.3. Как finding сохраняется в БД

```sql
-- gsc_db.py — таблица findings (schema 29)
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES audit_runs(id),
    project TEXT NOT NULL,
    echelon INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    detail TEXT,
    pattern_id INTEGER REFERENCES patterns(id),
    status TEXT DEFAULT 'open' CHECK(status IN ('open','confirmed','false_positive','fixed','by_design')),
    -- ... ещё 15 колонок (fingerprint, revalidation, confidence_score, current_state, etc.)
);
```

### 4.4. Где подключаются Blocking Engine / Compliance / EPSS

- **Blocking Engine**: `gsc_blocking.py:BlockingEngine.apply(findings, ...)` — после скана, мутирует findings
- **Compliance**: `gsc_compliance.py:enrich_finding(finding)` — вставляет CWE/OWASP/PCI в metadata
- **EPSS**: `gsc_epss.py` — отдельная команда `gsc epss --cve ...`, не встроен в scan

---

## БЛОК 5: Тестирование и калибровка

### 5.1. Тест на детектор — образец (`tests/test_corpus.py`)

```python
def scan_file(code, filename="test.py"):
    d = tempfile.mkdtemp()
    fpath = Path(d) / filename
    fpath.write_text(code)
    subprocess.run(["git", "-C", d, "init", "-q"], ...)
    subprocess.run(["git", "-C", d, "add", "-A"], ...)
    r = subprocess.run([sys.executable, GSC, "scan", d, "--ci", "--json"], ...)
    return json.loads(r.stdout)

def test_sql_injection():
    findings = scan_file('query = f"SELECT * FROM users WHERE id={uid}"\n')
    assert has_finding(findings, "sql", "CRITICAL")
```

**Паттерн теста:** `scan_file(код) → gsc.py scan --ci --json → проверка ключевых слов/severity`

### 5.2. Калибровка (`scripts/gsc_setup_calibration.py`)

```python
VULN = {
    "sqli-demo": ("py", 'db.execute(f"SELECT * FROM u WHERE id={x}")\n', "GS005"),
    "xss-demo": ("py", 'return f"<div>{name}</div>"\n', "GS017"),
    "secrets-demo": ("py", 'password = "SuperSecret123!"\n', "GS029"),
    # ... 9 проектов
}
CLEAN = {"clean-pure": ("py", 'def add(a: int, b: int) -> int:\n    return a + b\n')}
```

Структура: `/tmp/gsc-calibration/<name>/app.py` + `expected.json` `{"findings": [{"rule_id": "GSxxx"}]}`

### 5.3. Команды тестирования

```bash
python3 tests/test_corpus.py              # 8 базовых тестов
python3 -m pytest tests/ -v               # все тесты
python3 gsc.py scan /tmp/gsc-calibration/sqli-demo --ci --json  # один проект
python3 scripts/gsc_audit_groundtruth.py  # аудит
python3 scripts/gsc_benchmark_real.py --scan  # real-world benchmark
```

---

## БЛОК 6: БД и инварианты в коде

### 6.1. Схема БД (31 таблица)

```
audit_runs         file_state         pr_comments
awesome_patterns   finding_sightings  pr_feedback
bounty_examples    finding_states     publication_events
chains             findings           published_comments
comment_reactions  gsc_jobs           sca_cache
dast_findings      mutation_alerts    schema_version
epss_cache         negative_examples  secret_fingerprints
federated_deactivated  nuclei_templates  secret_sightings
federated_global_weights overrides    verify_results
federated_log      patterns           vrt_categories
                   detector_status
```

### 6.2. Инварианты, зашитые в код

**Инвариант #1 — finding_key** (в `base.py:make_finding`):
```python
key = hashlib.sha256(f"{rule_id}{file}{snippet}".encode()).hexdigest()[:12]
```

**Инвариант #2 — guard на rule_id** (в `base.py:make_finding`):
```python
if not rule_id or not str(rule_id).strip():
    return None  # caller must handle
```

**Инвариант #3 — Blocking Engine пороги** (в `gsc_blocking.py`):
```python
PHASE_THRESHOLDS = {
    "blocking-critical": [("CRITICAL", 0.90)],
    "blocking-standard": [("CRITICAL", 0.90), ("HIGH", 0.85)],
}
CHAIN_BLOCK_CONFIDENCE = 0.90
POC_BOOST = 0.05
POC_BOOST_CAP = 0.95
```

**Инвариант Shadow** (в `gsc_shadow_manager.py`):
```python
SHADOW_TO_FULL_VERDICTS = 10
SHADOW_TO_FULL_TP = 0.70
DEACTIVATE_TP = 0.30
```

**Инвариант Auto-degrade** (в `gsc_detectors/__init__.py` AuditContext):
```python
NON_CODE_GLOBS = ("*.svg", "*.png", ..., "*.min.js", "*.map")
TEST_GLOBS = ("test_*.py", "*_test.py", ...)
```

### 6.3. TODO/FIXME/HACK в коде

```python
gsc_external.py:168:    r"__TODO__", r"FIXME", r"REPLACE_ME"  # (паттерны, не баги)
gsc_collect_bounty.py:237:  if 'FIXME' in fixed_code or 'HACK' in fixed_code or 'TODO' in fixed_code:  # фильтр качества
gsc_detectors/gs001_hardcoded_secret.py:89:  placeholders = ("***", "your-", "xxxx", "changeme", "replace_me", "TODO")  # skip patterns
gsc_detectors/gs025_ai_provenance.py:28:  (r"(?:#|//)\s*TODO:\s*(?:review|verify|check|audit|harden|secure)\b", 0.15)  # detector
```

**Вывод: реальных TODO/FIXME-багов нет.** Все вхождения — это паттерны детекторов (ищут `TODO`/`FIXME` в коде пользователя) или фильтры качества bounty-примеров.

---

## ЧЕСТНЫЕ ПРОБЕЛЫ: что в доках, но не в коде

1. **"SAST+DAST+SCA+IaC+SBOM+SupplyChain — RELEASE"** — DAST есть (`gsc_dast_scanner.py`, `gsc_nuclei_export.py`), но требует запущенного приложения. SBOM генерирует CycloneDX, но не верифицирован на реальных проектах.
2. **"VSCode extension (v0.37)"** — каталог `gsc-vscode/` существует, но не проверялся в этой сессии.
3. **"SaaS S1–S4 🟢"** — `cloud/` содержит 30+ файлов (api_v2, tenancy, billing, sso, workers), но S2–S4 помечены как «pending».
4. **"Federated Learning"** — код есть (`gsc_federated.py`), но нет реальных федеративных узлов.
5. **"OWASP Benchmark"** — `benchmark/` содержит адаптер и scorer, но не прогонялся на OWASP Benchmark Suite.
6. **"Precision Report"** — `gsc_benchmark_real.py` склонировал 10 проектов, но скан не завершён.
7. **GS024 LLM-детектор** — lazy-loaded, требует DeepSeek API key, не проверялся на реальных данных.
8. **Proof-of-Fix sandbox** — `gsc_pof_sandbox.py` создан и smoke-test пройден, но не интегрирован в полный PoF-цикл.

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
| Tests | `~/gsc/tests/` |
| Calibration | `/tmp/gsc-calibration/` |
| Benchmark | `~/gsc/benchmark/real_world/` |
| API key | `~/.hermes/.env` → `DEEPSEEK_API_KEY` |
