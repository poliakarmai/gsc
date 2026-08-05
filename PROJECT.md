# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.12 — Developer Project Reviewer  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это и зачем

GSC — самообучающийся статический анализатор безопасности. Ищет уязвимости через plugin-детекторы (regex) и LLM (DeepSeek), сохраняет находки в SQLite, накапливает паттерны, авто-деактивирует шумные.

**Главная фича:** замкнутая петля самообучения + confidence-based scoring для внешних проектов.

**v0.12 — Developer Project Reviewer:** profiles, V3 signals-based scoring, понятные отчёты, policy-as-code.

---

## 2. Файловая структура

```
~/gsc/
├── gsc.py                          ← CLI (19 команд: scan, external-scan, report, feedback…)
├── gsc_external.py                 ← External Scanner v0.12 (950 строк)
├── gsc_resume.py                   ← FileStateManager
├── gsc_revalidate.py               ← Structured revalidator (TP/FP/Fixed/Uncertain)
├── gsc_detectors/                  ← Plugin detector system (23 детектора)
│   ├── __init__.py                 ← AuditContext, Finding, Detector
│   ├── registry.py                 ← ALL_DETECTORS
│   ├── gs001..gs023_*.py           ← 22 regex-based детектора
│   └── gs020_llm_sqli.py           ← GS024: LLM SQLi detector
├── calibration/
│   └── calibration_dataset.json    ← 14 проектов (4 vuln + 10 clean)
├── patterns/ scripts/ tests/ .github/workflows/
├── PROJECT.md AGENTS.md README.md
└── LICENSE

~/.hermes/scripts/gsc_self_learn.py ← Self-learning v2.0
~/.hermes/state/gsc_audit.db        ← SQLite WAL (391K находок)
~/.gsc/projects.txt                 ← 53+ проекта для ротации
```

---

## 3. Алгоритм сканирования

Четыре эшелона:
```
E1: Source-driven → grep + precise детекторы (GS001, GS003, GS008, GS015)
E2: Security → regex + permissions + systemd + normal детекторы (GS002, GS004-024)
E3: Adversarial → semantic patterns (TOCTOU, float precision)
E4: LLM → DeepSeek-верификация CRITICAL/HIGH (флаг --deep)

Post-фильтры: docstring, framework-aware (torch/SQLAlchemy→downgrade),
               reachability, inline suppression (# gsc:ignore)
```

---

## 4. External Scanner v0.12 — главный продукт

### Pipeline

```
clone → inventory → exclude → scan → LLM revalidate → V3 score → report
```

### Профили

| Профиль | LLM calls | Блокировка | Для чего |
|---------|:---------:|:----------:|----------|
| `developer-review` | 20 | ≥HIGH, 80% conf | Проверка проекта разработчика |
| `pr-gate` | 10 | ≥HIGH, 80% conf | PR gate (diff-only) |
| `audit` | 50 | ≥HIGH, 80% conf | Полный аудит |
| `candidate-review` | 15 | CRITICAL, 85% conf | Тестовое задание кандидата |

### Команды

```bash
gsc external-scan https://github.com/user/repo --profile developer-review
gsc external-scan ./project --profile pr-gate --mode diff
gsc external-scan ./legacy --profile audit --baseline baseline.json
gsc report scan.json --format markdown
gsc feedback 42 --verdict fp --reason "тестовый пароль"
```

### Выход

```
reports/<repo>/<date>/
  report.md           ← читабельный отчёт
  scan.json           ← полные данные
  summary.json        ← машиночитаемая сводка
  report.sarif.json   ← для GitHub Code Scanning
```

### Policy-as-code: .gsc-audit.yml

```yaml
profile: developer-review
exclude: [tests/, docs/]
rules:
  GS003: {enabled: false}
thresholds:
  block_min_confidence: 0.85
llm:
  max_calls_per_project: 30
baseline: .gsc/baseline.json
```

---

## 5. Confidence V3: Signals-Based Scoring

**Ключевой инсайт:** LLM reasoning всегда правильный, verdict label — нет.
V3 доверяет structured signals, а не одному слову вердикта.

### TP-сигналы (15)

`real_hardcoded_secret`, `production_config`, `jwt_secret_hardcoded`, `sql_injection_confirmed`,
`no_parameterization`, `reachable_route`, `command_injection`, `secret_format_valid`,
`no_safe_api_used`, `endpoint_reachable`, `framework_does_not_protect`, `code_not_test`, ...

### FP-сигналы (25+)

`safe default`, `not a vulnerability`, `localhost`, `127.0.0.1`, `test code`, `test file`,
`false positive`, `not exploitable`, `intended behavior`, `by design`, `configuration file`,
`build script`, `docstring`, `placeholder_value`, `documentation_file`, ...

### Алгоритм

```
base = 0.35 (uncertain)
+ LLM verdict: true-positive → 0.70, false-positive → 0.05
+ TP signals: ≥3 → +0.25, 2 → +0.15, 1 → +0.05
− FP signals: ≥2 → cap 0.08, 1 → ×0.5
− File context: test_file → 0.05, config_without_secret → 0.30
= confidence (0.0–1.0)
```

### Review statuses

| Confidence | Status |
|:----------:|--------|
| ≥ 0.80 | **confirmed** (blocking if CRITICAL/HIGH) |
| 0.55–0.79 | **likely** (warning) |
| 0.35–0.54 | **uncertain** (manual review) |
| < 0.35 | **false-positive** (suppressed) |

---

## 6. Self-Learning Engine v2

Ежедневно 04:00 МСК:
1. 5 проектов из ротации (53+)
2. git clone --depth 1 --filter=blob:none
3. gsc scan → auto_triage (heuristic FP)
4. revalidate_findings (LLM, бюджет 50/день)
5. update_pattern_stats (TP/(TP+FP), <30% → deactivate)
6. auto_create_patterns (≥5 confirmed TP, inactive)

---

## 7. Revalidation Pipeline

```
±15 строк → heuristic pre-checks (test/doc/placeholder → FP)
→ git blame/log → LLM (DeepSeek structured JSON)
→ {verdict, confidence, reasoning} → save to DB
```

---

## 8. Детекторы (23)

| Rule | Echelon | Category | Noise | Тип | Описание |
|------|:------:|----------|:-----:|-----|----------|
| GS001 | 1 | CRITICAL | precise | regex | Hardcoded secrets |
| GS002 | 2 | HIGH | normal | regex | World-readable sensitive files |
| GS004 | 2 | HIGH | precise | regex | Dangerous subprocess/eval/exec |
| GS005 | 2 | CRITICAL | precise | regex | SQL injection (87+ patterns) |
| GS007 | 2 | HIGH | normal | regex | BAC/IDOR (35 patterns) |
| GS011 | 2 | CRITICAL | precise | regex | JWT vulnerabilities |
| GS016 | 2 | CRITICAL | normal | regex | Linux priv esc |
| GS017 | 2 | CRITICAL | normal | regex | Weak/default passwords |
| GS020 | 2 | CRITICAL | precise | regex | XSS/SSTI (23 patterns) |
| GS021 | 2 | CRITICAL | normal | regex | CSRF/SSRF (20 patterns) |
| **GS024** | **2** | **CRITICAL** | **precise** | **LLM** | **LLM SQLi (пилот)** |

*Полный список из 23 детекторов — см. раздел 8 предыдущей версии.*

---

## 9. Ключевые алгоритмические решения

- **Pattern loading:** EXT_TO_LANG (25 расширений), ripgrep -t
- **Framework-aware:** pickle+torch→downgrade, SQL+SQLAlchemy→downgrade
- **Resume:** FileStateManager, per-file state, atomic locking
- **Auto-deactivation:** <30% precision при ≥10 LLM-вердиктах → active=0
- **GS024 LLM Detector:** 87 regex → 1 DeepSeek call, confidence ≥70%
- **Redaction:** API-ключи → `[REDACTED_*]` перед LLM и в отчётах

---

## 10. Известные проблемы

- Precision на внешних проектах ~0% без LLM-ревалидации → V3 scoring решает
- `sqlite3.Row` не имеет `.get()` → только `row['key']`
- `.env` dotfiles — `Path.suffix == ''` → проверять по имени
- f-string в LLM-промптах → двойные фигурные скобки `{{...}}`

---

## 11. Метрики и бенчмарки

### Текущее состояние БД

| Метрика | Значение |
|---------|----------|
| Всего находок | 391 984 |
| Ревалидировано | 0 (старт завтра, 04:00) |
| Активных паттернов | 211 |
| Деактивировано | 178 |

### Corpus tests: 8/8 ✅

### Ground truth (свои проекты)

| Проект | Всего | CRITICAL | Реальных |
|--------|:-----:|:--------:|:--------:|
| bybit-ws | 1647 | 122 | 0 |
| gsc | 720 | 186 | 0 |
| vpn-infra | 627 | 2 | 0 |

### Calibration (14 проектов, V3 scoring)

| Проект | Тип | Blocking | Precision |
|--------|:---:|:--------:|:---------:|
| flask-jwt-auth | vuln | **2** 🚨 | JWT secret 95% conf |
| click | clean | **0** ✅ | — |
| flask | clean | **0** ✅ | — |

*V2→V3: было 78 false confirmed → 0 на чистых проектах.*

---

## 12. Как запустить

```bash
# External scan (основной)
gsc external-scan https://github.com/user/repo --profile developer-review

# Локальный проект
gsc external-scan ./my-project --profile audit

# Конвертация отчёта
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json

# Feedback
gsc feedback 42 --verdict fp --reason "тест"

# Self-learning
python3 ~/.hermes/scripts/gsc_self_learn.py --dry-run

# Corpus tests
cd ~/gsc && python3 tests/test_corpus.py    # 8/8

# БД
gsc db "SELECT review_status, COUNT(*) FROM findings GROUP BY 1"
gsc metrics
```

---

## 13. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI (scan/triage/explain/fix/dashboard) | ✅ |
| CI/CD (SARIF, diff-only, pre-commit, PR comments) | ✅ |
| Качество (corpus tests, фильтры) | ✅ |
| LLM (E4 deep analysis, gsc fix) | ✅ |
| Self-learning v1 (daily cycle) | ✅ |
| Deepsec upgrade (15→23 детекторов, noise tiers) | ✅ |
| Self-learning v2 (LLM-ревалидация, авто-деактивация) | ✅ |
| GS024 LLM detector (пилот) | ✅ |
| External Scanner v0.11 | ✅ |
| **v0.12: profiles, V3 scoring, policy, report UX** | ✅ |
| **Calibration (14 проектов, 99.4% precision)** | ✅ |
| PR mode (diff-only scan, GitHub PR gate) | 🔜 |
| Calibration CI (авто-тест на каждом PR) | 🔜 |
| Мультиязычность (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
