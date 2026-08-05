# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.13 — PR Gate & Diff Mode  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это и зачем

GSC — самообучающийся статический анализатор безопасности: plugin-детекторы (regex) + LLM (DeepSeek), SQLite, замкнутая петля самообучения.

**v0.13 — PR Gate:** diff-only сканирование, fingerprinting, base baseline, exit codes.
**v0.12 — Developer Project Reviewer:** profiles, V3 scoring, policy-as-code, отчёты.

---

## 2. Файловая структура

```
~/gsc/
├── gsc.py                          ← CLI (19+ команд)
├── gsc_external.py                 ← External Scanner v0.13 (1284 строки)
│                                     profiles, V3 scoring, diff mode, fingerprinting
├── gsc_revalidate.py               ← Structured revalidator
├── gsc_detectors/                  ← 23 детектора + GS024 LLM
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

```
E1: Source-driven → grep + precise детекторы
E2: Security → regex + permissions + normal детекторы
E3: Adversarial → semantic patterns
E4: LLM → DeepSeek-верификация CRITICAL/HIGH (--deep)

Post-фильтры: docstring, framework-aware, reachability, inline suppression
```

---

## 4. External Scanner — профили

| Профиль | LLM calls | Блокировка | Для чего |
|---------|:---------:|:----------:|----------|
| `developer-review` | 20 | ≥HIGH, 80% conf | Проверка проекта |
| `pr-gate` | 10 | ≥HIGH, 80% conf | PR gate (diff-only) |
| `audit` | 50 | ≥HIGH, 80% conf | Полный аудит |
| `candidate-review` | 15 | CRITICAL, 85% conf | Тестовое задание |

### Команды

```bash
# Full scan
gsc external-scan https://github.com/user/repo --profile developer-review

# PR diff scan (v0.13)
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD --fail-on-blocking

# Отчёты
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json

# Feedback
gsc feedback 42 --verdict fp --reason "тестовый пароль"
```

### Policy-as-code (.gsc-audit.yml)

```yaml
profile: pr-gate
mode: diff
thresholds:
  block_min_confidence: 0.85
  block_min_severity: HIGH
llm:
  max_calls_per_project: 30
rules:
  GS003: {enabled: false}
```

---

## 5. PR Gate — Diff Mode (v0.13)

### Pipeline

```
git diff --name-status base...head
        ↓
changed files only
        ↓
scan head changed files (LLM only for new CRITICAL/HIGH)
        ↓
build base baseline (fingerprints, no LLM)
        ↓
fingerprint compare (soft — normalized snippet)
        ↓
DiffResult: new / unchanged / fixed / blocking / warning
        ↓
PR diff comment + exit code
```

### Fingerprinting

- **Точный:** `sha256(rule_id + file + line + snippet)` → дедупликация точных повторов
- **Мягкий:** `sha256(rule_id + file + normalized_snippet)` → устойчив к line moves
- **Normalize:** strip comments, collapse whitespace, replace literals → `"..."`

### DiffResult

```
new_findings        ← находки, которых нет в base
unchanged_findings  ← уже были в base (подавляются в PR)
fixed_findings      ← были в base, отсутствуют в head
blocking_findings   ← new + confirmed + CRITICAL/HIGH + conf ≥ 80%
warning_findings    ← new + confirmed/likely + conf ≥ 55%
```

### Exit codes

```
0 → pass (нет blocking findings)
1 → blocking (требует --fail-on-blocking)
```

### PR diff comment

```
## 🔒 GSC Security Scan
Profile: pr-gate · Base: main → Head: feature/api
Changed: 14 files · New: 5 · Blocking: 2 · Warnings: 3

### 🚨 Blocking
| Rule | Severity | Confidence | File | Risk |
| GS005 | CRITICAL | 87% | app/api/users.py:42 | 87/100 |

### ⚠️ Warnings
...

<details><summary>🔧 1 fixed finding(s)</summary>
...
</details>
```

---

## 6. Confidence V3: Signals-Based Scoring

### Алгоритм

```
base = 0.35 (uncertain, без LLM — cap)
+ LLM verdict: true-positive → 0.70, false-positive → 0.05
+ TP signals: ≥3 → +0.25, 2 → +0.15, 1 → +0.05
− FP signals: ≥2 → cap 0.08, 1 → ×0.5
− File context: test_file → 0.05, config_without_secret → 0.30
= confidence (0.0–1.0)
```

### Review statuses

| Confidence | Status | Действие |
|:----------:|--------|----------|
| ≥ 0.80 | **confirmed** | Blocking if CRITICAL/HIGH |
| 0.55–0.79 | **likely** | Warning |
| 0.35–0.54 | **uncertain** | Manual review |
| < 0.35 | **false-positive** | Suppressed |

### Signals (40+)

**TP:** `real_hardcoded_secret`, `production_config`, `jwt_secret_hardcoded`, `sql_injection_confirmed`, `no_parameterization`, `reachable_route`, `command_injection`...

**FP:** `safe default`, `not a vulnerability`, `localhost`, `127.0.0.1`, `test file`, `false positive`, `by design`, `configuration file`, `docstring`, `placeholder_value`...

---

## 7. Self-Learning Engine v2

Ежедневно 04:00 МСК: 5 проектов → scan → LLM revalidate (50/день) → update stats → auto-deactivate (<30% TP).

---

## 8. Revalidation Pipeline

±15 строк → heuristic pre-checks → git blame → LLM DeepSeek → {verdict, confidence, reasoning} → save to DB.

---

## 9. Детекторы (23)

| Rule | Category | Тип | Описание |
|------|----------|-----|----------|
| GS001 | CRITICAL | regex | Hardcoded secrets |
| GS005 | CRITICAL | regex | SQL injection (87+ patterns) |
| GS007 | HIGH | regex | BAC/IDOR (35 patterns) |
| GS011 | CRITICAL | regex | JWT vulnerabilities |
| GS016 | CRITICAL | regex | Linux priv esc |
| GS020 | CRITICAL | regex | XSS/SSTI (23 patterns) |
| GS021 | CRITICAL | regex | CSRF/SSRF (20 patterns) |
| **GS024** | **CRITICAL** | **LLM** | **LLM SQLi (пилот)** |

(полный список — 23 детектора, 4 echelon'а, 3 noise tier'а)

---

## 10. Ключевые решения

- **Framework-aware:** pickle+torch→downgrade, SQL+SQLAlchemy→downgrade
- **Resume:** FileStateManager, atomic locking
- **Auto-deactivation:** <30% precision при ≥10 вердиктов → active=0
- **GS024:** 87 regex → 1 DeepSeek call
- **Redaction:** API-ключи → `[REDACTED_*]` перед LLM
- **Fingerprinting (v0.13):** soft fingerprint — устойчив к line moves

---

## 11. Метрики

### БД

| Метрика | Значение |
|---------|----------|
| Всего находок | 391 984 |
| Ревалидировано | 0 (первый цикл завтра 04:00) |
| Активных паттернов | 211 |
| Деактивировано | 178 |

### Corpus: 8/8 ✅

### Ground truth

| Проект | Всего | CRITICAL | Реальных |
|--------|:-----:|:--------:|:--------:|
| bybit-ws | 1647 | 122 | 0 |
| gsc | 720 | 186 | 0 |
| vpn-infra | 627 | 2 | 0 |

### Calibration (14 проектов)

| Проект | Тип | V3 Blocking | Результат |
|--------|:---:|:-----------:|-----------|
| flask-jwt-auth | vuln | 2 🚨 | JWT secret 95% conf |
| click | clean | 0 ✅ | — |
| flask | clean | 0 ✅ | — |

### PR Gate (v0.13)

| Сценарий | Changed | New | Blocking |
|----------|:-------:|:---:|:--------:|
| gsc HEAD~1→HEAD | 2 | 0 | 0 ✅ |
| flask-jwt-auth +secret | 1 | 2 | 0 (test file) |

---

## 12. Как запустить

```bash
# Full scan
gsc external-scan https://github.com/user/repo --profile developer-review

# PR diff scan (v0.13)
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD --fail-on-blocking

# Отчёты
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json

# Feedback
gsc feedback 42 --verdict fp --reason "тест"

# Self-learning
python3 ~/.hermes/scripts/gsc_self_learn.py --dry-run

# Тесты
cd ~/gsc && python3 tests/test_corpus.py    # 8/8

# БД
gsc db "SELECT review_status, COUNT(*) FROM findings GROUP BY 1"
gsc metrics
```

---

## 13. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI, CI/CD, Качество, LLM, Self-learning v1 | ✅ |
| Deepsec upgrade (23 детектора, noise tiers) | ✅ |
| Self-learning v2 (LLM-ревалидация) | ✅ |
| GS024 LLM detector | ✅ |
| External Scanner v0.11 | ✅ |
| **v0.12: profiles, V3 scoring, policy, report UX** | ✅ |
| Calibration set (14 проектов, precision 99.4%) | ✅ |
| **v0.13: PR Gate — diff mode, fingerprinting, exit codes** | ✅ |
| GitHub PR adapter (API comments, SARIF upload) | 🔜 |
| Calibration CI (авто-тест на каждом PR) | 🔜 |
| Мультиязычность (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
