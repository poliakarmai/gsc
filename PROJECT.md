# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.14 — GitHub PR Adapter + Calibration CI  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это

GSC — самообучающийся статический анализатор безопасности: plugin-детекторы (regex) + LLM (DeepSeek), SQLite, замкнутая петля самообучения. Ищет уязвимости в коде, ревалидирует через LLM, авто-деактивирует шумные паттерны.

| Версия | Ключевая фича |
|--------|---------------|
| v0.11 | External Scanner MVP (clone → scan → revalidate → report) |
| v0.12 | Profiles + V3 scoring + policy-as-code + report UX |
| v0.13 | PR Gate: diff mode, fingerprinting, exit codes |
| **v0.14** | **GitHub PR Adapter + Calibration CI** |

---

## 2. Файловая структура

```
~/gsc/
├── gsc.py                          ← CLI (22 команды, 1890 строк)
├── gsc_external.py                 ← External Scanner (1284 строки)
│                                     profiles, V3 scoring, diff mode, fingerprinting
├── gsc_github_adapter.py           ← GitHub PR adapter (300 строк)
│                                     PR URL → context → comment + check run + SARIF
├── gsc_revalidate.py               ← Structured revalidator
├── gsc_detectors/                  ← 23 детектора + GS024 LLM
├── calibration/
│   ├── calibration_dataset.json    ← 14 проектов (4 vuln + 10 clean)
│   ├── expected/*.json             ← Ожидаемые находки
│   └── reports/                    ← Результаты calibration
├── scripts/
│   ├── gsc_calibration.py          ← Calibration runner (300 строк)
│   ├── gsc_metrics.py gsc_pr_scanner.py gsc_self_learn.py ...
├── .github/workflows/
│   ├── gsc-pr-scan.yml
│   └── gsc-calibration.yml         ← Calibration CI
├── tests/test_corpus.py            ← 8/8
├── PROJECT.md AGENTS.md README.md
└── LICENSE

~/.hermes/scripts/gsc_self_learn.py ← Self-learning v2.0
~/.hermes/state/gsc_audit.db        ← SQLite WAL (391K находок)
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

## 4. Команды

```bash
# Полное сканирование
gsc external-scan https://github.com/user/repo --profile developer-review

# PR diff scan (v0.13)
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD --fail-on-blocking

# GitHub PR scan (v0.14)
gsc github-scan https://github.com/org/repo/pull/123 --dry-run
gsc github-scan https://github.com/org/repo/pull/123 --post-comment --fail-on-blocking
gsc github-scan . --github-context "$GITHUB_EVENT_PATH" --post-comment

# Calibration (v0.14)
gsc calibration run --fail-on-regression

# Отчёты + обратная связь
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json
gsc feedback 42 --verdict fp --reason "тестовый пароль"
```

---

## 5. Профили

| Профиль | LLM calls | Блокировка | Для чего |
|---------|:---------:|:----------:|----------|
| `developer-review` | 20 | ≥HIGH, 80% conf | Проверка проекта |
| `pr-gate` | 10 | ≥HIGH, 80% conf | PR gate (diff-only) |
| `audit` | 50 | ≥HIGH, 80% conf | Полный аудит |
| `candidate-review` | 15 | CRITICAL, 85% conf | Тестовое задание |

---

## 6. PR Gate — Diff Mode (v0.13)

```
git diff --name-status base...head
        ↓
changed files only → scan head → LLM only new CRITICAL/HIGH
        ↓
build base baseline (fingerprints, no LLM)
        ↓
DiffResult: new / unchanged / fixed / blocking / warning
        ↓
PR diff comment + exit code (0=pass, 1=blocking)
```

### Fingerprinting

- **Точный:** `sha256(rule+file+line+snippet)` — дедупликация
- **Мягкий:** `sha256(rule+file+normalized_snippet)` — устойчив к line moves

### Exit codes: `0`=pass, `1`=blocking (`--fail-on-blocking`)

---

## 7. GitHub PR Adapter (v0.14)

```
PR URL / GITHUB_EVENT_PATH
        ↓
parse GitHub context (base/head refs, PR number)
        ↓
clone → diff scan → V3 score
        ↓
comment upsert (по маркеру <!-- gsc:pr-scan:v1 -->)
        ↓
check run (conclusion: success/failure/action_required)
        ↓
SARIF path для GitHub Code Scanning
```

- `parse_pr_url()` / `parse_github_event()` → GitHubPRContext
- `find_existing_comment()` → upsert (не создаёт дубликаты)
- `create_check_run()` с annotations
- `--dry-run` — всё печатает, ничего не отправляет

---

## 8. Confidence V3: Signals-Based Scoring

```
base = 0.35 (без LLM — cap)
+ LLM verdict: TP→0.70, FP→0.05
+ TP signals: ≥3→+0.25, 2→+0.15, 1→+0.05
− FP signals: ≥2→cap 0.08, 1→×0.5
− File context: test_file→0.05, config→0.30
= confidence (0.0–1.0)
```

| Confidence | Status | Действие |
|:----------:|--------|----------|
| ≥ 0.80 | confirmed | Blocking if CRITICAL/HIGH |
| 0.55–0.79 | likely | Warning |
| 0.35–0.54 | uncertain | Manual review |
| < 0.35 | false-positive | Suppressed |

---

## 9. Calibration CI (v0.14)

### Результат: 14/14 ✅

| Группа | Проектов | Результат |
|--------|:--------:|-----------|
| Clean | 10 | 0 blocking, 0 redaction leaks, SARIF valid |
| Vuln | 4 | Все ожидаемые находки обнаружены |

### CI triggers

- PR в детекторы/scoring/revalidation/calibration
- Nightly 07:00 UTC
- `workflow_dispatch`

---

## 10. Self-Learning Engine v2

Ежедневно 04:00 МСК: 5 проектов → scan → LLM revalidate (50/день) → update stats → auto-deactivate (<30% TP).

---

## 11. Детекторы (23)

| Rule | Category | Тип | Описание |
|------|----------|-----|----------|
| GS001 | CRITICAL | regex | Hardcoded secrets |
| GS005 | CRITICAL | regex | SQL injection (87+ patterns) |
| GS007 | HIGH | regex | BAC/IDOR (35 patterns) |
| GS011 | CRITICAL | regex | JWT vulnerabilities |
| GS020 | CRITICAL | regex | XSS/SSTI (23 patterns) |
| GS021 | CRITICAL | regex | CSRF/SSRF (20 patterns) |
| **GS024** | **CRITICAL** | **LLM** | **LLM SQLi (пилот)** |

---

## 12. Ключевые решения

- **Framework-aware:** pickle+torch→downgrade, SQL+SQLAlchemy→downgrade
- **Resume:** FileStateManager, atomic locking
- **Auto-deactivation:** <30% precision при ≥10 вердиктов
- **GS024:** 87 regex → 1 DeepSeek call
- **Redaction:** API-ключи → `[REDACTED_*]` перед LLM и в отчётах
- **Fingerprinting:** soft fingerprint — устойчив к line moves
- **GitHub adapter:** upsert комментарий по маркеру, check run с conclusion

---

## 13. Метрики

### БД: 391 984 находок, 0 ревалидировано (первый цикл завтра 04:00)

### Corpus tests: 8/8 ✅

### Ground truth

| Проект | Всего | Реальных CRITICAL |
|--------|:-----:|:-----------------:|
| bybit-ws | 1647 | 0 |
| gsc | 720 | 0 |
| vpn-infra | 627 | 0 |

### Calibration: 14/14 ✅ (10 clean + 4 vuln)

---

## 14. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI, CI/CD, Качество, LLM, Self-learning v1 | ✅ |
| Deepsec upgrade (23 детектора, noise tiers) | ✅ |
| Self-learning v2 (LLM-ревалидация) | ✅ |
| GS024 LLM detector | ✅ |
| v0.11: External Scanner MVP | ✅ |
| v0.12: profiles, V3 scoring, policy, report UX | ✅ |
| Calibration set (14 проектов) | ✅ |
| v0.13: PR Gate — diff mode, fingerprinting, exit codes | ✅ |
| **v0.14: GitHub PR Adapter + Calibration CI** | ✅ |
| GitHub PR adapter (реальные API-вызовы в Actions) | 🔜 |
| Fork PR safe mode (без LLM для внешних PR) | 🔜 |
| Мультиязычность (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
