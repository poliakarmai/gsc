# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.15 — Real GitHub Operations & Safe Fork Mode  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это

GSC — самообучающийся статический анализатор безопасности: 23 plugin-детектора (regex) + LLM (DeepSeek), SQLite, замкнутая петля self-learning.

### Версии за сегодня

| v | Ключевая фича |
|----|---------------|
| v0.11 | External Scanner MVP |
| v0.12 | Profiles, V3 scoring, policy-as-code, report UX |
| v0.13 | PR Gate: diff mode, fingerprinting, exit codes |
| v0.14 | GitHub PR Adapter + Calibration CI (14/14) |
| **v0.15** | **Real GitHub API, fork safe mode, redaction audit, CI workflows** |

---

## 2. Файловая структура

```
~/gsc/
├── gsc.py                          ← CLI (22+ команд)
├── gsc_external.py                 ← External Scanner (1284 строки)
├── gsc_github_adapter.py           ← GitHub Adapter v0.15 (570 строк)
│                                     GitHubAPIClient, upsert, check runs, doctor, audit
├── gsc_revalidate.py               ← Structured revalidator
├── gsc_detectors/                  ← 23 детектора + GS024 LLM
├── calibration/
│   ├── calibration_dataset.json    ← 14 проектов
│   └── expected/*.json             ← Ожидаемые находки
├── scripts/
│   ├── gsc_calibration.py          ← Calibration runner
│   ├── gsc_metrics.py gsc_pr_scanner.py gsc_self_learn.py ...
├── .github/workflows/
│   ├── gsc-internal-pr.yml         ← Internal PR: LLM + comment + check + SARIF
│   ├── gsc-fork-safe.yml           ← Fork PR: regex-only, warn comment
│   └── gsc-calibration.yml         ← Calibration CI
├── tests/test_corpus.py            ← 8/8
├── PROJECT.md AGENTS.md README.md
└── LICENSE

~/.hermes/scripts/gsc_self_learn.py ← Self-learning v2.0
~/.hermes/state/gsc_audit.db        ← SQLite WAL (391K находок, старт ревалидации: завтра 04:00)
```

---

## 3. Команды — всё в одном месте

```bash
# ── Полное сканирование ──
gsc external-scan https://github.com/user/repo --profile developer-review

# ── PR diff scan ──
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD --fail-on-blocking

# ── GitHub PR (v0.15) ──
gsc doctor --github
gsc github-scan https://github.com/org/repo/pull/123 --dry-run
gsc github-scan https://github.com/org/repo/pull/123 --post-comment --create-check --fail-on-blocking
gsc github-scan . --github-context "$GITHUB_EVENT_PATH" --safe-mode --no-llm

# ── Отчёты + обратная связь ──
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json
gsc feedback 42 --verdict fp --reason "тестовый пароль"

# ── Качество ──
gsc calibration run --fail-on-regression
gsc metrics
cd ~/gsc && python3 tests/test_corpus.py   # 8/8
```

---

## 4. Профили

| Профиль | LLM calls | Блокировка | Для чего |
|---------|:---------:|:----------:|----------|
| `developer-review` | 20 | ≥HIGH, 80% conf | Проверка проекта |
| `pr-gate` | 10 | ≥HIGH, 80% conf | PR gate (diff-only) |
| `audit` | 50 | ≥HIGH, 80% conf | Полный аудит |
| `candidate-review` | 15 | CRITICAL, 85% conf | Тестовое задание |

---

## 5. PR Gate — Diff Mode (v0.13)

```
git diff --name-status base...head → changed files
→ scan head (LLM only new CRITICAL/HIGH)
→ build base baseline (fingerprints, no LLM)
→ DiffResult: new / unchanged / fixed / blocking / warning
→ exit code: 0=pass, 1=blocking
```

**Fingerprinting:** точный (rule+file+line+snippet) + мягкий (normalized, line-move устойчив).

---

## 6. GitHub PR Adapter (v0.15)

### GitHubAPIClient
- Rate limiting: `X-RateLimit-Remaining`, auto-wait при <20
- Retries: 429 (backoff), 5xx (2 attempts)
- Pagination: до 3×100 комментариев для поиска маркера

### Comment ops
- Маркер `<!-- gsc:pr-scan:v1 -->` → idempotent upsert
- Truncation: 60KB лимит, обрезает warnings при переполнении

### Check run
- Conclusion: `success` (pass) / `failure` (blocking) / `neutral` (safe mode) / `action_required` (error)
- Max 50 annotations per request

### Redaction audit
- 5 паттернов: API keys, AWS keys, private keys, credentials, email
- Проверяет comment + SARIF + check summary перед публикацией
- При утечке → exit 2, ничего не публикуется

### Fork safe mode (авто)
```
ctx.is_fork → safe_mode + no_llm + no blocking
Комментарий: "⚠️ Fork-safe (limited)"
Без DEEPSEEK_API_KEY
```

---

## 7. Confidence V3

```
base = 0.35 (без LLM — cap)
+ LLM verdict: TP→0.70, FP→0.05
+ TP signals: ≥3→+0.25, 2→+0.15, 1→+0.05
− FP signals: ≥2→cap 0.08, 1→×0.5
− File context: test→0.05, config→0.30
```
| Confidence | Status | Действие |
|:----------:|--------|----------|
| ≥ 0.80 | confirmed | Blocking (CRITICAL/HIGH) |
| 0.55–0.79 | likely | Warning |
| 0.35–0.54 | uncertain | Manual review |
| < 0.35 | false-positive | Suppressed |

---

## 8. CI Workflows (v0.15)

### Internal PR (`gsc-internal-pr.yml`)
```
Trigger: pull_request, same-repo
Действия: LLM scan → comment upsert → check run → SARIF upload
if: head.repo == base.repo
```

### Fork Safe (`gsc-fork-safe.yml`)
```
Trigger: pull_request, fork PR
Действия: regex-only scan → warn comment → neutral check
if: head.repo != base.repo
Без DEEPSEEK_API_KEY
```

### Calibration (`gsc-calibration.yml`)
```
Trigger: PR paths (detectors/scoring) + nightly 07:00 + dispatch
Действия: run calibration → fail on regression → upload artifacts
```

---

## 9. Calibration: 14/14 ✅

| Группа | Проектов | Результат |
|--------|:--------:|-----------|
| Clean | 10 | 0 blocking, 0 redaction leaks, SARIF valid |
| Vuln | 4 | Все ожидаемые находки обнаружены |

---

## 10. Self-Learning Engine v2

Ежедневно 04:00 МСК: 5 проектов → scan → LLM revalidate (50/день) → update stats → auto-deactivate (<30% TP при ≥10 вердиктах).

---

## 11. Детекторы (23)

| Rule | Category | Тип |
|------|----------|-----|
| GS001 | CRITICAL | regex — Hardcoded secrets |
| GS005 | CRITICAL | regex — SQL injection (87+ patterns) |
| GS011 | CRITICAL | regex — JWT vulnerabilities |
| GS020 | CRITICAL | regex — XSS/SSTI (23 patterns) |
| GS021 | CRITICAL | regex — CSRF/SSRF (20 patterns) |
| **GS024** | **CRITICAL** | **LLM — SQLi (пилот)** |

---

## 12. Метрики

- **БД:** 391 984 находок, 0 ревалидировано (старт завтра 04:00)
- **Corpus:** 8/8 ✅
- **Ground truth:** 0 реальных CRITICAL на своих проектах
- **Calibration:** 14/14 ✅
- **JWT secret:** 95% confidence, 3 TP signals

---

## 13. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI, CI/CD, Качество, LLM, Self-learning v1 | ✅ |
| Deepsec upgrade (23 детектора) | ✅ |
| Self-learning v2 | ✅ |
| GS024 LLM detector | ✅ |
| v0.11: External Scanner MVP | ✅ |
| v0.12: Profiles, V3 scoring, policy, report UX | ✅ |
| v0.13: PR Gate — diff mode, fingerprinting | ✅ |
| v0.14: GitHub adapter + Calibration 14/14 | ✅ |
| **v0.15: Real API, fork safe, redaction audit, CI** | ✅ |
| Production rollout (warn-only → blocking) | 🔜 |
| Multi-language (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
