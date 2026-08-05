# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.16 — Production Rollout & Learning Loop  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это

GSC — самообучающийся статический анализатор безопасности: 23 plugin-детектора + LLM (DeepSeek), SQLite, замкнутая петля self-learning. Ищет уязвимости, ревалидирует через LLM, авто-деактивирует шумные паттерны.

### Версии за сегодня (17 коммитов)

| v | Ключевая фича |
|----|---------------|
| v0.11 | External Scanner MVP |
| v0.12 | Profiles, V3 scoring, policy-as-code, report UX |
| v0.13 | PR Gate: diff mode, fingerprinting, exit codes |
| v0.14 | GitHub PR Adapter + Calibration CI (14/14) |
| v0.15 | Real GitHub API, fork safe mode, redaction audit, CI workflows |
| **v0.16** | **finding_key, rollout_phase, feedback loop, rollout metrics** |

---

## 2. Файловая структура

```
~/gsc/
├── gsc.py                          ← CLI (22+ команд)
├── gsc_external.py                 ← External Scanner v0.16
├── gsc_github_adapter.py           ← GitHub Adapter v0.15 (570 строк)
├── gsc_revalidate.py               ← Structured revalidator
├── gsc_detectors/                  ← 23 детектора + GS024 LLM
├── calibration/
│   ├── calibration_dataset.json    ← 14 проектов
│   ├── expected/*.json             ← Ожидаемые находки
│   └── reports/                    ← Результаты
├── scripts/
│   ├── gsc_calibration.py          ← Calibration runner
│   ├── gsc_rollout_metrics.py      ← 🆕 Rollout metrics
│   ├── gsc_metrics.py gsc_self_learn.py ...
├── .github/workflows/
│   ├── gsc-internal-pr.yml         ← Internal PR
│   ├── gsc-fork-safe.yml           ← Fork safe
│   └── gsc-calibration.yml         ← Calibration CI
├── tests/test_corpus.py            ← 8/8
├── PROJECT.md AGENTS.md README.md
└── LICENSE

~/.hermes/scripts/gsc_self_learn.py ← Self-learning v2.0
~/.hermes/state/gsc_audit.db        ← SQLite (400K находок)
```

---

## 3. Все команды

```bash
# Full scan
gsc external-scan https://github.com/user/repo --profile developer-review

# PR diff scan
gsc external-scan ./repo --profile pr-gate --mode diff --base main --head HEAD --fail-on-blocking

# GitHub PR
gsc doctor --github
gsc github-scan https://github.com/org/repo/pull/123 --dry-run
gsc github-scan https://github.com/org/repo/pull/123 --post-comment --create-check --fail-on-blocking
gsc github-scan . --github-context "$GITHUB_EVENT_PATH" --safe-mode --no-llm

# Reports + feedback
gsc report scan.json --format markdown
gsc report scan.json --format sarif -o report.sarif.json
gsc feedback abc123def456 --verdict fp --reason "test fixture"

# Quality
gsc calibration run --fail-on-regression
gsc metrics --rollout                    # 🆕 v0.16
cd ~/gsc && python3 tests/test_corpus.py  # 8/8
```

---

## 4. Profiles + rollout_phase

| Профиль | LLM calls | Блокировка | Для чего |
|---------|:---------:|:----------:|----------|
| `developer-review` | 20 | ≥HIGH, 80% | Проверка проекта |
| `pr-gate` | 10 | ≥HIGH, 80% | PR gate |
| `audit` | 50 | ≥HIGH, 80% | Полный аудит |
| `candidate-review` | 15 | CRITICAL, 85% | Тестовое задание |

### Rollout phases (.gsc-audit.yml)

```yaml
rollout_phase: warn-only           # комментарии без блокировки
rollout_phase: blocking-critical   # только CRITICAL ≥90%
rollout_phase: blocking-standard   # HIGH ≥85%
```

---

## 5. PR Gate + GitHub Adapter

```
git diff base...head → changed files → diff scan → V3 score
→ finding_key → redaction audit → comment upsert → check run → SARIF
→ exit: 0=pass, 1=blocking, 2=error
```

- **Comment:** idempotent (`<!-- gsc:pr-scan:v1 -->`), 60KB truncation
- **Check run:** success/failure/neutral/action_required
- **Fork safe:** авто no-LLM + no-blocking + limited comment
- **Redaction audit:** 5 паттернов, проверка до публикации

---

## 6. Confidence V3

| Confidence | Status | Действие |
|:----------:|--------|----------|
| ≥ 0.80 | confirmed | Blocking (CRITICAL/HIGH) |
| 0.55–0.79 | likely | Warning |
| 0.35–0.54 | uncertain | Manual review |
| < 0.35 | false-positive | Suppressed |

### finding_key (v0.16)

`sha256(rule+file+snippet)[:12]` — стабильный ID в PR comment для `gsc feedback <key>`.

---

## 7. CI Workflows

| Workflow | Trigger | Действие |
|----------|---------|----------|
| `gsc-internal-pr.yml` | same-repo PR | LLM + comment + check + SARIF |
| `gsc-fork-safe.yml` | fork PR | regex-only + warn comment |
| `gsc-calibration.yml` | PR paths + nightly | 14/14 calibration |

---

## 8. Calibration: 14/14 ✅

10 clean (0 blocking) + 4 vuln (все находки обнаружены).

---

## 9. Production Readiness (v0.16)

```
✅ 8/8 corpus tests
✅ 14/14 calibration
✅ DB backup created
✅ finding_key + gsc feedback
✅ rollout_phase policy
✅ gsc metrics --rollout
⚠️ Self-learning: 0 ревалидировано (первый цикл завтра 04:00)
```

### Rollout plan

```
Phase 0: ✅ Readiness check
Phase 1: 🔜 Dry-run CI
Phase 2: 🔜 Warn-only comments (rollout_phase: warn-only)
Phase 3: 🔜 Feedback collection
Phase 4: 🔜 Blocking CRITICAL (rollout_phase: blocking-critical)
Phase 5: 🔜 Blocking CRITICAL+HIGH (rollout_phase: blocking-standard)
```

---

## 10. Self-Learning Engine v2

Ежедневно 04:00 МСК: 5 проектов → scan → LLM revalidate (50/день) → update stats → auto-deactivate (<30% TP при ≥10 вердиктах).

---

## 11. Метрики

- **БД:** 400K находок, 0 ревалидировано
- **Corpus:** 8/8 ✅
- **Calibration:** 14/14 ✅
- **JWT secret:** 95% confidence

---

## 12. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI, CI/CD, Self-learning v1, Deepsec, GS024 | ✅ |
| v0.11–v0.16: full pipeline (5 версий за день) | ✅ |
| Production rollout (warn-only → blocking) | 🔜 |
| Multi-language (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
