# GSC Feature List

> Статус: 2026-08-05 · 17 коммитов · 6 версий за день (v0.11 → v0.16)

---

## Must-have features — статус реализации

| # | Feature | Status | Где |
|---|---------|:------:|-----|
| 1 | **Finding key** — stable ID для feedback + dedup | ✅ | `gsc_external.py` L1013-1018, `sha256[:12]` |
| 2 | **Redaction audit** — блокировка при утечке секретов | ✅ | `gsc_github_adapter.py` L320-355, 5 паттернов |
| 3 | **Fork-safe mode** — no LLM, no blocking, limited comment | ✅ | `gsc_github_adapter.py` — авто `ctx.is_fork` |
| 4 | **Structured revalidation** — second-pass LLM + schema | ✅ | `gsc_revalidate.py` — 5-step pipeline |
| 5 | **Feedback loop** — gsc feedback + self-learning | ✅ | `gsc_external.py` CLI, `feedback.jsonl`, `gsc_self_learn.py` |
| 6 | **Rollout phases** — warn-only, blocking-critical, standard | ✅ | `.gsc-audit.yml` `rollout_phase`, `merge_policy()` |
| 7 | **Rollout metrics** — FP rate, confirmation, coverage | ✅ | `scripts/gsc_rollout_metrics.py` |
| 8 | **Idempotent PR comment upsert** — update, не spam | ✅ | `gsc_github_adapter.py` — маркер `<!-- gsc:pr-scan:v1 -->` |
| 9 | **SARIF export** — GitHub Code Scanning | ✅ | `gsc_external.py` `generate_sarif()`, partialFingerprints |
| 10 | **Check-run status mapping** — success/neutral/failure/action_required | ✅ | `gsc_github_adapter.py` `conclusion_from_result()` |
| 11 | **Corpus calibration CLI** — regression tests | ✅ | `scripts/gsc_calibration.py` — 14/14, `--fail-on-regression` |
| 12 | **Policy-as-code profiles** — 4 профиля | ✅ | `gsc_external.py` `PROFILES`, `.gsc-audit.yml` |
| 13 | **Auto-deactivation** — noisy rules below TP threshold | ✅ | `gsc_self_learn.py` — <30% TP при ≥10 вердиктах |
| 14 | **Multi-language detectors** — Go, TS, Rust, Java | ✅ | `gsc_detectors/multi_lang.py` → Step 3.5 в `gsc_external.py` |
| 15 | **VSCode extension hooks** | 📋 | Будущее |

---

## Nice-to-have — статус

| Feature | Статус |
|---------|:------:|
| Explainable finding cards (rule, snippet, severity, confidence, remediation) | ✅ Markdown-отчёт |
| Team baselines per repository | ✅ `.gsc/baseline.json` |
| Secret-classification tags | ✅ `confidence_signals` |
| Attack-path grouping | 📋 |
| Safe mode for external repos | ✅ Fork-safe |
| Finding-key based feedback links | ✅ `gsc feedback <key>` |

---

## Файловая структура

```
~/gsc/
├── gsc.py                       ← CLI (22+ команд)
├── gsc_external.py              ← External Scanner (1318 строк)
│                                   profiles, V3 scoring, finding_key, diff mode, fingerprinting
├── gsc_github_adapter.py        ← GitHub Adapter (570 строк)
│                                   GitHubAPIClient, upsert, check runs, doctor, redaction audit
├── gsc_revalidate.py            ← Structured revalidator (5-step)
├── gsc_detectors/               ← 47 детекторов (43 registry + 4 движка)
├── calibration/
│   ├── calibration_dataset.json ← 14 проектов
│   └── expected/*.json          ← Ожидаемые находки
├── scripts/
│   ├── gsc_calibration.py       ← Calibration runner
│   ├── gsc_rollout_metrics.py   ← Rollout метрики
│   ├── gsc_metrics.py           ← Precision/recall
│   ├── gsc_self_learn.py (symlink)
│   ├── gsc_pr_scanner.py        ← PR comment scanner
│   ├── gsc_baseline.py          ← Baseline suppressions
│   ├── framework_aware.py       ← AST-фильтр
│   └── gsc_github_dorks.py      ← Dorks scanner
├── .github/workflows/
│   ├── gsc-internal-pr.yml      ← Internal PR: LLM + comment + check + SARIF
│   ├── gsc-fork-safe.yml        ← Fork: regex-only + warn
│   ├── gsc-calibration.yml      ← CI: PR paths + nightly
│   └── gsc-pr-scan.yml          ← Legacy PR scanner
├── tests/test_corpus.py         ← 8/8
├── patterns/ corpus/
├── PROJECT.md AGENTS.md README.md
└── LICENSE

~/.hermes/
├── scripts/gsc_self_learn.py    ← Self-learning v2.0 (514 строк)
└── state/gsc_audit.db           ← SQLite WAL (~480K находок)
```

---

## Ключевые алгоритмы

### Confidence V3 (signals-based)

```python
base = 0.35                        # без LLM — cap
+ LLM verdict: TP→0.70, FP→0.05
+ TP signals: ≥3→+0.25, 2→+0.15, 1→+0.05
− FP signals: ≥2→cap 0.08, 1→×0.5
− File context: test_file→0.05, config→0.30
= confidence (0.0–1.0)
```

40+ signals: `real_hardcoded_secret`, `jwt_secret_hardcoded`, `safe default`, `localhost`, ...

### Finding key

```python
key = sha256(rule_id + file_path + snippet)[:12]  # stable, diff-safe
```

### Diff mode fingerprinting

```python
exact_fp = sha256(rule + file + line + snippet)     # dedup
soft_fp  = sha256(rule + file + normalized_snippet) # line-move resistant
```

### Redaction audit (5 patterns)

```python
API keys (sk-*)  |  AWS keys (AKIA*)  |  Private keys  |  Credentials  |  Email
```

### Rollout phases

```yaml
rollout_phase: warn-only           # fail_on_blocking=false
rollout_phase: blocking-critical   # CRITICAL only, ≥90%
rollout_phase: blocking-standard   # HIGH, ≥85%
```

### PR comment upsert

```
find_existing_comment(marker) → PATCH if found, POST if not
marker: <!-- gsc:pr-scan:v1 -->
max_bytes: 60000
```

### Check run conclusions

```
pass → success
blocking → failure
safe mode → neutral
error → action_required
```

---

## Production readiness

```
✅ 8/8 corpus tests
✅ 14/14 calibration (10 clean + 4 vuln)
✅ DB backup created
✅ finding_key + gsc feedback
✅ rollout_phase policy
✅ gsc metrics --rollout
⚠️ Self-learning: 0 ревалидировано (первый цикл завтра 04:00)
```

---

## Rollout plan

```
Phase 0: ✅ Readiness check
Phase 1: 🔜 Dry-run CI (workflows готовы)
Phase 2: 🔜 Warn-only comments (rollout_phase: warn-only)
Phase 3: 🔜 Feedback collection
Phase 4: 🔜 Blocking CRITICAL (rollout_phase: blocking-critical)
Phase 5: 🔜 Blocking CRITICAL+HIGH (rollout_phase: blocking-standard)
```

---

## Roadmap

| Фаза | Статус |
|------|:-----:|
| CLI, CI/CD, Self-learning v1, Deepsec upgrade | ✅ |
| GS024 LLM detector | ✅ |
| v0.11–v0.16: full pipeline (17 коммитов) | ✅ |
| Production rollout (warn-only → blocking) | 🔜 |
| Multi-language (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Marketplace | 📋 |
| Enterprise (Helm, SSO) | 📋 |
