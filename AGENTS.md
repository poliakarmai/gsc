# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — production security scanner.
> Обновлено: 2026-08-06 (v0.26 — Blocking CRITICAL+HIGH, rollout Phase 5 complete)
>
> **Версия:** v0.26 | **Детекторов:** 25 | **Schema:** 23 | **Файлов:** ~35
> **Статус:** Production — blocking-standard

## Что это

GSC — production-сканер безопасности с LLM-ревалидацией. 
25 детекторов (GS001–GS025 + GS028), PoC Auto-Generation, 
Exploit Chain Composer, Temporal Mutation Tracker, Security Invariant Engine,
Blocking Engine с авто-политикой на основе вердиктов сообщества.

**Быстрый старт:** `gsc external-scan /path/to/repo --profile developer-review`

## Структура

```
gsc/
├── gsc.py                ← CLI (30+ команд)
├── gsc_external.py       ← External Scanner v0.26
├── gsc_github_adapter.py ← GitHub PR Adapter (priority truncation)
├── gsc_blocking.py       ← v0.25/26 Blocking Engine
├── gsc_poc_generator.py  ← v0.17 PoC Auto-Generation
├── gsc_chain_composer.py ← v0.18/v0.21 Exploit Chain Composer
├── gsc_mutation_tracker.py ← v0.19 Temporal Mutation Tracker
├── gsc_invariant_engine.py ← v0.20 Security Invariant Engine
├── gsc_ast_dataflow.py   ← v0.21 Python AST taint tracking
├── gsc_revalidate.py     ← Structured LLM revalidator
├── gsc_db.py             ← SQLite wrapper, schema 23
├── gsc_detectors/        ← 25 детекторов (GS001–GS028)
├── calibration/          ← 17 проектов (11 clean + 6 vuln)
├── scripts/              ← dry-run, feedback, metrics, self-learning
├── .github/workflows/    ← 5 CI workflows
├── tests/test_corpus.py  ← 67/67
└── PROJECT.md AGENTS.md README.md LICENSE
```

## Как запускать

```bash
cd ~/gsc

# Основной скан (regex + LLM)
python3 gsc_external.py scan <repo> --profile developer-review

# Diff-режим (только изменения)
python3 gsc_external.py scan . --mode diff --base origin/main --head HEAD

# С доп. фичами
gsc external-scan <repo> --with-poc --with-chains --fail-on-blocking

# GitHub PR
gsc github-scan <pr-url> --post-comment --create-check

# Вердикты (из PR или CLI)
gsc feedback <finding_key> --verdict tp|fp|fixed
# или в PR-комментарии: /gsc fp <key> причина

# Метрики
gsc metrics --rollout | --detectors
gsc rollout report
python3 tests/test_corpus.py         # 67/67
```

## Архитектура

```
external-scan → regex detectors (24) → LLM revalidate (DeepSeek)
  ├── PoC Generator (curl exploit for confirmed findings)
  ├── Chain Composer (SQLi→RCE, SSRF→IDOR chains)
  ├── Mutation Tracker (рецидивы «починенных» уязвимостей)
  ├── Invariant Engine (policy-as-code, AST taint)
  └── Blocking Engine (CRITICAL≥90%, HIGH≥85%, auto-policy)
```

### Plugin Detector System (v0.9 — 18 detectors)

| Rule | Tier | Category | Description |
|------|:----:|----------|-------------|
| GS001 | precise | CRITICAL | Hardcoded secrets (API keys, tokens, passwords, PAN/CVV/Track/IBAN) |
| GS002 | normal | HIGH | World-readable sensitive files |
| GS003 | normal | LOW | Debug/diagnostic code (print, console.log) |
| GS004 | precise | HIGH | Dangerous subprocess (shell=True, eval, exec) |
| GS005 | precise | CRITICAL | SQL injection (f-strings, raw SQL) |
| GS007 | normal | HIGH | Broken Access Control — IDOR, fintech-IDOR, cross-tenant, admin panels, file downloads, ticket operations (35 patterns) |
| GS008 | normal | LOW | Dead code — constants never used |
| GS009 | normal | HIGH | Supply chain (Bumblebee scanner) |
| GS010 | precise | CRITICAL | Weak SSH config (PermitRootLogin, LD_PRELOAD) |
| GS011 | precise | CRITICAL | JWT vulnerabilities (alg:none, weak secrets) |
| GS012 | normal | HIGH | Mass Assignment (Django/FastAPI/Rails/GraphQL) |
| GS013 | normal | HIGH | GraphQL security (introspection, depth limiting) |
| GS014 | precise | HIGH | Credential exposure (SAM, DPAPI, unattend, sudoers) |
| GS015 | noisy | INFO | Entry-point coverage (all HTTP handlers → AI review) |
| GS016 | normal | CRITICAL | Linux privilege escalation (SUID, sudo NOPASSWD, cron hijack) |
| GS017 🆕 | normal | CRITICAL | Weak/default passwords (admin:admin, Docker defaults, MD5/SHA1) |
| GS018 🆕 | normal | CRITICAL | Payment logic abuse (idempotency, promo locking, balance races, webhook sigs) |
| GS019 🆕 | normal | HIGH | Auth/session weaknesses (SMS exhaustion, session fixation, JWT, OTP brute-force) |
| GS020 🆕🆕 | precise | CRITICAL | XSS/HTML/SSTI injection (reflected, stored, DOM, template) — 23 patterns |
| GS021 🆕🆕 | normal | CRITICAL | CSRF/SSRF (missing tokens, internal URL fetches, metadata endpoints) — 20 patterns |
| GS022 🆕🆕 | normal | HIGH | Open Redirect (redirect/url/next params, validation bypass) — 13 patterns |
| GS023 🆕🆕 | noisy | HIGH | Race Conditions (TOCTOU, double-spend, async races, coupon abuse) — 16 patterns |

### Noise Tiers (Deepsec-inspired)

| Tier | When | Processing |
|------|------|------------|
| `precise` | Pattern is unambiguous | Processed first (highest signal/token) |
| `normal` | Pattern is broader; needs disambiguation | Default tier |
| `noisy` | Every file matching glob must be AI-reviewed | Entry-point coverage (GS015) |

### Resume Mechanism

```python
# Per-file state tracking in SQLite
from gsc_resume import FileStateManager
fsm = FileStateManager(db_path, project, run_id)
fsm.init_files(code_files)           # mark all files
pending = fsm.get_pending_files()    # files to scan
fsm.mark_scanned(file_path, count)   # file done
fsm.mark_processed(file_path, count) # AI done

# CLI: gsc scan --resume → skips already-scanned files
# CLI: gsc status → progress: 45/200 (22.5%)
```

### Structured Revalidate

```python
from gsc_revalidate import Revalidator
rev = Revalidator(db_path, project_path)

result = rev.revalidate_finding(finding, use_llm=True)
# → {revalidation_verdict: "true-positive", reasoning: "..."}
# → {revalidation_verdict: "false-positive", reasoning: "test config"}
# → {revalidation_verdict: "fixed", reasoning: "patched in abc123"}
# → {revalidation_verdict: "uncertain", reasoning: "needs manual review"}

stats = rev.get_stats()
# → {true-positive: 3, false-positive: 12, fp_rate: 66.7%}
```

Heuristic pre-checks (free, no LLM):
1. File no longer exists → `fixed`
2. Test/demo/fixture files → `false-positive`
3. Documentation files → `false-positive`
4. Template/example configs → `false-positive`
5. Placeholder values → `false-positive`

Git history check: `git blame` + `git log` to detect recent fixes.

### Adding a Detector

1. Create `gsc_detectors/gsNNN_name.py`:
```python
RULE_ID = "GSNNN"
ECHELON = 2
NOISE_TIER = "precise"  # precise|normal|noisy
description = "What this detects"

def detect(ctx: AuditContext) -> list[Finding]:
    return [Finding(rule_id=RULE_ID, severity="HIGH", ...)]
```
2. Register in `gsc_detectors/registry.py` → `import ... as _gsNNN` + `DetectorEntry(...)`
3. Done — `gsc scan` picks it up automatically

## Инварианты

1. **Самообучение обязательно.** После каждого аудита находки → DB.
2. **Noise tiers first.** Precise → normal → noisy. Экономия токенов.
3. **Resume by default.** Каждый скан трекает per-file state.
4. **DB — SSOT.** `~/.hermes/state/gsc_audit.db` — единственный источник правды.
5. **Revalidate before report.** Structured verdicts (TP/FP/Fixed/Uncertain), не бинарный REAL/FALSE.

## Связанные компоненты

| Компонент | Путь |
|-----------|------|
| GSC DB | `~/.hermes/state/gsc_audit.db` |
| Seed patterns | `~/gsc/patterns/*.json` |
| Detectors | `~/gsc/gsc_detectors/gs*.py` |
| Resume tracking | `~/gsc/gsc_resume.py` |
| Revalidation | `~/gsc/gsc_revalidate.py` |
| Self-learn | `~/.hermes/scripts/gsc_self_learn.py` |
| Obsidian reports | `~/obsidian-vault/audits/` |
| Redteam Kit (training) | `~/obsidian-vault/hermes/redteam-kit/` |
|| GSC Dev Skill | `~/.hermes/skills/engineering/gsc-development/` |

## GS007 v2.0 — BAC Upgrade (2026-07-28)

**Источник:** Meta $78K bug bounty — chained Broken Access Control в support-инфраструктуре.
Исследователь Рони К. Рой: комбинация IDOR + ticket enumeration + missing org checks → доступ к тикетам, файлам, переписке.

**Что добавлено (28 patterns total, было 5):**
- Sequential ID enumeration (AUTOINCREMENT, SERIAL, `int(request.GET['id'])`)
- Cross-tenant/org isolation gaps (missing `tenant_id`/`org_id` filter)
- Admin/support/internal panel routes without auth
- File/attachment download without ownership check
- Ticket operations without permission (subscribe, status change)

**Бенчмарк 5 проектов (2026-07-28):**

| Проект | GS007 v1 | GS007 v2 | Урок |
|--------|:-------:|:-------:|------|
| django-helpdesk | 0 | 2 | Оба — контекстные FP (staff-only view, single-tenant). Паттерны корректны. |
| Flask-AppBuilder | 0 | 0 | Чисто |
| fastapi-realworld | 0 | 0 | Чисто |
| django-organizations | 0 | 0 | Чисто |
| Corpus (gs007_bac) | — | 9 | 9/9 expected (5 HIGH, 4 INFO) |

**Тюнинг шума:**
- `SERIAL` без `\b` → матчил `serializers` (109 FP на django-helpdesk) → фикс: `\bSERIAL\b`
- `subscribe` без `\b` → матчил `swagger-ui-bundle.js` (14 FP) → фикс: `\badd_subscriber\b`
- AUTOINCREMENT: CRITICAL → INFO (фасилитатор, не уязвимость сама по себе)
- Добавлен skip vendor/minified/static файлов

**Итого:** 96% reduction шума (257→2 на 4 проектах), все 2 оставшиеся — объяснимые контекстные FP.
