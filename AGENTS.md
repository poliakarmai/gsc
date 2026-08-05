# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — self-learning audit system.
> Обновлено: 2026-08-04 (v0.11 — Self-Learning v2, GS024 LLM detector, честные метрики)

## Что это

Пятистадийный аудитор кода с самообучением. 400+ паттернов, 18 plugin-детекторов, SQLite DB, Obsidian-отчёты.
Каждая находка становится паттерном для будущих аудитов.

Архитектура вдохновлена Deepsec (Vercel Labs): scan → revalidate → export, per-file state, structured verdicts.

## Структура

```
gsc/
├── gsc.py                ← CLI entry point (15 команд)
├── gsc_detectors/        ← Plugin detector system (v0.9, 18 детекторов)
│   ├── __init__.py       ← AuditContext, Finding (noise_tier), Detector interface
│   ├── registry.py       ← ALL_DETECTORS, get_detectors(), run_detectors()
│   ├── gs001_hardcoded_secret.py   ← API keys, tokens, passwords, PAN/CVV/Track/IBAN
│   ├── gs002_world_readable.py     ← Sensitive files (perms)
│   ├── gs003_debug_prints.py       ← print() / console.log in production
│   ├── gs004_dangerous_subprocess.py ← shell=True, eval, exec
│   ├── gs005_sql_injection.py      ← f-string SQL, raw queries
│   ├── gs007_idor.py              ← BAC: IDOR + fintech-IDOR (payment methods, transactions, statements) — 35 patterns, v2.2
│   ├── gs008_dead_code.py         ← Constants never used
│   ├── gs009_supply_chain.py      ← Bumblebee scanner (npm/PyPI/Go/MCP)
│   ├── gs010_ssh_hardening.py     ← sshd_config weakness
│   ├── gs011_jwt_vulnerabilities.py ← alg:none, weak secrets
│   ├── gs012_mass_assignment.py   ← 🆕 Django/FastAPI/Rails/GraphQL
│   ├── gs013_graphql_security.py  ← 🆕 introspection, depth limiting
│   ├── gs014_credential_exposure.py ← SAM, DPAPI, unattend, sudoers
│   ├── gs015_entry_points.py      ← Noisy matcher: all HTTP handlers
│   ├── gs016_linux_priv_esc.py    ← 🆕 SUID, cron hijack, capabilities, sudo NOPASSWD
│   ├── gs017_weak_passwords.py    ← 🆕🆕 Default creds, Docker defaults, short passwords
│   ├── gs018_payment_abuse.py     ← 🆕🆕 Payment logic, idempotency, promos, race conditions
│   └── gs019_auth_session.py      ← 🆕🆕 Auth/session: SMS exhaustion, JWT, cookie flags, OTP
│   ├── gs020_xss_injection.py     ← 🆕🆕🆕 XSS/HTML/SSTI: reflected, stored, DOM, template injection (Web Hacking 101)
│   ├── gs021_csrf_ssrf.py         ← 🆕🆕🆕 CSRF/SSRF: missing tokens, internal URL fetches (Bug Hunting)
│   ├── gs022_open_redirect.py     ← 🆕🆕🆕 Open Redirect: redirect params, URL bypass (Web Hacking 101)
│   └── gs023_race_conditions.py   ← 🆕🆕🆕 Race Conditions: TOCTOU, double-spend, async races (Bug Hunting)
│   └── gs024_llm_sqli.py          ← 🆕🆕🆕🆕 LLM-based SQLi detector (pilot, replaces 87 regex patterns)
├── gsc_resume.py         ← 🆕 FileStateManager (per-file scan state)
├── gsc_revalidate.py     ← 🆕 Structured revalidator (TP/FP/Fixed/Uncertain)
├── patterns/             ← Seed patterns (OWASP, CWE, 7 languages)
├── scripts/              ← Self-learn, export, metrics, CI, config
├── tests/                ← Corpus tests (8/8)
├── AGENTS.md             ← This file
└── README.md             ← User docs
```

## Как запускать

```bash
cd ~/gsc

# Scan
python3 gsc.py scan <project>                       # полный аудит
python3 gsc.py scan <project> --resume              # 🆕 продолжить прерванный скан
python3 gsc.py scan <project> --deep                # LLM-анализ
python3 gsc.py scan <project> --diff                # только изменённые файлы
python3 gsc.py scan <project> --json                # JSON-вывод

# Revalidate (Deepsec-inspired)
python3 gsc.py revalidate <project>                 # 🆕 перепроверить находки (LLM)
python3 gsc.py revalidate <project> --no-llm        # 🆕 только эвристики (бесплатно)
python3 gsc.py revalidate <project> --min-severity HIGH

# Status
python3 gsc.py status <project>                     # 🆕 прогресс скана (resume-aware)

# Other
python3 gsc.py init                                 # инициализация
python3 gsc.py dashboard                            # веб-дашборд (:8080)
python3 gsc.py patterns --list                      # список паттернов
python3 gsc.py triage <project>                     # ручная разметка TP/FP
python3 gsc.py explain <id>                         # CVSS + анализ
python3 gsc.py fix <id>                             # AI-патч
python3 gsc.py metrics                              # precision/recall
python3 gsc.py db "SELECT COUNT(*) FROM findings"   # прямой SQL
```

## Архитектура

```
gsc scan <project>
  ├── load_patterns (DB + seed files, noise-tier приоритизация)
  ├── E1: Source-driven (grep + precise-tier detectors)
  ├── E2: Security (regex + permissions + normal-tier detectors)
  ├── E3: Adversarial (semantic + noisy-tier detectors)
  ├── E4: LLM deep analysis (--deep, опционально)
  ├── post-filters: docstring/comment, framework-aware, reachability
  └── save_findings → SQLite + Obsidian
       ↓
gsc revalidate <project>  ← 🆕 Deepsec-inspired
  ├── Heuristic pre-checks (test files, docs, placeholders)
  ├── Git history check (was this fixed?)
  ├── LLM structured analysis (DeepSeek)
  └── Verdict: true-positive / false-positive / fixed / uncertain
```

### Pipeline (Deepsec-inspired)

```
         scan              revalidate            export
          │                    │                    │
          ▼                    ▼                    ▼
   candidates  →   findings    TP/FP/Fixed   →  JSON / Obsidian
   (regex+15      (LLM verify)  (structured      (markdown +
   detectors)                    verdicts)        SARIF)
        │                      │
        └── resume ────────────┘
      (per-file state, idempotent,
       можно продолжить с места падения)
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
