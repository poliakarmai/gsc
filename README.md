# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![detectors-23](https://img.shields.io/badge/detectors-23-green)
![patterns-400+](https://img.shields.io/badge/patterns-400+-green)
![python-3.10+](https://img.shields.io/badge/python-3.10+-blue)
![self-learning-v2](https://img.shields.io/badge/self--learning-v2-blue)

> Самообучающийся аудитор кода с замкнутой петлёй обучения. 23 детектора, LLM-ревалидация, авто-деактивация.
> **v0.16 (август 2026):** Production rollout, REST API, adversarial review fixes, CI workflows.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре, но пропускают специфичные для вашего проекта баги. Хуже — 99% их находок на чужих проектах ложные.

**GSC решает это через замкнутую петлю:** scan → LLM-ревалидация → авто-деактивация шумных паттернов → новые паттерны из подтверждённых TP. Каждый цикл повышает precision.

## Что это

CLI-инструмент с накоплением паттернов и **самообучением v2**. Архитектура вдохновлена [Deepsec (Vercel Labs)](https://github.com/vercel-labs/deepsec).

**Текущее состояние (v0.16):**
- **23 plugin-детектора** — GS024 (LLM SQLi пилот)
- **400+ паттернов** (7 языков), авто-создание из TP
- **Self-learning v2** — замкнутая петля с LLM-ревалидацией
- **192 проекта** в ротации, **400K+ находок** в БД
- **REST API v1.0** — FastAPI, 7 эндпоинтов, OpenAPI docs
- **CI/CD** — GitHub Actions (internal PR + fork-safe + calibration)
- **Rollout Phase 1** — warn-only, готов к blocking
- **Calibration:** 14/14, **corpus:** 8/8
- Noise tiers, resume, structured revalidate, PR gate с fingerprinting

> **Честно о precision:** на своих проектах GSC точен (73% на размеченных данных). На чужих — precision ~0% без ревалидации. Self-learning v2 закрывает этот разрыв через LLM-триаж каждого цикла.

## 🚀 Установка

**Требования:** Python 3.10+, ripgrep 13+ (бинарник, не pip).

```bash
brew install ripgrep      # macOS
sudo apt install ripgrep  # Linux
git clone https://github.com/poliakarmai/gsc.git
cd gsc && pip install .
gsc doctor && gsc scan .
```

---

## Архитектура (Self-Learning v2)

```
         scan              revalidate            learn
          │                    │                    │
          ▼                    ▼                    ▼
   candidates  →   findings    TP/FP/Fixed   →  update patterns
   (regex+23      (auto-FP +   (DeepSeek LLM)   (effectiveness,
   detectors)     LLM verify)                     auto-deactivate)
        │                      │                    │
        └── resume ────────────┴── new patterns ───┘
      (per-file state,      (from confirmed TPs,
       idempotent)            manual activation)
```

```
Ежедневный цикл (cron 04:00):
  5 проектов → clone → gsc scan → heuristic auto-FP (тесты/docstrings)
  → LLM revalidate CRITICAL/HIGH (до 50/день, ~$0.05)
  → update_pattern_stats() → effectiveness из verdicts
  → авто-деактивация (<30% TP, ≥10 rated, не CRITICAL)
  → auto-create patterns из ≥5 confirmed TP (inactive — manual activation)
```

## Детекторы (v0.11)

| Rule | Tier | Category | What it catches |
|------|:----:|----------|-----------------|
| GS001 | precise | CRITICAL | Hardcoded secrets (API keys, JWT, tokens, PAN/CVV/IBAN) |
| GS002 | normal | HIGH | World-readable sensitive files (.pem, .key, .env) |
| GS003 | normal | LOW | Debug code left in production (print, console.log) |
| GS004 | precise | HIGH | Dangerous subprocess (shell=True, os.system, eval, exec) |
| GS005 | precise | CRITICAL | SQL injection (87+ patterns: f-strings, raw SQL, ORM, NoSQL) |
| GS007 | normal | HIGH | IDOR/BAC — 35 patterns (Django/Rails/FastAPI, fintech-IDOR) |
| GS008 | normal | LOW | Dead code — constants/feature flags declared but never used |
| GS009 | normal | HIGH | Supply chain (Bumblebee: npm/PyPI/Go/MCP/editor extensions) |
| GS010 | precise | CRITICAL | Weak SSH config (PermitRootLogin, PasswordAuth, LD_PRELOAD, X11) |
| GS011 | precise | CRITICAL | JWT vulnerabilities (alg:none, verify=False, hardcoded secrets) |
| GS012 | normal | HIGH | Mass Assignment (Django/FastAPI/Rails/GraphQL) |
| GS013 | normal | HIGH | GraphQL security (introspection, depth, error disclosure) |
| GS014 | precise | HIGH | Credential exposure (SAM, DPAPI, unattend.xml, sudoers NOPASSWD) |
| GS015 | noisy | INFO | Entry-point coverage (all HTTP handlers → AI review) |
| GS016 | normal | CRITICAL | Linux privilege escalation (SUID, sudo, cron hijack, capabilities) |
| GS017 | normal | CRITICAL | Weak/default passwords (admin:admin, Docker defaults, MD5/SHA1) |
| GS018 | normal | CRITICAL | Payment logic abuse (idempotency, promos, balance races, webhooks) |
| GS019 | normal | HIGH | Auth/session weaknesses (SMS exhaustion, JWT, cookie flags, OTP) |
| GS020 | precise | CRITICAL | XSS/HTML/SSTI injection — 23 patterns (Web Hacking 101) |
| GS021 | normal | CRITICAL | CSRF/SSRF — 20 patterns (Bug Hunting) |
| GS022 | normal | HIGH | Open Redirect — 13 patterns (Web Hacking 101) |
| GS023 | noisy | HIGH | Race Conditions — 16 patterns (TOCTOU, double-spend, async) |
| **GS024** 🆕 | **precise** | **CRITICAL** | **LLM-based SQL injection** (pilot — replaces 87 regex patterns) |

## Пример

```python
# config.py:11
SECRET_KEY = os.getenv('SECRET_KEY', 'my_precious')  # ← хардкод JWT secret
```
```bash
$ gsc scan .                  # → GS011: HIGH — Hardcoded JWT secret
$ gsc revalidate . --no-llm   # → 🔴 true-positive (confirmed)
$ gsc fix 42                  # → AI-патч: заменить на os.getenv('SECRET_KEY')
$ gsc triage .                # [y] → TP+1 → следующий скан умнее
```

## Команды

```bash
# Scan
gsc scan <project>                      # полный аудит
gsc scan <project> --resume             # продолжить прерванный скан
gsc scan <project> --deep               # LLM-анализ (Echelon 4)
gsc scan <project> --diff               # только изменённые файлы
gsc scan <project> --json               # JSON-вывод
gsc scan <project> --sarif              # SARIF для GitHub Code Scanning

# Revalidate
gsc revalidate <project>                # structured re-check (LLM)
gsc revalidate <project> --no-llm       # только эвристики (бесплатно)
gsc revalidate <project> --min-severity HIGH

# Status
gsc status <project>                    # прогресс скана (resume-aware)

# Metrics (v2.0 — revalidation-based)
gsc metrics                             # precision/recall, per-detector stats
gsc metrics <project>                   # per-project breakdown

# Triage
gsc triage <project>                    # ручная разметка TP/FP
gsc triage <project> --group-by pattern # кластерами

# Analysis
gsc explain <id>                        # CVSS, threat/impact
gsc fix <id>                            # AI-патч (DeepSeek)

# Management
gsc init                                # инициализация (.gsc/, CI workflow)
gsc dashboard                           # веб-интерфейс (:8080)
gsc api --port 8766                     # REST API (FastAPI + Swagger)
gsc doctor                              # диагностика окружения
gsc patterns export [file]              # экспорт YAML
gsc db "SELECT COUNT(*) FROM findings"  # прямой SQL
```

## REST API 🆕

```bash
gsc api --port 8766                     # старт сервера

# Эндпоинты (x-api-key header):
curl localhost:8766/api/v1/health                          # статус
curl -X POST localhost:8766/api/v1/scan \                  # запуск скана
  -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d '{"target":"https://github.com/user/repo"}'
curl -H "x-api-key: $KEY" \                                # результаты
  localhost:8766/api/v1/scan/{scan_id}
curl -H "x-api-key: $KEY" \                                # находки
  "localhost:8766/api/v1/findings/gsc?severity=CRITICAL"
open http://localhost:8766/docs                            # Swagger UI
```

## Noise Tiers (Deepsec-inspired)

| Tier | Когда | Пример |
|------|-------|--------|
| `precise` | Паттерн однозначен — только уязвимость | `$queryRawUnsafe(` — только небезопасный Prisma API |
| `normal` | Паттерн шире — AI/человек разбирается | `auth-bypass`: флагит admin-чеки и skip-auth строки |
| `noisy` | Каждый файл в глобе → AI review | `**/api/**/route.ts` — все entry-point файлы |

## Самообучение v2 (замкнутая петля)

Ежедневный цикл (cron 04:00): 5 проектов → scan → heuristic FP → **LLM revalidate** → обновление effectiveness → авто-деактивация → новые паттерны из TP.

```bash
python3 scripts/gsc_self_learn.py           # ручной запуск цикла
python3 scripts/gsc_self_learn.py --stats   # статистика (precision trend)
python3 scripts/gsc_self_learn.py --dry-run # какие проекты сегодня
```

**Ключевое изменение v1→v2:** раньше находки просто сохранялись как `open`. Теперь CRITICAL/HIGH проходят LLM-ревалидацию (до 50/день), вердикты сохраняются в БД, и метрики считаются от реальных TP/FP.

## Сравнение с Deepsec

| Фича | GSC | Deepsec |
|------|-----|--------|
| **Pipeline** | scan → revalidate → learn → export | scan → process → revalidate → enrich → export |
| **Detectors** | 23 plugin-детекторов + LLM | Встроенные matchers + custom |
| **Noise tiers** | precise/normal/noisy | precise/normal/noisy |
| **Resume** | ✅ per-file state + --resume | ✅ per-file JSON state |
| **Revalidate** | ✅ TP/FP/Fixed/Uncertain + git history | ✅ TP/FP/Fixed + git history |
| **AI backend** | DeepSeek (~$0.05/день) | Claude Opus / Codex SDK (тысячи $) |
| **Самообучение** | ✅ v2: замкнутая петля, авто-деактивация | ❌ |
| **LLM detector** | ✅ GS024 (пилот) | ❌ (только verify) |
| **PR comments** | ✅ GitHub Actions workflow | ❌ |
| **Стоимость полного прогона** | ~$0.05 | ~$1000+ |

## CI/CD (GitHub Actions)

```yaml
# .github/workflows/gsc-internal-pr.yml — same-repo PR (full LLM)
# .github/workflows/gsc-fork-safe.yml   — fork PR (regex-only, safe mode)
# .github/workflows/gsc-calibration.yml — nightly calibration (14/14)

# В своем репо:
- run: pip install git+https://github.com/poliakarmai/gsc.git
- run: gsc scan . --diff --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
```

PR scanner: комментарий + check run + SARIF. Fork-safe: авто no-LLM, no-blocking.

## Дорожная карта

| Фаза | Что | Статус |
|------|-----|--------|
| **1. CLI** | scan, triage, explain, fix, dashboard | ✅ |
| **2. CI/CD** | diff-only, SARIF, pre-commit, PR comments | ✅ |
| **3. Качество** | Corpus-тесты, docstring/AST/reachability фильтры | ✅ |
| **4. LLM** | E4 deep analysis, gsc fix, LLM-триаж | ✅ |
| **5. Самообучение v1** | Daily cycle, 53 проекта, авто-триаж | ✅ |
| **6. Deepsec upgrade** | 15 детекторов, noise tiers, resume, revalidate | ✅ |
| **7. Self-learning v2** 🆕 | Замкнутая петля, LLM-ревалидация, честные метрики | ✅ |
| **8. LLM детектор** 🆕 | GS024 — пилот (SQLi), замена 87 regex одним LLM-вызовом | ✅ |
| **9. Production rollout** | warn-only → blocking-critical → blocking-standard | 🔜 Август 2026 |
| **10. Мультиязычность** | Go, TS, Rust, Java (интегрирована, тестируется) | ✅ |
| **11. REST API** | FastAPI, 7 эндпоинтов, OpenAPI docs, API key auth | ✅ |
| **12. DX** | VSCode extension, Pattern marketplace | 📋 2027 |
| **12. Enterprise** | Helm chart, SSO, Compliance, RBAC | 📋 2027 |

## 🔧 Troubleshooting

**`❌ ripgrep`** → `brew install ripgrep` / `apt install ripgrep` (бинарник, не pip).
**Слишком много FP** → `gsc revalidate --no-llm` → эвристики отсеют тесты/доку/плейсхолдеры.
**LLM не работает** → `GSC_LLM_PROVIDER=ollama` или проверь `DEEPSEEK_API_KEY`.
**Скан упал** → `gsc scan --resume` продолжит с места падения.
**Прогресс** → `gsc status` покажет сколько файлов отсканировано.

## 📄 Лицензия

MIT — см. [LICENSE](./LICENSE).
