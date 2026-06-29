# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![detectors-15](https://img.shields.io/badge/detectors-15-green)
![patterns-350+](https://img.shields.io/badge/patterns-350+-green)
![python-3.10+](https://img.shields.io/badge/python-3.10+-blue)
![precision-73%](https://img.shields.io/badge/precision-73%25-yellow)

> Самообучающийся аудитор кода с архитектурой Deepsec. 15 детекторов, resume, structured revalidate.
> Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре, но пропускают специфичные для вашего проекта баги: «здесь `round(..., 2)` должен быть `round(..., 6)`», «после рефакторинга `valid_from` стал `created_at`».

Такие находки рождаются из опыта и теряются после аудита. **GSC их сохраняет и переиспользует.**

## Что это

CLI-инструмент с накоплением паттернов и **самообучением**. Архитектура вдохновлена [Deepsec (Vercel Labs)](https://github.com/vercel-labs/deepsec) — scan → revalidate → export, per-file state, structured verdicts.

**Текущее состояние (v0.7 — Deepsec upgrade):**
- **15 plugin-детекторов** (было 9): SSH, JWT, Mass Assignment, GraphQL, Credential Exposure, Entry-point Coverage
- **350+ активных паттернов** (7 языков), авто-создание из TP (≥3 подтверждений)
- **Noise tiers** (precise/normal/noisy) — приоритизация по сигнал/токен
- **Resume** (`--resume`, `gsc status`) — per-file state, продолжение после падения
- **Structured revalidate** (`gsc revalidate`) — TP/FP/Fixed/Uncertain, git history check
- **Precision: 73%** (104 TP / 38 FP), 34 000+ находок в базе
- Фильтры: docstring/comment, language + AST, inline suppression (`# gsc:ignore`), reachability, framework-aware
- Самообучение: 53 проекта, daily cron, multi-LLM voting, severity-weighted деактивация
- AI-патч (`gsc fix`), SARIF, diff-only, baseline, PR comments

> **v0.7 новое:** 6 детекторов обучены на Redteam Kit (22 источника: SSH Hardening, Hacking APIs, Window PrivEsc, 2025 Playbooks). Resume + revalidate — полноценный Deepsec-подобный пайплайн. При этом на DeepSeek в 1000× дешевле Claude Opus.

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

## Архитектура (Deepsec-inspired)

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

```
gsc scan <project>
  ├── load_patterns (DB + seed files, noise-tier приоритизация)
  ├── E1: Source-driven (grep + precise-tier detectors)
  ├── E2: Security (regex + permissions + normal-tier detectors)
  ├── E3: Adversarial (semantic + noisy-tier detectors)
  ├── post-filters: docstring/comment, framework-aware, reachability
  └── save_findings → SQLite + Obsidian
       ↓
gsc revalidate <project>  ← Deepsec-inspired
  ├── Heuristic pre-checks (test files, docs, placeholders)
  ├── Git history check (was this fixed?)
  └── LLM structured analysis → TP/FP/Fixed/Uncertain
```

## Детекторы (v0.7)

| Rule | Tier | Category | What it catches |
|------|:----:|----------|-----------------|
| GS001 | precise | CRITICAL | Hardcoded secrets (API keys, JWT, tokens, connection strings) |
| GS002 | normal | HIGH | World-readable sensitive files (.pem, .key, .env) |
| GS003 | normal | LOW | Debug code left in production (print, console.log) |
| GS004 | precise | HIGH | Dangerous subprocess (shell=True, os.system, eval, exec) |
| GS005 | precise | CRITICAL | SQL injection (f-strings, raw SQL, ORM interpolation) |
| GS007 | normal | HIGH | IDOR — missing auth/ownership checks (Django/Rails/FastAPI) |
| GS008 | normal | LOW | Dead code — constants/feature flags declared but never used |
| GS009 | normal | HIGH | Supply chain (Bumblebee: npm/PyPI/Go/MCP/editor extensions) |
| GS010 🆕 | precise | CRITICAL | Weak SSH config (PermitRootLogin, PasswordAuth, LD_PRELOAD, X11) |
| GS011 🆕 | precise | CRITICAL | JWT vulnerabilities (alg:none, verify=False, hardcoded secrets) |
| GS012 🆕 | normal | HIGH | Mass Assignment (Django **request.POST, FastAPI **body, Rails params) |
| GS013 🆕 | normal | HIGH | GraphQL security (introspection, depth, error disclosure, GraphiQL) |
| GS014 🆕 | precise | HIGH | Credential exposure (SAM, DPAPI, unattend.xml, sudoers NOPASSWD) |
| GS015 🆕 | noisy | INFO | Entry-point coverage (FastAPI, Flask, Django, Sanic, Tornado, aiohttp) |

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
gsc scan <project> --resume             # 🆕 продолжить прерванный скан
gsc scan <project> --deep               # LLM-анализ (Echelon 4)
gsc scan <project> --diff               # только изменённые файлы
gsc scan <project> --json               # JSON-вывод
gsc scan <project> --sarif              # SARIF для GitHub Code Scanning

# Revalidate 🆕
gsc revalidate <project>                # structured re-check (LLM)
gsc revalidate <project> --no-llm       # только эвристики (бесплатно)
gsc revalidate <project> --min-severity HIGH

# Status 🆕
gsc status <project>                    # прогресс скана (resume-aware)

# Triage
gsc triage <project>                    # ручная разметка TP/FP
gsc triage <project> --group-by pattern # кластерами
gsc triage <project> --bulk             # JSON со stdin

# Analysis
gsc explain <id>                        # CVSS, threat/impact
gsc fix <id>                            # AI-патч (OpenRouter/DeepSeek)

# Management
gsc init                                # инициализация (.gsc/, CI workflow)
gsc dashboard                           # веб-интерфейс (:8080)
gsc doctor                              # диагностика окружения
gsc metrics                             # precision/recall
gsc patterns export [file]              # экспорт YAML
gsc patterns import <file>              # импорт YAML
gsc config set <key> <value>            # настройка
gsc db "SELECT COUNT(*) FROM findings"  # прямой SQL
```

## Noise Tiers (Deepsec-inspired)

| Tier | Когда | Пример |
|------|-------|--------|
| `precise` | Паттерн однозначен — только уязвимость | `$queryRawUnsafe(` — только небезопасный Prisma API |
| `normal` | Паттерн шире — AI/человек разбирается | `auth-bypass`: флагит admin-чеки и skip-auth строки |
| `noisy` | Каждый файл в глобе → AI review | `**/api/**/route.ts` — все entry-point файлы |

Precise-паттерны обрабатываются первыми (максимум сигнала на токен).

## Бенчмарк на open-source проектах

| Проект | ⭐ | Всего | Новые детекторы | Реальные |
|--------|---|:----:|:---------------:|:--------:|
| requests | 52k | 131 | — | — |
| flask | 68k | 16 | — | — |
| flask-jwt-auth | 1 | 11 | GS011: 2 (1 real) | 🔴 JWT secret `my_precious` |
| blueprint-api | 1 | 15 | GS012: 1 | — (DRF serializer, safe) |
| tock | 100+ | 177 | GS014: 2, GS012: 42 | — (dev configs) |
| sshpiper | 1k+ | 373 | GS014: 1 | — (e2e test key) |

> **Вывод:** GS011 нашёл реальный JWT-секрет в первый же день. Остальные детекторы требуют LLM-верификации (revalidate) для фильтрации FP. GSC не универсальный сканер — он инструмент для **вашей** кодовой базы.

### Производительность

| Проект | LOC | Время скана |
|--------|----:|:----------:|
| flask | 35k | 2.1 сек |
| requests | 18k | 1.4 сек |
| flask-jwt-auth | 2k | 0.8 сек |
| sshpiper (Go) | 50k | 3.2 сек |
| tock (Django) | 30k | 2.4 сек |

## Сравнение с Deepsec

| Фича | GSC | Deepsec |
|------|-----|--------|
| **Pipeline** | scan → revalidate → export | scan → process → revalidate → enrich → export |
| **Detectors** | 15 plugin-детекторов | Встроенные matchers + custom |
| **Noise tiers** | precise/normal/noisy | precise/normal/noisy |
| **Resume** | ✅ per-file state + --resume | ✅ per-file JSON state |
| **Revalidate** | ✅ TP/FP/Fixed/Uncertain + git history | ✅ TP/FP/Fixed + git history |
| **AI backend** | DeepSeek (~$0.05/день) | Claude Opus / Codex SDK (тысячи $) |
| **Самообучение** | ✅ daily cron, 53 проекта, авто-деактивация | ❌ |
| **Стоимость полного прогона** | ~$0.01 | ~$1000+ |

## Самообучение

Ежедневный цикл (cron, 04:00) — 10 проектов из ротации (53 Python-проекта) → scan → авто-триаж → накопление статистики → авто-деактивация слабых паттернов.

```bash
python3 scripts/gsc_self_learn.py           # ручной запуск цикла
python3 scripts/gsc_self_learn.py --stats   # статистика
python3 scripts/gsc_self_learn.py --dry-run # какие проекты сегодня
```

**Авто-триаж — три уровня:**
1. Эвристики: test-файлы, docstrings, config-файлы → авто-FP
2. LLM (DeepSeek): CRITICAL/HIGH → REAL/FALSE
3. Multi-model voting (gemini + qwen + deepseek) для спорных случаев

Слабые паттерны (<30% эффективности, ≥10 оценок) авто-отключаются. CRITICAL защищены от авто-деактивации.

## CI/CD (GitHub Actions)

```yaml
- name: Install GSC
  run: pip install git+https://github.com/poliakarmai/gsc.git
- name: Run GSC Audit
  run: gsc scan . --diff --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: results.sarif}
```

## Дорожная карта

| Фаза | Что | Статус |
|------|-----|--------|
| **1. CLI** | scan, triage, explain, fix, dashboard | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, WAL | ✅ |
| **3. Качество** | Corpus-тесты, docstring/AST/reachability фильтры | ✅ |
| **4. LLM** | E4 deep analysis, gsc fix, LLM-триаж | ✅ |
| **5. Самообучение** | Daily cycle, 53 проекта, авто-триаж, авто-деактивация | ✅ |
| **6. Deepsec upgrade** 🆕 | 15 детекторов, noise tiers, resume, structured revalidate | ✅ |
| **7. Мультиязычность** | Go, TS, Rust, Java, Docker, Terraform самообучение | 🔜 Июль 2026 |
| **8. Dependency scanning** | pip-audit, npm audit, cargo-audit | 🔜 Июль 2026 |
| **9. DX** | VSCode extension, Jira/Linear, Pattern marketplace | 🔜 Август 2026 |
| **10. Enterprise** | Helm chart, SSO, Compliance, RBAC | 📋 2027 |
| **11. Agent Training** | Экспорт размеченных находок (JSONL/OpenAI/Markdown) | ✅ |

## 🔧 Troubleshooting

**`❌ ripgrep`** → `brew install ripgrep` / `apt install ripgrep` (бинарник, не pip).
**Слишком много FP** → `gsc revalidate --no-llm` → эвристики отсеют тесты/доку/плейсхолдеры.
**LLM не работает** → `GSC_LLM_PROVIDER=ollama` или проверь `DEEPSEEK_API_KEY`.
**Скан упал** → `gsc scan --resume` продолжит с места падения.
**Прогресс** → `gsc status` покажет сколько файлов отсканировано.

## 📄 Лицензия

MIT — см. [LICENSE](./LICENSE).
