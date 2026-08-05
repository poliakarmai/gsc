# PROJECT.md — GSC: Git Security Checker

> **Для:** внешнего AI-агента для аудита кодовой базы.  
> **Автор:** Море (Hermes orchestrator, профиль `default`)  
> **Дата:** 2026-08-05  
> **Версия:** v0.11  
> **Репозиторий:** `github.com/poliakarmai/gsc`

---

## 1. Что это и зачем

GSC — самообучающийся статический анализатор безопасности. Ищет уязвимости в коде через plugin-детекторы (regex) и LLM (DeepSeek), сохраняет находки в SQLite, накапливает паттерны, авто-деактивирует шумные.

**Главная фича:** замкнутая петля самообучения. Каждый день cron-скрипт сканирует 5 GitHub-проектов, прогоняет CRITICAL/HIGH находки через LLM-ревалидацию, и на основе вердиктов авто-деактивирует паттерны с precision <30%.

**Архитектурное вдохновение:** Deepsec (Vercel Labs) — scan → revalidate → export, noise tiers, per-file resume.

---

## 2. Файловая структура

```
~/gsc/                              ← основной репозиторий
├── gsc.py                          ← CLI (1818 строк, 15 команд)
├── gsc_resume.py                   ← FileStateManager (per-file scan state)
├── gsc_revalidate.py               ← Structured revalidator (TP/FP/Fixed/Uncertain)
├── gsc_detectors/                  ← Plugin detector system (23 детектора)
│   ├── __init__.py                 ← AuditContext, Finding, Detector (Protocol)
│   ├── registry.py                 ← ALL_DETECTORS, get_detectors(), run_detectors()
│   ├── gs001..gs023_*.py           ← 22 regex-based детектора
│   ├── gs020_llm_sqli.py           ← GS024: LLM-based SQLi detector (pilot)
│   └── llm_verify.py               ← LLM verification for --deep flag
├── patterns/                       ← Seed patterns (JSON, 7 языков)
├── corpus/                         ← Тестовые корпуса для детекторов
├── scripts/                        ← Вспомогательные скрипты
│   ├── gsc_metrics.py              ← Precision/recall v2.0
│   ├── gsc_pr_scanner.py           ← GitHub PR comment scanner
│   ├── gsc_self_learn.py (symlink) → ~/.hermes/scripts/gsc_self_learn.py
│   ├── framework_aware.py          ← AST-фильтр (torch/pickle/etc)
│   ├── gsc_baseline.py             ← Baseline suppressions
│   ├── gsc_doctor.py               ← Диагностика окружения
│   ├── gsc_config.py               ← Управление конфигурацией
│   ├── gsc_export_knowledge.py     ← Экспорт размеченных находок
│   ├── gsc_reachability.py         ← Reachability analysis
│   └── gsc_github_dorks.py         ← GitHub Dorks scanner
├── tests/
│   └── test_corpus.py              ← 8 интеграционных тестов (8/8)
├── .github/workflows/
│   └── gsc-pr-scan.yml             ← GitHub Actions PR scanner
├── AGENTS.md                       ← Навигация для AI-агентов
├── README.md                       ← Пользовательская документация
└── LICENSE                         ← MIT

~/.hermes/scripts/
└── gsc_self_learn.py               ← Self-learning engine v2.0 (514 строк)

~/.hermes/state/
├── gsc_audit.db                    ← SQLite: patterns, findings, audit_runs
├── gsc_self_learn_stats.json       ← Статистика циклов (precision trend)
└── gsc_deactivation_log.json       ← Лог авто-деактиваций

~/.gsc/
└── projects.txt                    ← Список 53+ проектов для self-learning
```

---

## 3. Алгоритм сканирования (`gsc scan`)

### Точка входа

`gsc.py:cmd_scan(args)` → `run_audit_echelons(project, path, echelons, deep)`

### Четыре эшелона

```
E1: Source-driven
  ├── check_source_driven()  → grep-паттерны из БД (400+)
  └── check_plugin_detectors(echelon=1) → GS001, GS003, GS008, GS015

E2: Security
  ├── check_security()       → regex-паттерны + file permissions + systemd hardening
  └── check_plugin_detectors(echelon=2) → GS002, GS004-GS007, GS009-GS024

E3: Adversarial
  └── check_adversarial()    → semantic patterns (TOCTOU, float precision, state corruption)

E4: LLM (опционально, флаг --deep)
  └── llm_verify.verify_findings() → DeepSeek-верификация CRITICAL/HIGH (до 15 за раз)
```

### Post-фильтры (после E1-E3, до сохранения)

1. **Docstring/comment filter** — `_is_in_docstring_or_comment()`: исключает находки внутри `"""..."""` и `#...`
2. **Framework-aware filter** — `framework_aware.filter_findings()`: `pickle.load()` в torch-контексте → downgrade
3. **Reachability** (опционально) — `gsc_reachability.analyze_reachability()`: unreachable файлы → downgrade
4. **Inline suppression** — `# gsc:ignore` на строке находки

### Сохранение

- `save_findings()` → SQLite (WAL mode, busy_timeout=5s)
- `export_to_obsidian()` → `~/obsidian-vault/audits/gsc-<project>-<date>.md`

---

## 4. Plugin Detector System

### Интерфейс детектора

```python
# gsc_detectors/__init__.py
class AuditContext:
    project: str          # имя проекта
    path: Path            # абсолютный путь
    skipped_detectors: set[str]
    
    def get_source_files(extensions) -> list[Path]  # исключает тесты и не-код
    def is_test_file(path) -> bool
    def is_non_code_file(path) -> bool

class Finding(dict):
    rule_id, severity, title, file_path, line_number, detail, noise_tier

# Каждый детектор:
def detect(ctx: AuditContext) -> list[Finding]: ...
```

### Реестр (`registry.py`)

```python
ALL_DETECTORS = [DetectorEntry(rule_id, echelon, detect_fn, description, noise_tier), ...]
# 23 детектора → запускаются через run_detectors(ctx, echelons=[1,2])
```

### Noise Tiers

| Tier | Когда | Приоритет AI |
|------|-------|:-----------:|
| `precise` | Паттерн однозначно указывает на уязвимость | Высший |
| `normal` | Паттерн шире, AI дизамбигирует | Стандартный |
| `noisy` | Каждый файл — кандидат для AI review | Низший |

---

## 5. Self-Learning Engine v2

### Файл: `~/.hermes/scripts/gsc_self_learn.py` (514 строк)

### Алгоритм цикла (`run_cycle()`)

```
1. Загрузить список проектов из ~/.gsc/projects.txt (53+ проектов)
2. Выбрать 5 проектов по day-of-year offset (PROJECTS_PER_DAY=5)
3. Для каждого проекта:
   a. git clone --depth 1 --filter=blob:none (экономия трафика)
   b. gsc scan --json --ci → findings[]
   c. auto_triage():
      - is_test_file() → auto-FP
      - config/doc files → auto-FP  
      - noise patterns → auto-FP
      - остальные → сохранить как 'open'
   d. revalidate_findings():
      - CRITICAL/HIGH → gsc_revalidate (DeepSeek LLM)
      - бюджет: 20/проект, 50/день
      - вердикты → revalidation_verdict в БД
4. update_pattern_stats():
   - Для каждого активного паттерна: TP/(TP+FP) из revalidation_verdict
   - Если ≥10 рейтингов и <30% TP → active=0 (КРОМЕ CRITICAL)
   - Если 0 рейтингов → effectiveness=NULL
5. auto_create_patterns():
   - Находки с ≥5 confirmed TP → новый grep-паттерн (inactive, manual activation)
6. Сохранить статистику в gsc_self_learn_stats.json
```

### Крон-джоба

```
Job ID: 5819a70c0e54
Name: GSC Daily Self-Learn
Schedule: 0 4 * * * (ежедневно в 04:00 МСК)
Mode: no_agent (script gsc_self_learn.py)
Delivery: local (~/.hermes/cron/output/5819a70c0e54/)
```

Также: **GSC Daily Collector** (06:00) — сбор свежих CVE из NVD + GitHub Search API.

---

## 6. Revalidation Pipeline (`gsc_revalidate.py`)

### Алгоритм `revalidate_finding()`

```
1. Прочитать ±15 строк кода вокруг находки
2. Heuristic pre-checks (быстрые, бесплатные):
   - Файл удалён → fixed
   - Путь test/demo/fixture → false-positive
   - Расширение .md/.rst/.txt → false-positive
   - Имя example/sample/template/.dist → false-positive (кроме CRITICAL)
   - Деталь содержит placeholder/changeme/your-key → false-positive
3. Git history check:
   - git log -1 -- file → последний коммит
   - git blame -L line,line → кто менял строку
4. LLM deep check:
   - DeepSeek API: промпт с кодом, импортами, контекстом
   - structured JSON response: {verdict, reasoning}
   - 4 вердикта: true-positive, false-positive, fixed, uncertain
5. Сохранить в БД → revalidation_verdict, revalidation_reasoning, revalidation_checked_at
```

---

## 7. База данных (SQLite)

### Файл: `~/.hermes/state/gsc_audit.db`

### Таблицы

```sql
patterns:
  id, project, category, echelon, title, pattern_type, search_pattern,
  description, language, effectiveness, active, deactivated_at,
  noise_tier, true_positive_count, false_positive_count

findings:
  id, run_id, project, category, echelon, title, file_path, line_number,
  detail, status, pattern_title, pattern_id, noise_tier,
  revalidation_verdict, revalidation_reasoning, revalidation_checked_at,
  revalidation_git_fixed

audit_runs:
  id, project, started_at, finished_at, total_findings, new_findings

file_state (для resume):
  project, file_path, file_hash, status, candidates_count,
  findings_count, locked_by_run_id, analysis_history

e4_cache:
  sha256_hash, verdict, confidence, checked_at
```

### Режим: WAL + busy_timeout=5000ms (для конкурентного доступа CI/CD)

---

## 8. Детекторы — полный список

| Rule | Echelon | Category | Noise | Тип | Описание |
|------|:------:|----------|:-----:|-----|----------|
| GS001 | 1 | CRITICAL | precise | regex | Hardcoded secrets (API keys, JWT, tokens, PAN/CVV/IBAN) |
| GS002 | 2 | HIGH | normal | regex | World-readable sensitive files (.pem, .key, .env) |
| GS003 | 1 | LOW | normal | regex | Debug code (print, console.log) |
| GS004 | 2 | HIGH | precise | regex | Dangerous subprocess (shell=True, eval, exec) |
| GS005 | 2 | CRITICAL | precise | regex | SQL injection (87+ patterns, multi-language) |
| GS007 | 2 | HIGH | normal | regex | BAC/IDOR — 35 patterns (fintech-IDOR) |
| GS008 | 1 | LOW | normal | regex | Dead code |
| GS009 | 2 | HIGH | normal | regex | Supply chain (Bumblebee scanner) |
| GS010 | 2 | CRITICAL | precise | regex | Weak SSH config |
| GS011 | 2 | CRITICAL | precise | regex | JWT vulnerabilities |
| GS012 | 2 | HIGH | normal | regex | Mass Assignment |
| GS013 | 2 | HIGH | normal | regex | GraphQL security |
| GS014 | 2 | HIGH | precise | regex | Credential exposure |
| GS015 | 1 | INFO | noisy | regex | Entry-point coverage |
| GS016 | 2 | CRITICAL | normal | regex | Linux priv esc (SUID, cron hijack) |
| GS017 | 2 | CRITICAL | normal | regex | Weak/default passwords |
| GS018 | 2 | CRITICAL | normal | regex | Payment logic abuse |
| GS019 | 2 | HIGH | normal | regex | Auth/session weaknesses |
| GS020 | 2 | CRITICAL | precise | regex | XSS/HTML/SSTI — 23 patterns |
| GS021 | 2 | CRITICAL | normal | regex | CSRF/SSRF — 20 patterns |
| GS022 | 2 | HIGH | normal | regex | Open Redirect — 13 patterns |
| GS023 | 2 | HIGH | noisy | regex | Race Conditions — 16 patterns |
| **GS024** | **2** | **CRITICAL** | **precise** | **LLM** | **LLM SQLi (пилот)** |

---

## 9. Ключевые алгоритмические решения

### 9.1. Pattern loading

`gsc_load_patterns.py` загружает паттерны из JSON-файлов + активные паттерны из БД. Языковая фильтрация через `EXT_TO_LANG` (25+ расширений → 12 языков). `ripgrep -t py` ограничивает поиск только файлами нужного языка.

### 9.2. Framework-aware filtering

`framework_aware.py` — AST-анализ импортов. Примеры правил:
- `pickle.load()` + `import torch` → CRITICAL→LOW (ML-контекст)
- `eval()` + `import ast.literal_eval` → downgrade
- `f-string SQL` + `import sqlalchemy` → downgrade (ORM)

### 9.3. Resume mechanism

`gsc_resume.py:FileStateManager` — per-file state tracking в SQLite. Статусы: pending→scanning→scanned→processed→skipped. Атомарная блокировка через `locked_by_run_id`. CLI: `gsc scan --resume`, `gsc status`.

### 9.4. Auto-deactivation

`update_pattern_stats()`: для каждого активного паттерна считает TP/(TP+FP) из `revalidation_verdict`. Порог: <30% precision при ≥10 рейтингах → `active=0`. CRITICAL защищены от авто-деактивации.

### 9.5. Multi-LLM voting (legacy v1, заменён в v2)

Старая `e4_triage()` использовала 3 модели (gemini-flash + qwen-coder + deepseek-chat) с majority voting. В v2 заменена на `gsc_revalidate.py` с одним structured вызовом DeepSeek.

### 9.6. GS024 LLM Detector

Заменяет 87 regex-паттернов одним LLM-вызовом:
1. Pre-filter: grep по файлам с `execute|query|cursor` + `f"..."`  
2. Candidate extraction: ±10 строк контекста
3. DeepSeek: structured JSON `{vulnerable, confidence, reason}`
4. Только confidence ≥70% → finding

API-ключ читается из `~/.hermes/.env` (DEEPSEEK_API_KEY), с fallback на `os.environ`.

---

## 10. Известные проблемы и грабли

### 10.1. Precision на внешних проектах ~0%

Паттерны заточены под свои проекты. На чужих — 99% FP (тестовые пароли, docstring-примеры, `model.eval()`). Самообучение v2 должно это исправить через LLM-ревалидацию.

### 10.2. `sqlite3.Row` не имеет `.get()`

Все выборки через `conn.row_factory = sqlite3.Row` требуют `row['key']`, не `row.get('key')`. Исторически 5+ багов из-за этого.

### 10.3. `.env` dotfiles — `Path.suffix == ''`

`Path('.env').suffix` возвращает пустую строку. Проверки по suffix пропускают dotfiles. Фикс: `f.name in sensitive_names`.

### 10.4. `f.get('detail', '')[:60]` → `TypeError`

Если ключ `detail` существует но значение `None`, `.get()` возвращает `None`. Фикс: `(f.get('detail') or '')[:60]`.

### 10.5. Raw string escaping в regex детекторов

В Python raw-строках `r'...'` символ `\'` — два байта. Regex видит `\'` как «буквальный backslash + apostrophe». Фикс: использовать `r"..."` для паттернов с апострофами.

### 10.6. GS024: f-string в промпте

`{request.GET['id']}` внутри f-string-промпта → `NameError`. Фикс: `{{request.GET['id']}}`.

---

## 11. Метрики и бенчмарки

### Текущее состояние БД

| Метрика | Значение |
|---------|----------|
| Всего находок | 391 984 |
| Ревалидировано | 0 (старт завтра) |
| Статус open | 391 842 |
| Активных паттернов | 211 |
| Деактивировано | 178 |
| Precision (ручной) | 73.2% (104 TP / 38 FP) |

### Corpus tests: 8/8

| Тест | Статус |
|------|:-----:|
| SQL injection detection | ✅ |
| Hardcoded secret detection | ✅ |
| Unsafe pickle detection | ✅ |
| Bare except detection | ✅ |
| eval() detection | ✅ |
| World-readable .env | ✅ |
| Clean code (no FP) | ✅ |
| assert in prod | ✅ |

### Ground truth (свои проекты)

| Проект | Всего находок | CRITICAL | Реальных CRITICAL |
|--------|:----------:|:--------:|:----------------:|
| bybit-ws | 1647 | 122 | 0 |
| gsc | 720 | 186 | 0 |
| vpn-infra | 627 | 2 | 0 |

---

## 12. Как запустить и проверить

```bash
# Тесты
cd ~/gsc && python3 tests/test_corpus.py    # 8/8

# Скан своего проекта
python3 gsc.py scan ~/gsc --json --ci 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d))"
# → 720 findings

# Метрики
python3 gsc.py metrics
# → precision 73.2%, 0% revalidated, per-detector breakdown

# Self-learn (dry-run)
python3 ~/.hermes/scripts/gsc_self_learn.py --dry-run
# → покажет 5 проектов на сегодня

# Self-learn (полный цикл, ~5 мин)
python3 ~/.hermes/scripts/gsc_self_learn.py

# GS024 LLM detector (требует DEEPSEEK_API_KEY)
python3 -c "
from gsc_detectors.gs020_llm_sqli import _get_api_key
print('API key:', bool(_get_api_key()))
"

# БД
python3 gsc.py db "SELECT COUNT(*) FROM findings"
python3 gsc.py db "SELECT revalidation_verdict, COUNT(*) FROM findings WHERE revalidation_verdict IS NOT NULL GROUP BY 1"
```

---

## 13. Дорожная карта

| Фаза | Статус |
|------|:-----:|
| CLI (scan/triage/explain/fix/dashboard) | ✅ |
| CI/CD (SARIF, diff-only, pre-commit, PR comments) | ✅ |
| Качество (corpus tests, docstring/AST/reachability фильтры) | ✅ |
| LLM (E4 deep analysis, gsc fix) | ✅ |
| Self-learning v1 (daily cycle, 53 проекта) | ✅ |
| Deepsec upgrade (15→23 детекторов, noise tiers, resume, revalidate) | ✅ |
| **Self-learning v2** (замкнутая петля, LLM-ревалидация) | ✅ |
| **GS024 LLM detector** (пилот) | ✅ |
| Ground truth / precision tracking | 🔜 |
| Мультиязычность (Go/TS/Rust/Java) | 🔜 |
| VSCode extension / Pattern marketplace | 📋 |
| Enterprise (Helm, SSO, Compliance) | 📋 |
