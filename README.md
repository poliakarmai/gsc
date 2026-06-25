# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![patterns-277](https://img.shields.io/badge/patterns-277-green)
![fp-reduction-88%](https://img.shields.io/badge/FP%20reduction-88%25-brightgreen)
![corpus-8/8](https://img.shields.io/badge/corpus-8%2F8-success)

**💡 Живой счётчик:** GSC запомнил **358** уязвимостей из **6** проектов. Следующий скан — умнее.

> Адаптивный аудитор кода. Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

**Для кого:** разработчики и команды, которым надоел шум от SonarQube/Semgrep.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре `f"SELECT {var}"`, но никогда не найдут:

- «В этом проекте `round(..., 2)` в финансах — баг, нужно 6 знаков»
- «После рефакторинга промокодов сломалась схема БД — `valid_from` стали `created_at`»
- «Этот конкретный паттерн TOCTOU уже 3 раза приводил к потере данных»

Такие находки рождаются из опыта на проектах. И они теряются сразу после аудита.

**GSC их сохраняет.**

## Что это

GSC — CLI-инструмент для поиска багов и уязвимостей с накоплением паттернов. Не просто линтер: каждая подтверждённая находка становится правилом для будущих сканов. Слабые паттерны автоматически отключаются.

**Сегодня работает:** 3 эшелона аудита, 277 seed-паттернов (7 языков), language-aware фильтрация, framework-aware AST-фильтр, авто-деактивация ложных паттернов, AI-патч (опционально), SARIF, diff-only, baseline, HTML-отчёты.

**Результат:** 82 находки на собственном коде GSC. Языковой фильтр: -66% FP. Framework-фильтр: -88% от исходного.

## 🚀 Установка и быстрый старт

**Требования:** Python 3.10+, ripgrep 13+ (бинарник — не pip!)

```bash
# 1. Установить ripgrep
brew install ripgrep      # macOS
sudo apt install ripgrep  # Linux

# 2. Клонировать и установить GSC
git clone https://github.com/poliakarmai/gsc.git
cd gsc
pip install .              # глобальная установка → команда gsc

# 3. Проверить окружение
gsc doctor

# 4. Первый аудит
gsc scan .

# 5. Триаж, diff-скан, baseline
gsc triage .
gsc scan . --diff
```

---

## Как это работает

```
Seed patterns (OWASP/CWE/7 языков)
        ↓
    gsc scan
        ↓
   E1: Source-driven (grep) → E2: Security (regex+perms) → E3: Adversarial (logic)
   E4: LLM deep analysis (--deep, опционально)
        ↓
   Language filter (Go паттерны не лезут в Python)
   Framework filter (AST: pickle в torch — норм)
        ↓
  Сохранение в SQLite + Obsidian
        ↓
   gsc triage → TP/FP → паттерны с эффективностью <30% → авто-деактивация
```

### Пример: от находки до паттерна

```python
# api/billing.py:147
def apply_discount(user_id, code):
    query = f"SELECT * FROM discounts WHERE code='{code}'"
    return db.execute(query)
```

```bash
$ gsc scan .
🔴 CRITICAL: SQL injection risk: f-string in query → api/billing.py:147

$ gsc fix 42
--- a/api/billing.py
+++ b/api/billing.py
-    query = f"SELECT * FROM discounts WHERE code='{code}'"
+    query = "SELECT * FROM discounts WHERE code=?"
-    return db.execute(query)
+    return db.execute(query, (code,))

$ gsc triage .  # [y] → TP+1 → следующий скан умнее
```

## 🏗️ Архитектура

```
~/.hermes/state/
    └── gsc_audit.db            ← SQLite (SSOT)
        ├── patterns (277+)     ← seed + learned
        ├── findings (358)      ← TP/FP/baseline
        └── audit_runs (8)      ← история сканов

~/obsidian-vault/audits/       ← Markdown-отчёты
    ├── gsc-patterns.md
    └── findings/*.md

<project>/.gsc/
    ├── config.yaml              ← per-project настройки
    └── baseline.json            ← suppressions
```

## 📊 Модель данных

**Seed patterns:** 277 правил из OWASP Top 10, CWE Top 25, и 7 языков.  
**Learned patterns:** находки, подтверждённые через `gsc triage` как TP.  
**TP/FP счётчики:** каждый паттерн хранит `true_positive_count` и `false_positive_count`.  
**Effectiveness:** `TP / (TP + FP)` — пересчитывается при каждом триаже.  
**Авто-деактивация:** при effectiveness < 30% AND ≥10 разметок паттерн отключается.

---

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов между аудитами | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация ложных паттернов | ✅ | ❌ | ❌ | ❌ |
| Language-aware + Framework-aware | ✅ | ✅ | ✅ | ✅ |
| AI-patch (опционально) | ✅ | ❌ | ❌ | ❌ |
| Автономный | ✅ | ❌ | ❌ | ✅ |
| Open source (MIT) | ✅ | ❌ | ❌ | ✅ |

## ⚠️ Ограничения

- Тестирован на 6 собственных проектах. На чужих — неизбежны ложные срабатывания.
- `--deep` и `gsc fix` отправляют код в OpenRouter. Enterprise: `GSC_LLM_PROVIDER=ollama`.
- Языки: Python, Go, TS, Rust, Java, Docker, Terraform. C/C++, PHP, Ruby — в roadmap.

---

## Команды

```bash
gsc scan <project>           # полный аудит (3 эшелона)
gsc scan <project> --diff    # только изменённые файлы (для PR)
gsc scan <project> --deep    # + E4 LLM-анализ
gsc scan <project> --sarif   # экспорт для GitHub Code Scanning

gsc triage <project>         # интерактивная разметка TP/FP
gsc triage <project> --group-by pattern  # массовый accept/reject кластеров
gsc explain <id>             # CVSS, threat/impact
gsc fix <id>                 # AI-патч (OpenRouter)

gsc init                     # .gsc/, hook, GitHub Actions workflow
gsc dashboard                # веб-интерфейс (:8080), триаж в браузере
gsc doctor                   # проверка Python, ripgrep, БД, паттернов
gsc metrics                  # precision/recall по паттернам и языкам
gsc config                   # настройки (vault, API-ключ, excludes)
gsc patterns export [file]   # экспорт паттернов в YAML
gsc patterns import <file>   # импорт из YAML
gsc patterns list            # список с эффективностью
gsc issue <id>               # тикет в Jira/Linear/Markdown
```

## ⚙️ Конфигурация

```bash
gsc config set obsidian_vault ~/vault    # путь к Obsidian
gsc config set llm_provider ollama       # локальная модель
gsc config set exclude_dirs "tests,vendor,node_modules"
gsc config show                          # текущие настройки
```

**Env vars:** `GSC_LLM_PROVIDER=ollama`, `GSC_DB_KEY=...`, `GSC_MAX_COST_USD=2.0`

Файлы: `~/.gsc/config.json` (глобальные), `<project>/.gsc/config.yaml` (per-project).

---

## Дорожная карта

| Фаза | Что | Срок | Статус |
|------|-----|------|--------|
| **1. CLI** | scan, triage, explain, fix, 277 паттернов, dashboard | Июль 2026 | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, baseline, Fernet | Август 2026 | ✅ |
| **3. Качество** | Corpus-тесты (8/8), lang filter (-66%), framework filter (-88%), HTML | Сентябрь 2026 | ✅ |
| **4. DX** | VSCode extension (требует Azure DevOps PAT) | Октябрь 2026 | 🔜 отложен |
| **5. Enterprise** | Helm chart (код готов), SSO (OAuth2), RBAC | Ноябрь 2026 | 🔜 |
| **6. Сеть** | Federated learning, pattern marketplace (SaaS) | Январь 2027 | 📋 |
| **7. Compliance** | PCI DSS, SOC2 auto-reports, evidence | Февраль 2027 | 🔜 mapping ✅ |

---

## CI/CD (GitHub Actions)

```yaml
- name: Install GSC
  run: pip install git+https://github.com/poliakarmai/gsc.git

- name: Run GSC Security Audit
  run: gsc scan . --diff --sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## ⚡ Производительность

| Метрика | Значение |
|---------|----------|
| Скан 10k LOC | <10 сек (без E4) |
| Скан 100k LOC | <60 сек |
| Размер БД (6 проектов) | ~2 MB |
| Память (peak) | <200 MB |

## Метрики

| Метрика | Значение |
|---------|----------|
| Seed-паттернов | 277 (7 языков) |
| Паттернов из находок | 62+ |
| Проектов отсканировано | 6 |
| Находок в базе (после фильтров) | 358 |
| Corpus-тестов | 8/8 pass |
| FP reduction (lang filter) | -66% |
| FP reduction (framework filter) | -88% от исходного |
| Precision (оценка по triage) | ~72% |

## 🔧 Troubleshooting

**`❌ ripgrep not found`** → `brew install ripgrep` (macOS) / `apt install ripgrep` (Linux).  
**`❌ Python 3.8`** → нужен Python 3.10+.  
**Слишком много finding'ов** → `gsc baseline --update`, затем `gsc scan --diff`.  
**LLM не работает** → `export GSC_LLM_PROVIDER=ollama` или проверь `OPENROUTER_API_KEY`.

---

## ❓ FAQ

**Q: Чем отличается от SonarQube/Semgrep?**  
A: GSC накапливает паттерны между аудитами и авто-деактивирует ложные.

**Q: Можно в CI/CD?** Да. `gsc scan --diff --sarif` + GitHub Actions.

**Q: Без интернета?** Да. Только `--deep`/`gsc fix` требуют OpenRouter (или локальный Ollama).

## 🔮 Что дальше

**Октябрь 2026:** VSCode extension, Jira/Linear, PDF export  
**Ноябрь 2026:** Helm chart, SSO (OAuth2), RBAC  
**Январь 2027:** Federated learning, pattern marketplace (SaaS)  
**Февраль 2027:** PCI DSS/SOC2 auto-reports

## 🤝 Контрибьюция

- **Python:** новые паттерны для Django/Flask/FastAPI
- **Security:** OWASP/CWE/NIST-покрытие, compliance mapping
- **DevOps:** GitLab CI, Helm charts, Docker
- **Другие языки:** Go (net/http, gin), TypeScript (Express, Next.js), Rust (actix-web)

[Issue](https://github.com/poliakarmai/gsc/issues) → PR.

## 📄 Лицензия

MIT License — см. [LICENSE](./LICENSE).

## 🚀 Попробуй сейчас

```bash
git clone https://github.com/poliakarmai/gsc.git
cd gsc && pip install .
gsc scan .  # первый аудит за 10 секунд
```
