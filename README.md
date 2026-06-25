# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![patterns-112](https://img.shields.io/badge/patterns-112-green)
![python-3.10+](https://img.shields.io/badge/python-3.10+-blue)
![self-learning](https://img.shields.io/badge/self--learning-active-brightgreen)

> Самообучающийся аудитор кода. Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

**Для кого:** команд, которые хотят находить специфичные для их проекта баги, а не тысячу generic-предупреждений.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре, но никогда не найдут специфичные для вашего проекта баги: «здесь `round(..., 2)` должен быть `round(..., 6)`», «после рефакторинга `valid_from` стал `created_at`».

Такие находки рождаются из опыта и теряются после аудита. **GSC их сохраняет и переиспользует.**

## Что это

CLI-инструмент с накоплением паттернов и **автономным самообучением**. Каждый день сканирует 10 open-source проектов, авто-триажит находки (эвристики + LLM для CRITICAL/HIGH), и слабые паттерны отключаются автоматически.

**Работает:** 3+1 эшелон (source → security → adversarial → LLM), 112 seed-паттернов (7 языков), docstring/comment фильтр, language-aware + AST-фильтры, авто-деактивация FP (<30% эффективности), AI-патч, SARIF, diff-only, baseline, ежедневное самообучение.

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

## Архитектура

```
                    ┌── Самообучение (ежедневно, 04:00) ──┐
                    │  10 проектов → scan → авто-триаж    │
                    │  Эвристики + LLM (CRITICAL/HIGH)    │
                    │  Паттерны <30% → авто-деактивация   │
                    └──────────────┬──────────────────────┘
                                   ↓
Seed patterns (OWASP/CWE/7 языков) + ваши паттерны + накопленные
        ↓  gsc scan
   E1: Source-driven (grep) → E2: Security (regex+perms) → E3: Adversarial
   E4: LLM deep analysis (--deep, опционально)
        ↓  docstring/comment фильтр → language + AST фильтры
   SQLite (WAL mode, concurrent-safe) + Obsidian notes
        ↓  gsc triage → TP/FP
   Паттерны с эффективностью <30% AND ≥10 оценок → авто-деактивация
```

## Пример

```python
# api/billing.py:147
query = f"SELECT * FROM discounts WHERE code='{code}'"
```
```bash
$ gsc scan .          # → CRITICAL: SQL injection risk
$ gsc fix 42          # → AI-патч: f-string → параметризованный запрос
$ gsc triage .        # [y] → TP+1 → следующий скан умнее
```

## Бенчмарк на open-source проектах

| Проект | ⭐ | Находок | CRIT (реальных) | HIGH | Шум |
|--------|---|:------:|:---:|:----:|:---:|
| requests | 52k | 131 | 0 | 3 | высокий |
| flask | 68k | 16 | 0 | 10 | высокий |
| httpx | 14k | 30 | 0 | 3 | высокий |
| rich | 52k | 59 | 0 | 9 | высокий |
| fastapi | 82k | 101 | 1¹ | 7 | высокий |
| numpy | 29k | 591 | 5² | 33 | высокий |
| **Наши проекты** | — | — | **реальные** | — | **низкий** |

¹ Type-annotation, не баг. ² C-препроцессор + guarded `pickle.load()`.

> ⚠️ **Честно:** на чужих проектах шум высокий. GSC оптимизирован под нашу кодовую базу — паттерны выросли из реальных багов. Самообучение (10 проектов/день) постепенно снижает шум: слабые паттерны отключаются, сильные накапливают статистику. При сканировании незнакомого кода воспринимайте находки как «подозрительные места».

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов между аудитами | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация ложных паттернов | ✅ | ❌ | ❌ | ❌ |
| **Автономное самообучение** | ✅ | ❌ | ❌ | ❌ |
| **LLM-триаж (CRITICAL/HIGH)** | ✅ | ❌ | ❌ | ❌ |
| Docstring/comment фильтр | ✅ | ✅ | ✅ | ✅ |
| Language-aware + AST фильтры | ✅ | ✅ | ✅ | ✅ |
| AI-патч (gsc fix) | ✅ | ❌ | ❌ | ❌ |
| LLM deep analysis (--deep) | ✅ | ❌ | ❌ | ❌ |
| Автономный (не требует сервера) | ✅ | ❌ | ❌ | ✅ |
| Open source (MIT) | ✅ | ❌ | ❌ | ✅ |

> ⚠️ `--deep`/`gsc fix` отправляют код в OpenRouter. Для enterprise: `GSC_LLM_PROVIDER=ollama`.

---

## Команды

```bash
gsc scan <project>              # полный аудит
gsc scan <project> --diff       # только изменённые файлы
gsc scan <project> --deep       # LLM-анализ (Echelon 4)
gsc scan <project> --sarif      # SARIF для GitHub Code Scanning
gsc triage <project>            # разметка TP/FP
gsc triage <project> --group-by pattern  # кластерами
gsc explain <id>                # CVSS, threat/impact
gsc fix <id>                    # AI-патч (OpenRouter)
gsc init                        # .gsc/, CI workflow
gsc dashboard                   # веб (:8080)
gsc doctor                      # диагностика
gsc metrics                     # precision/recall
gsc patterns export [file]      # экспорт YAML
gsc patterns import <file>      # импорт YAML
gsc config set <key> <value>    # настройка
```

## Самообучение

```bash
# Запустить один цикл вручную
python3 ~/.hermes/scripts/gsc_self_learn.py

# Посмотреть статистику
python3 ~/.hermes/scripts/gsc_self_learn.py --stats

# Dry-run (какие проекты будут сегодня)
python3 ~/.hermes/scripts/gsc_self_learn.py --dry-run
```

**Механика:** каждый день в 04:00 — 10 проектов из ротации (53 Python-проекта) → scan → авто-триаж:
- Эвристики: test-файлы, docstrings, config-файлы → авто-FP
- E4 LLM (gemini-flash): CRITICAL/HIGH находки → REAL/FALSE
- Накопление статистики → паттерны с эффективностью <30% отключаются

## ⚙️ Конфигурация

```bash
gsc config set obsidian_vault ~/vault
gsc config set llm_provider ollama
gsc config show
```

Env vars: `GSC_LLM_PROVIDER=ollama`, `OPENROUTER_API_KEY=...`

## Дорожная карта

| Фаза | Что | Статус |
|------|-----|--------|
| **1. CLI** | scan, triage, explain, fix, 112 паттернов, dashboard | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, baseline, WAL | ✅ |
| **3. Качество** | Corpus-тесты (8/8), docstring-фильтр, AST-фильтр, метрики | ✅ |
| **4. LLM** | E4 deep analysis (--deep), gsc fix, LLM-триаж в самообучении | ✅ |
| **5. Самообучение** | Ежедневный цикл, 53 проекта, авто-триаж, авто-деактивация | ✅ |
| **6. DX** | VSCode extension, Jira/Linear, Pattern marketplace | 🔜 |
| **7. Enterprise** | Helm chart, SSO (OAuth2), Compliance (PCI/SOC2/ISO) | 🔜 |

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

## 🔧 Troubleshooting

**`❌ ripgrep`** → `brew install ripgrep` / `apt install ripgrep`.  
**Слишком много FP** → `gsc triage` разметить, `gsc baseline --update`, затем `gsc scan --diff`.  
**LLM не работает** → `GSC_LLM_PROVIDER=ollama` или проверь `OPENROUTER_API_KEY`.

## 📄 Лицензия

MIT — см. [LICENSE](./LICENSE).

## 📚 Документация

- [Установка](docs/INSTALL.md)
- [Использование](docs/USAGE.md)
- [Паттерны](docs/PATTERNS.md)
- [Конфигурация](docs/CONFIG.md)
- [Compliance](docs/compliance.md)
