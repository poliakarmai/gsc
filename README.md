# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![patterns-112](https://img.shields.io/badge/patterns-112-green)
![python-3.10+](https://img.shields.io/badge/python-3.10+-blue)
![precision-73%](https://img.shields.io/badge/precision-73%25-yellow)

> Самообучающийся аудитор кода. Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре, но пропускают специфичные для вашего проекта баги: «здесь `round(..., 2)` должен быть `round(..., 6)`», «после рефакторинга `valid_from` стал `created_at`».

Такие находки рождаются из опыта и теряются после аудита. **GSC их сохраняет и переиспользует.**

## Что это

CLI-инструмент с накоплением паттернов и **самообучением**. Каждый день сканирует свежие open-source проекты, авто-триажит находки, и слабые паттерны отключаются.

**Текущее состояние (v0.5):**
- 112 активных паттернов (7 языков), авто-создание новых из TP (≥3 подтверждений)
- 3+1 эшелон: source → security → adversarial → LLM (`--deep`)
- Precision: **73%** (104 TP / 38 FP, ручная разметка), 34 000+ находок в базе
- Фильтры: docstring/comment, language + AST, **inline suppression** (`# gsc:ignore`), **reachability** (`--reachability`)
- Самообучение: 53 проекта, daily cron, **multi-LLM voting** (gemini + qwen), **severity-weighted** деактивация (CRITICAL защищены)
- AI-патч (`gsc fix`), SARIF, diff-only, baseline, **PR comments**

> **Почему 112, а не 277?** v0.3 генерировал 178 одинаковых «Generic code smell» паттернов — все матчились на `TODO|FIXME`. В v0.4 они деактивированы как бесполезные. Взамен добавлены 12 точных Python-паттернов (asyncio, subprocess, multiprocessing). **Реальных правил стало больше, а не меньше.**

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

## Как это работает

```
Seed patterns (OWASP/CWE/7 языков) + ваши + накопленные самообучением
        ↓  gsc scan
   E1: Source-driven (grep) → E2: Security (regex+perms) → E3: Adversarial
   E4: LLM deep analysis (--deep, опционально)
        ↓  docstring/comment фильтр → language + AST фильтры
   SQLite (WAL mode) + Obsidian notes
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

Честные цифры — что GSC находит на чужом коде без предварительной разметки:

| Проект | ⭐ | Всего | CRIT (сырых) | CRIT (реальных) | HIGH | Precision |
|--------|---|:----:|:---:|:---:|:----:|:---:|
| requests | 52k | 131 | 0 | 0 | 3 | — |
| flask | 68k | 16 | 0 | 0 | 10 | — |
| httpx | 14k | 30 | 0 | 0 | 3 | — |
| rich | 52k | 59 | 0 | 0 | 9 | — |
| fastapi | 82k | 101 | 1 | 0¹ | 7 | 0% |
| numpy | 29k | 591 | 5 | 0² | 33 | 0% |
| **Наши проекты** | — | ~200 | **реальные** | **реальные** | — | **73%** |

¹ Type-annotation `password: OAuthFlowPassword | None = None`. ² C-препроцессор `__f2py_cb_#name#` + guarded `pickle.load()` с проверкой `allow_pickle`.

> **Вывод:** на чужих проектах без разметки Precision ≈ 0%. GSC не универсальный сканер — он инструмент для **вашей** кодовой базы. После 2-3 недель разметки (`gsc triage`) точность на вашем коде растёт до 70%+. Самообучение ускоряет этот процесс.

### Производительность

| Проект | LOC | Время скана |
|--------|----:|:----------:|
| flask | 35k | 2.1 сек |
| requests | 18k | 1.4 сек |
| rich | 42k | 2.8 сек |
| numpy | 280k | 14.3 сек |
| fastapi | 190k | 9.7 сек |

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация FP | ✅ * | ❌ | ❌ | ❌ |
| Самообучение (daily) | ✅ | ❌ | ❌ | ❌ |
| Language + AST фильтры | ✅ | ✅ | ✅ | ✅ |
| AI-патч (`gsc fix`) | ✅ | ❌ | ❌ | ❌ |
| LLM deep analysis | ✅ | ❌ | ❌ | ❌ |
| Dependency scanning | 🔜 | ✅ | ✅ | ❌ |
| Шифрование БД | 🔜 | ✅ | ❌ | ❌ |
| Автономный | ✅ | ❌ | ❌ | ✅ |
| Open source (MIT) | ✅ | ❌ | ❌ | ✅ |

\* При ≥10 оценках и эффективности <30%.

> ⚠️ `--deep`/`gsc fix` отправляют код в OpenRouter. Для enterprise: `GSC_LLM_PROVIDER=ollama` (локальная модель, код не покидает контур).

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
gsc dashboard                   # веб-интерфейс
gsc doctor                      # диагностика окружения
gsc metrics                     # precision/recall
gsc patterns export [file]      # экспорт YAML
gsc patterns import <file>      # импорт YAML
gsc config set <key> <value>    # настройка
```

## Самообучение

Ежедневный цикл (cron, 04:00) — 10 проектов из ротации (53 Python-проекта) → scan → авто-триаж → накопление статистики → авто-деактивация слабых паттернов.

```bash
python3 scripts/gsc_self_learn.py           # ручной запуск цикла
python3 scripts/gsc_self_learn.py --stats   # статистика
python3 scripts/gsc_self_learn.py --dry-run # какие проекты сегодня
```

**Авто-триаж:**
- Уровень 1 (быстрый): test-файлы, docstrings, config-файлы → авто-FP
- Уровень 2 (LLM): CRITICAL/HIGH находки → gemini-flash решает REAL/FALSE
- При ошибке LLM или недоступности API → находка остаётся «open» (консервативно)

> **Где запускать:** скрипт самодостаточен — работает на любой машине с Python и доступом в интернет. Может быть запущен как cron, systemd timer, GitHub Actions, или вручную. База данных (`gsc_audit.db`) — единый источник.

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
| **1. CLI** | scan, triage, explain, fix, dashboard, 112 паттернов | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit (baseline-aware), WAL | ✅ |
| **3. Качество** | Corpus-тесты (8/8), docstring-фильтр, AST-фильтр, метрики | ✅ |
| **4. LLM** | E4 deep analysis, gsc fix, LLM-триаж в самообучении | ✅ |
| **5. Самообучение** | Ежедневный цикл, 53 Python-проекта, авто-триаж, авто-деактивация | ✅ |
| **6. Мультиязычность** | Самообучение на Go, TS, Rust, Java, Docker, Terraform (сейчас только Python) | 🔜 Июль 2026 |
| **7. Dependency scanning** | pip-audit, npm audit, cargo-audit — проверка зависимостей в requirements.txt, package.json, Cargo.toml | 🔜 Июль 2026 |
| **8. Шифрование БД** | Fernet-шифрование `gsc_audit.db` (AES-128) — защита находок при хранении и передаче | 🔜 Август 2026 |
| **9. DX** | VSCode extension, Jira/Linear, Pattern marketplace | 🔜 Август 2026 |
| **10. Enterprise** | Helm chart, SSO (OAuth2), Compliance (PCI/SOC2/ISO), RBAC | 📋 2027 |

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

**`❌ ripgrep`** → `brew install ripgrep` / `apt install ripgrep` (бинарник, не pip).  
**Слишком много FP** → `gsc triage` разметить 2-3 недели → точность вырастет до 70%+.  
**LLM не работает** → `GSC_LLM_PROVIDER=ollama` или проверь `OPENROUTER_API_KEY`.

## 📄 Лицензия

MIT — см. [LICENSE](./LICENSE).

## 📚 Документация

- [Установка](docs/INSTALL.md)
- [Использование](docs/USAGE.md)
- [Паттерны](docs/PATTERNS.md)
- [Конфигурация](docs/CONFIG.md)
- [Compliance](docs/compliance.md)
