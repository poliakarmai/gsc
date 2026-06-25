# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![patterns-277](https://img.shields.io/badge/patterns-277-green)

> Адаптивный аудитор кода. Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

**Для кого:** разработчики, которым надоел шум от статических анализаторов.

## 🤔 Проблема

Статические анализаторы работают по жёстким правилам. Они находят `SQL injection` по сигнатуре, но никогда не найдут специфичные для вашего проекта баги: «здесь `round(..., 2)` должен быть `round(..., 6)`», «после рефакторинга `valid_from` стал `created_at`».

Такие находки рождаются из опыта. И теряются после аудита. **GSC их сохраняет.**

## Что это

CLI-инструмент с накоплением паттернов. Каждая подтверждённая находка становится правилом для будущих сканов. Слабые паттерны отключаются автоматически.

**Работает:** 3 эшелона, 277 seed-паттернов (7 языков), language-aware + AST-фильтры, авто-деактивация FP, AI-патч (опционально), SARIF, diff-only, baseline.

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
Seed patterns (OWASP/CWE/7 языков)
        ↓  gsc scan
   E1: Source-driven (grep) → E2: Security (regex+perms) → E3: Adversarial
   E4: LLM deep analysis (--deep, опционально)
        ↓  language + framework filters
   SQLite (WAL mode, concurrent-safe) + Obsidian notes
        ↓  gsc triage → TP/FP
   Паттерны с эффективностью <30% AND ≥10 оценок → авто-деактивация
```

### Пример

```python
# api/billing.py:147
query = f"SELECT * FROM discounts WHERE code='{code}'"
```
```bash
$ gsc scan .          # → CRITICAL: SQL injection risk
$ gsc fix 42          # → AI-патч: f-string → параметризованный запрос
$ gsc triage .        # [y] → TP+1 → следующий скан умнее
```

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация FP | ✅ | ❌ | ❌ | ❌ |
| AST-анализ импортов | ✅ | ❌ | ❌ | ❌ |
| AI-патч (опционально) | ✅ | ❌ | ❌ | ❌ |
| Автономный | ✅ | ❌ | ❌ | ✅ |
| Open source (MIT) | ✅ | ❌ | ❌ | ✅ |

> ⚠️ `--deep`/`gsc fix` отправляют код в OpenRouter. Для enterprise: `GSC_LLM_PROVIDER=ollama`.

## ⚠️ Ограничения

- **Тестирован на 6 собственных проектах.** На чужих репозиториях будут ложные срабатывания.
- **Языки:** Python, Go, TS, Rust, Java, Docker, Terraform.
- **Нет проверки зависимостей** (requirements.txt, package.json).
- **LLM-анализ требует OpenRouter** или локальный Ollama.

---

## Команды

```bash
gsc scan <project>              # полный аудит
gsc scan <project> --diff       # только изменённые файлы
gsc scan <project> --sarif      # SARIF для GitHub Code Scanning
gsc triage <project>            # разметка TP/FP
gsc triage <project> --group-by pattern  # кластерами
gsc explain <id>                # CVSS, threat/impact
gsc fix <id>                    # AI-патч
gsc init                        # .gsc/, hook, CI workflow
gsc dashboard                   # веб (:8080)
gsc doctor                      # диагностика
gsc metrics                     # precision/recall
gsc patterns export [file]      # экспорт YAML
gsc patterns import <file>      # импорт YAML
gsc issue <id>                  # тикет Jira/Linear/Markdown
```

## ⚙️ Конфигурация

```bash
gsc config set obsidian_vault ~/vault
gsc config set llm_provider ollama
gsc config show
```

Env vars: `GSC_LLM_PROVIDER=ollama`, `GSC_DB_KEY=...`, `OPENROUTER_API_KEY=...`

## Дорожная карта

---

## Дорожная карта

| Фаза | Что | Статус |
|------|-----|--------|
| **1. CLI** | scan, triage, explain, fix, 277 паттернов, dashboard | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, baseline, WAL | ✅ |
| **3. Качество** | Corpus-тесты, языковой фильтр, AST-фильтр, HTML-отчёты | ✅ |
| **4. DX** | VSCode extension, Jira/Linear | 🔜 |
| **5. Enterprise** | Helm chart, SSO, RBAC | 🔜 |
| **6. Ecosystem** | Pattern marketplace, dependency scanning | 📋 |

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
**Слишком много FP** → `gsc baseline --update`, затем `gsc scan --diff`.  
**LLM не работает** → `GSC_LLM_PROVIDER=ollama` или проверь `OPENROUTER_API_KEY`.

## 🤝 Контрибьюция

Новые паттерны (Django/Flask/FastAPI), OWASP/CWE-покрытие, CI/CD шаблоны. [Issue](https://github.com/poliakarmai/gsc/issues) → PR.

## 📄 Лицензия

MIT — см. [LICENSE](./LICENSE).

## 📚 Документация

- [Установка](docs/INSTALL.md)
- [Использование](docs/USAGE.md)
- [Паттерны](docs/PATTERNS.md)
- [Конфигурация](docs/CONFIG.md)
- [Compliance](docs/compliance.md)
