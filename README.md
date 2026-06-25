# 🔒 GSC — Git Security Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![patterns-277](https://img.shields.io/badge/patterns-277-green)
![fp-reduction-88%](https://img.shields.io/badge/FP%20reduction-88%25-brightgreen)
![corpus-8/8](https://img.shields.io/badge/corpus-8%2F8-success)

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

**Сегодня работает:**
- 3 эшелона аудита (Source → Security → Adversarial)
- 277 seed-паттернов (Python, Go, TS, Rust, Java, Docker, Terraform)
- Language-aware фильтрация (Go-паттерны не лезут в Python)
- Framework-aware фильтрация (AST-анализ импортов, ML/ORM контекст)
- Авто-деактивация ложных паттернов (< 30% эффективности)
- AI-патч через OpenRouter (опционально)
- SARIF-экспорт для GitHub Code Scanning
- Diff-only scan для PR
- Baseline/suppressions для CI

**Результат на своём проекте:** 388 → 46 находок. **88% шума отфильтровано.**

## 🚀 Установка и быстрый старт

**Требования:** Python 3.10+, ripgrep 13+ (бинарник, не pip!)

```bash
# 1. Установить ripgrep
brew install ripgrep      # macOS
sudo apt install ripgrep  # Linux

# 2. Клонировать GSC
git clone https://github.com/poliakarmai/gsc.git
cd gsc

# 3. Проверить окружение
python3 gsc.py doctor

# 4. Первый аудит
python3 gsc.py scan .

# 5. Интерактивный триаж (разметка TP/FP)
python3 gsc.py triage .

# 6. Сканировать только изменённые файлы (для PR)
python3 gsc.py scan . --diff
```

---

## Как это работает

### Архитектура

```
Seed patterns (OWASP/CWE/7 языков)
        ↓
    gsc scan
        ↓
   E1: Source-driven (grep по коду)
   E2: Security (regex + права файлов)
   E3: Adversarial (логические паттерны)
   E4: LLM deep analysis (--deep, опционально)
        ↓
   Language filter (Go паттерны не лезут в Python)
   Framework filter (AST-анализ: pickle в torch — норм)
        ↓
  Сохранение в SQLite + Obsidian
        ↓
   gsc triage → TP/FP разметка
        ↓
  Паттерны с эффективностью <30% → авто-деактивация
  Новые подтверждённые находки → становятся паттернами
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
🔴 CRITICAL: SQL injection risk: f-string in query
   File: api/billing.py:147 | CVSS: 8.6

$ gsc fix 42
🔧 GSC fix #42: SQL injection risk
--- a/api/billing.py
+++ b/api/billing.py
-    query = f"SELECT * FROM discounts WHERE code='{code}'"
+    query = "SELECT * FROM discounts WHERE code=?"
-    return db.execute(query)
+    return db.execute(query, (code,))

$ gsc triage .  # [y] accept → TP+1 → следующий скан умнее
```

---

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов между аудитами | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация ложных паттернов | ✅ | ❌ | ❌ | ❌ |
| Language-aware фильтрация | ✅ | ✅ | ✅ | ✅ |
| Framework-aware (AST импортов) | ✅ | ❌ | ❌ | ❌ |
| AI-patch (опционально) | ✅ | ❌ | ❌ | ❌ |
| Автономный | ✅ | ❌ | ❌ | ✅ |
| Open source (MIT) | ✅ | ❌ | ❌ | ✅ |

> ⚠️ `--deep` и `gsc fix` отправляют код в OpenRouter API. Для enterprise: `GSC_LLM_PROVIDER=ollama`.

## ⚠️ Ограничения

- **Тестирован на 6 собственных проектах.** На чужих репозиториях неизбежны ложные срабатывания — для этого triage и авто-деактивация.
- **LLM-анализ отправляет код в OpenRouter.** Для enterprise используйте локальную модель: `GSC_LLM_PROVIDER=ollama`.
- **Языки:** Python, Go, TS, Rust, Java, Docker, Terraform. C/C++, PHP, Ruby — в roadmap.
- **Compliance-маппинг — не сертификация.** GSC показывает соответствие стандартам, но не заменяет официальный аудит.

---

## Команды

```bash
gsc scan <project>           # полный аудит
gsc scan <project> --diff    # только изменённые файлы (PR)
gsc scan <project> --deep    # + E4 LLM-анализ
gsc scan <project> --sarif   # экспорт для GitHub Code Scanning

gsc triage <project>         # интерактивная разметка TP/FP
gsc triage <project> --group-by pattern  # массовый accept/reject
gsc explain <id>             # CVSS, threat/impact
gsc fix <id>                 # AI-патч

gsc init                     # установка в проект (.gsc/, hook, CI)
gsc dashboard                # веб-интерфейс (:8080)
gsc doctor                   # диагностика
gsc metrics                  # precision/recall
gsc config                   # настройки
gsc patterns export          # экспорт паттернов в YAML
gsc patterns import <file>   # импорт паттернов из YAML
gsc issue <id>               # тикет в Jira/Linear
```

---

## Дорожная карта

| Фаза | Что | Срок | Статус |
|------|-----|------|--------|
| **1. CLI** | scan, triage, explain, fix, 277 паттернов, dashboard | Июль 2026 | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, baseline, Fernet | Август 2026 | ✅ |
| **3. Качество** | Corpus-тесты (8/8), lang filter (-66%), framework filter (-88%), HTML | Сентябрь 2026 | ✅ |
| **4. DX** | VSCode extension, Jira/Linear, PDF export | Октябрь 2026 | 🔜 |
| **5. Enterprise** | Helm chart, SSO (OAuth2 Proxy), RBAC | Ноябрь 2026 | 🔜 |
| **6. Сеть** | Federated learning, pattern marketplace (SaaS) | Январь 2027 | 📋 |
| **7. Compliance** | PCI DSS, SOC2 auto-reports, evidence collection | Февраль 2027 | 🔜 |

---

## CI/CD (GitHub Actions)

```yaml
- name: Run GSC Security Audit
  run: |
    python3 ~/gsc/gsc.py scan . --diff --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Метрики

| Метрика | Значение |
|---------|----------|
| Seed-паттернов | 277 (7 языков) |
| Паттернов из находок | 62+ |
| Проектов отсканировано | 6 |
| Находок в базе | 358 |
| Corpus-тестов | 8/8 pass |
| FP reduction (lang filter) | -66% |
| FP reduction (framework filter) | -88% от исходного |
| Precision (оценка по triage) | ~72% |

## 📖 Case Study: bybit-ws

**Проект:** Python-трейдинг-монитор Bybit (15k LOC)

| Этап | Находок | Критических |
|------|---------|-------------|
| Сырой скан | 388 | 22 |
| Language filter | 133 (-66%) | 20 |
| Framework filter | 46 (-88%) | 2 |
| После triage (5 мин) | 2 | 0 |

**Реальные находки:** SQL injection в `dspy_optimizer.py`, TOCTOU в `save_state()`.  
**Время:** 4 минуты вместо часов ручного ревью.

## Obsidian Integration

GSC генерирует Markdown-заметки, создавая связи между уязвимостями, файлами и паттернами в вашем Obsidian vault. Откройте `obsidian-vault/audits/` — и увидите граф безопасности проекта.

## Dashboard

`gsc dashboard` — веб-интерфейс на :8080: Top-10 шумных паттернов, статус триажа (TP/FP), график накопления находок.

---

## ❓ FAQ

**Q: Чем отличается от SonarQube/Semgrep?**  
A: GSC накапливает паттерны между аудитами и авто-деактивирует ложные. SonarQube/Semgrep — жёсткие правила.

**Q: Можно ли в CI/CD?**  
A: Да. `gsc scan --diff --sarif` + GitHub Actions. Pre-commit hook прилагается.

**Q: Как работает самообучение?**  
A: `gsc triage` → счётчики TP/FP обновляются → эффективность <30% → авто-деактивация.

**Q: Можно без интернета?**  
A: Да. Только `--deep` и `gsc fix` требуют OpenRouter (или локальный Ollama).

## 🔮 Что дальше

**Октябрь 2026 (Фаза 4):** VSCode extension, Jira/Linear, PDF export  
**Ноябрь 2026 (Фаза 5):** Helm chart, SSO, RBAC  
**Январь 2027 (Фаза 6):** Federated learning, pattern marketplace (SaaS)  
**Февраль 2027 (Фаза 7):** PCI DSS/SOC2 auto-reports

## 🤝 Контрибьюция

- **Python-разработчики:** новые паттерны, интеграции с языками
- **Security-инженеры:** OWASP/CWE/NIST-покрытие
- **DevOps:** CI/CD шаблоны, Helm-чарты

[Issue](https://github.com/poliakarmai/gsc/issues) → PR.

## 📄 Лицензия

MIT License — см. [LICENSE](./LICENSE).

## 🚀 Попробуй сейчас

```bash
git clone https://github.com/poliakarmai/gsc.git
cd gsc
python3 gsc.py scan .  # первый аудит за 10 секунд
```
