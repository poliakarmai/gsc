# 🔒 GSC — Git Security Checker

> Адаптивный аудитор кода. Находит уязвимости, запоминает паттерны, умнеет с каждым проектом.

## Что это

GSC — CLI-инструмент для поиска багов и уязвимостей с накоплением паттернов. Не просто линтер: каждая подтверждённая находка становится правилом для будущих сканов. Слабые паттерны автоматически отключаются.

**Для кого:** разработчики и команды, которым надоел шум от SonarQube/Semgrep.

**Сегодня работает:**
- 3 эшелона аудита (Source → Security → Adversarial)
- 277 seed-паттернов (Python, Go, TS, Rust, Java, Docker, Terraform)
- Language-aware фильтрация (Go-паттерны не лезут в Python)
- Авто-деактивация ложных паттернов (< 30% эффективности)
- AI-патч через OpenRouter (опционально)
- SARIF-экспорт для GitHub Code Scanning

**Результат:** 388 → 133 находки на своём проекте after language filter. 66% шума отфильтровано.

```bash
pip install ripgrep  # единственная зависимость
git clone https://github.com/poliakarmai/gsc.git
python3 gsc.py scan my-project
```

---

## Как это работает

### Модель данных

```
Seed patterns (OWASP/CWE/7 языков)
        ↓
    gsc scan
        ↓
   E1: Source-driven (grep по коду)
   E2: Security (regex + права файлов)
   E3: Adversarial (логические паттерны)
   E4: LLM deep analysis (опционально, --deep)
        ↓
  Сохранение в SQLite + Obsidian
        ↓
   gsc triage → TP/FP разметка
        ↓
  Паттерны с эффективностью <30% → авто-деактивация
  Новые подтверждённые находки → становятся паттернами
```

### Пример: от находки до паттерна

**Код:**
```python
# api/billing.py:147
def apply_discount(user_id, code):
    query = f"SELECT * FROM discounts WHERE code='{code}'"
    return db.execute(query)
```

**Скан:**
```bash
$ gsc scan pci-index
🔴 CRITICAL: SQL injection risk: f-string in query
   File: api/billing.py:147
   Pattern: sql-injection-fstring (seed, E2)
   CVSS: 8.6
```

**Объяснение:**
```bash
$ gsc explain 42
🔍 #42: SQL injection risk: f-string in query
   Threat: Remotely exploitable
   Impact: CVSS 8.6 — злоумышленник может читать/менять БД
```

**AI-фикс:**
```bash
$ gsc fix 42
🔧 GSC fix #42: SQL injection risk
   Analyzing with OpenRouter...

--- a/api/billing.py
+++ b/api/billing.py
@@ -145,7 +145,7 @@
 def apply_discount(user_id, code):
-    query = f"SELECT * FROM discounts WHERE code='{code}'"
+    query = "SELECT * FROM discounts WHERE code=?"
-    return db.execute(query)
+    return db.execute(query, (code,))
```

**Триаж:** пользователь подтверждает находку (TP) → счётчик `true_positive` растёт → следующий скан находит похожие паттерны быстрее.

---

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов между аудитами | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация ложных паттернов | ✅ | ❌ | ❌ | ❌ |
| Language-aware фильтрация | ✅ | ✅ | ✅ | ✅ |
| LLM deep analysis (опционально) | ✅ | ❌ | ❌ | ❌ |
| AI-generate patch | ✅ | ❌ | ❌ | ❌ |
| Автономный (не требует сервера) | ✅ | ❌ | ❌ | ✅ |
| Open source | ✅ | ❌ | ❌ | ✅ |

> 90% находок — grep/regex (< 1 сек). E4 LLM подключается через `--deep` для сложных логических паттернов. AI-патч через `gsc fix` опционален и требует OpenRouter API.

---

## Команды

```bash
gsc scan <project>           # полный аудит
gsc scan <project> --diff    # только изменённые файлы
gsc scan <project> --deep    # + E4 LLM-анализ
gsc scan <project> --sarif   # экспорт для GitHub Code Scanning

gsc triage <project>         # интерактивная разметка TP/FP
gsc explain <id>             # CVSS, threat/impact
gsc fix <id>                 # AI-generate patch

gsc init                     # установка в проект (.gsc/, hook, CI)
gsc dashboard                # веб-интерфейс (:8080)
gsc doctor                   # диагностика окружения
gsc encrypt-db               # шифрование БД (Fernet)
```

---

## Дорожная карта

| Фаза | Что | Статус |
|------|-----|--------|
| **1. CLI** | scan, triage, explain, fix, 277 паттернов, dashboard | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, шифрование | ✅ |
| **3. Качество** | Corpus-тесты (8/8), language filter (-66% FP), precision/recall | 🔜 |
| **4. DX** | VSCode extension, Jira/Linear, HTML/PDF export | 📋 |
| **5. Enterprise** | SSO, RBAC, Helm chart, multi-tenancy | 📋 |
| **6. Экосистема** | Pattern marketplace, community rules, bug bounty | 📋 |

---

## Метрики

| Метрика | Значение |
|---------|----------|
| Seed-паттернов | 277 (7 языков) |
| Паттернов из находок | 62+ |
| Проектов отсканировано | 6 |
| Находок в базе | 358 |
| Corpus-тестов | 8/8 pass |
| FP reduction (lang filter) | -66% |
| Precision (оценка) | растёт с каждым triage |

> ⚠️ GSC тестирован на 6 собственных проектах. На чужих репозиториях неизбежны ложные срабатывания — для этого triage и авто-деактивация.

---

## Установка

```bash
pip install ripgrep
git clone https://github.com/poliakarmai/gsc.git
cd gsc

# Первый запуск
python3 gsc.py doctor          # проверка окружения
python3 gsc.py scan my-project # первый аудит
```
