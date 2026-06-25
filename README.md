# 🔒 GSC — Git Security Checker

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
- Compliance-отчёты (PCI DSS, SOC2, ISO 27001)
- SSO через OAuth2 Proxy (Google/Auth0/Okta/Azure AD)
- Pattern marketplace (экспорт/импорт YAML)
- Helm chart для Kubernetes

**Результат на своём проекте:** 388 → 46 находок. **88% шума отфильтровано.**

## Быстрый старт

```bash
# Требования: Python 3.10+, ripgrep 13+
python3 --version  # должно быть 3.10+

# 1. Установить ripgrep (бинарник, не pip!)
brew install ripgrep      # macOS
sudo apt install ripgrep  # Linux

# 2. Клонировать GSC
git clone https://github.com/poliakarmai/gsc.git
cd gsc

# 3. Первый аудит
python3 gsc.py scan my-project

# 4. Интерактивный триаж (разметка TP/FP)
python3 gsc.py triage my-project

# 5. Обновить baseline (игнорировать известные находки)
python3 gsc.py baseline --update

# 6. Сканировать только изменённые файлы (для PR)
python3 gsc.py scan my-project --diff
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

### Модель данных

- **Seed patterns:** 277 правил из OWASP Top 10, CWE Top 25, и 7 языков
- **Learned patterns:** находки, подтверждённые через `gsc triage` как TP
- **TP/FP счётчики:** каждый паттерн хранит `true_positive_count` и `false_positive_count`
- **Effectiveness:** `TP / (TP + FP)` — пересчитывается при каждом триаже
- **Авто-деактивация:** при effectiveness < 30% AND ≥10 разметок паттерн отключается

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
   CVSS: 8.6
```

**AI-фикс:**
```bash
$ gsc fix 42
🔧 GSC fix #42: SQL injection risk

--- a/api/billing.py
+++ b/api/billing.py
@@ -145,7 +145,7 @@
 def apply_discount(user_id, code):
-    query = f"SELECT * FROM discounts WHERE code='{code}'"
+    query = "SELECT * FROM discounts WHERE code=?"
-    return db.execute(query)
+    return db.execute(query, (code,))
```

**Триаж:** пользователь подтверждает (TP) → счётчик растёт → следующий скан умнее.

---

## Сравнение

| Фича | GSC | SonarQube | Snyk | Semgrep |
|------|-----|-----------|------|---------|
| Накопление паттернов между аудитами | ✅ | ❌ | ❌ | ❌ |
| Авто-деактивация ложных паттернов | ✅ | ❌ | ❌ | ❌ |
| Language-aware фильтрация | ✅ | ✅ | ✅ | ✅ |
| Framework-aware (AST импортов) | ✅ | ❌ | ❌ | ❌ |
| Compliance mapping (PCI/SOC2/ISO) | ✅ | ❌ | ❌ | ❌ |
| AI-patch (опционально) | ✅ | ❌ | ❌ | ❌ |
| Автономный | ✅ | ❌ | ❌ | ✅ |
| Open source | ✅ | ❌ | ❌ | ✅ |

> ⚠️ `--deep` и `gsc fix` отправляют код в OpenRouter API. Для enterprise: `GSC_LLM_PROVIDER=ollama`.

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
gsc marketplace              # экспорт/импорт паттернов
gsc issue <id>               # тикет в Jira/Linear
gsc scan <project> --compliance pci-dss  # compliance-отчёт
```

---

## Дорожная карта

| Фаза | Что | Срок | Статус |
|------|-----|------|--------|
| **1. CLI** | scan, triage, explain, fix, 277 паттернов, dashboard | Июль 2026 | ✅ |
| **2. CI/CD** | diff-only, SARIF, AI-patch, pre-commit, baseline, шифрование | Август 2026 | ✅ |
| **3. Качество** | Corpus-тесты (8/8), language filter (-66%), framework filter (-88% FP), HTML-отчёты | Сентябрь 2026 | ✅ |
| **4. DX** | VSCode extension, Jira/Linear, PDF export | Октябрь 2026 | 🔜 |
| **5. Enterprise** | Helm chart, SSO (OAuth2 Proxy), RBAC | Ноябрь 2026 | 🔜 код готов |
| **6. Сеть** | Federated learning, pattern marketplace | Январь 2027 | 📋 marketplace ✅ |
| **7. Compliance** | PCI DSS, SOC2 auto-reports, evidence collection | Февраль 2027 | 🔜 mapping ✅ |

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

> ⚠️ GSC тестирован на 6 собственных проектах. На чужих репозиториях неизбежны ложные срабатывания — для этого triage и авто-деактивация.

## Obsidian Integration

GSC генерирует Markdown-заметки для каждой находки, создавая связи между уязвимостями, файлами и паттернами в вашем Obsidian vault. Откройте `obsidian-vault/audits/` — и увидите граф безопасности проекта.

## Dashboard

`gsc dashboard` поднимает веб-интерфейс на порту 8080: Top-10 шумных паттернов, статус триажа (TP/FP), график накопления находок.

---

## Установка

```bash
# Требования: Python 3.10+, ripgrep 13+
python3 --version

# 1. ripgrep (бинарник)
brew install ripgrep      # macOS
sudo apt install ripgrep  # Linux

# 2. GSC
git clone https://github.com/poliakarmai/gsc.git
cd gsc
python3 gsc.py doctor
python3 gsc.py scan .
```

## 🚀 Попробуй сейчас

```bash
git clone https://github.com/poliakarmai/gsc.git
cd gsc
python3 gsc.py scan .  # первый аудит за 10 секунд
```

## Enterprise

- **Helm chart:** `helm install gsc ./helm` — CronJob-аудит в Kubernetes
- **SSO:** OAuth2 Proxy sidecar (Google/Auth0/Okta/Azure AD), `sso.enabled: true` в values.yaml
- **DB encryption:** Fernet AES-128, `gsc encrypt-db`
- **Audit log:** каждая находка имеет `reviewed_at`, `reviewer`, `status`

## Compliance

```bash
gsc scan my-project --compliance pci-dss    # PCI DSS 4.0 (6 требований)
gsc scan my-project --compliance soc2        # SOC2 (CC6/CC7)
gsc scan my-project --compliance iso27001    # ISO 27001 (Annex A)
gsc scan my-project --compliance all         # все стандарты
```

32+ паттернов замаплены на PCI DSS, 28 на SOC2, 35 на ISO 27001.  
[Полный маппинг](./docs/compliance.md)

## 🤝 Контрибьюция

- **Python-разработчики:** новые паттерны, интеграции с языками
- **Security-инженеры:** OWASP/CWE/NIST-покрытие
- **DevOps:** CI/CD шаблоны, Helm-чарты

Откройте [Issue](https://github.com/poliakarmai/gsc/issues) или пришлите PR.
