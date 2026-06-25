# Использование GSC

## Первый запуск

```bash
gsc init                  # инициализация: .gsc/, hook, CI workflow
gsc scan .                # первый аудит
gsc triage .              # разметка находок (y/n/i)
```

## Аудит

```bash
# Полный скан
gsc scan my-project

# Только изменённые файлы (для PR)
gsc scan my-project --diff

# С LLM-анализом (OpenRouter)
gsc scan my-project --deep

# SARIF для GitHub Code Scanning
gsc scan my-project --sarif > results.sarif

# JSON (для скриптов)
gsc scan my-project --ci --json
```

## Триаж

```bash
# Интерактивный (по одной находке)
gsc triage my-project

# Кластерами (accept/reject все находки паттерна разом)
gsc triage my-project --group-by pattern

# Автоматический (CI)
gsc scan my-project --ci --json | gsc triage --bulk --auto-accept
```

## Анализ находок

```bash
# CVSS + threat/impact
gsc explain 42

# AI-патч (OpenRouter)
gsc fix 42

# Создать тикет
gsc issue 42 --md        # Markdown для копипасты
gsc issue 42 --jira      # Jira (нужен JIRA_URL/JIRA_TOKEN)
gsc issue 42 --linear    # Linear (нужен LINEAR_API_KEY)
```

## Паттерны

```bash
gsc patterns list                    # список с эффективностью
gsc patterns export patterns.yaml    # экспорт в YAML
gsc patterns import patterns.yaml    # импорт из YAML
```

## Инструменты

```bash
gsc doctor              # диагностика окружения
gsc metrics             # precision/recall
gsc dashboard           # веб-интерфейс (:8080)
gsc config show         # текущие настройки
```

## CI/CD

### GitHub Actions

```yaml
- name: Install GSC
  run: pip install git+https://github.com/poliakarmai/gsc.git
- name: Run GSC
  run: gsc scan . --diff --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: results.sarif}
```

### Pre-commit hook

```bash
cp pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Хук блокирует коммит только при НОВЫХ Critical находках (baseline-aware).

## Типичный workflow

```bash
# 1. Инициализация (один раз)
gsc init

# 2. Аудит перед PR
gsc scan . --diff

# 3. Разметка находок
gsc triage .

# 4. Обновление baseline
gsc baseline --update

# 5. Коммит
git commit -m "fix: security issues found by GSC"
```

---

[Установка](INSTALL.md) | [Паттерны](PATTERNS.md) | [Конфигурация](CONFIG.md) | [Compliance](compliance.md)
