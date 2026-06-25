# Конфигурация GSC

## Глобальная (`~/.gsc/config.json`)

```bash
gsc config show                          # текущие настройки
gsc config set obsidian_vault ~/vault   # путь к Obsidian
gsc config set llm_provider ollama      # локальная модель
gsc config set exclude_dirs "tests,vendor,node_modules"
gsc config init                          # сброс к defaults
```

| Ключ | По умолчанию | Описание |
|------|-------------|----------|
| `obsidian_vault` | `~/obsidian-vault/audits` | Куда писать Markdown-отчёты |
| `openrouter_key` | — | API-ключ для `--deep`/`gsc fix` |
| `exclude_dirs` | `tests,vendor,node_modules,.git` | Пропускать директории |
| `llm_provider` | `openrouter` | `openrouter` или `ollama` |
| `llm_model` | `google/gemini-2.5-flash` | Модель для E4 |
| `auto_deactivate_threshold` | `0.3` | Порог деактивации (<30%) |
| `min_ratings_for_deactivate` | `10` | Мин. оценок для деактивации |

## Per-project (`<project>/.gsc/config.yaml`)

```yaml
language: python
excludes:
  - "tests/**"
  - "migrations/**"
threshold: 5.0  # минимальный CVSS для показа
```

## Переменные окружения

```bash
GSC_LLM_PROVIDER=ollama        # локальная модель вместо OpenRouter
OPENROUTER_API_KEY=sk-or-...   # ключ OpenRouter
GSC_DB_KEY=...                 # ключ шифрования БД
GSC_E4_MAX_COST_USD=2.0        # лимит на LLM-анализ
GSC_E4_CB_MAX=20               # максимум finding'ов в E4
```

## Шифрование БД

```bash
gsc encrypt-db    # зашифровать Fernet (AES-128)
gsc decrypt-db    # расшифровать
```

Ключ хранится в `~/.gsc/db.key` (chmod 600) или `GSC_DB_KEY` env var.

---

[Установка](INSTALL.md) | [Использование](USAGE.md) | [Паттерны](PATTERNS.md)
