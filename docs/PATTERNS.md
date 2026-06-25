# Паттерны GSC

Паттерны — атомарные правила проверки. Хранятся в SQLite. Каждый имеет TP/FP счётчики.

## Типы паттернов

| Тип | Описание | Пример |
|-----|----------|--------|
| `regex` | grep-совпадение | `f['"].*SELECT` → SQL injection |
| `semantic` | AST/логический анализ | `pickle.loads` в non-ML контексте |

## Структура паттерна

```json
{
  "title": "SQL injection risk: f-string in query",
  "category": "CRITICAL",
  "echelon": 2,
  "pattern_type": "regex",
  "search_pattern": "f['\"].*SELECT",
  "description": "f-string в SQL-запросе — параметризуйте запрос",
  "language": "python"
}
```

## Как добавить паттерн

### 1. Создать JSON-файл

```bash
# patterns/my-pattern.json
[
  {
    "title": "My new pattern",
    "category": "HIGH",
    "echelon": 1,
    "pattern_type": "regex",
    "search_pattern": "my_regex_pattern",
    "description": "What to look for"
  }
]
```

### 2. Добавить corpus-тест

```bash
# tests/corpus/my_pattern/
#   ├── vulnerable.py    (уязвимый код)
#   └── expected.json    (ожидаемые находки)
```

### 3. Импортировать

```bash
gsc patterns import patterns/my-pattern.json --force
```

### 4. Проверить

```bash
gsc patterns list | grep "My new pattern"
gsc scan . --diff
```

## Эффективность

Каждый паттерн после триажа получает счётчики:

```
true_positive_count: 14
false_positive_count: 3
effectiveness: 14 / (14 + 3) = 82%
```

При `effectiveness < 30%` AND `≥10` оценок паттерн **автоматически деактивируется**.

## Языки

Паттерны с префиксом языка применяются только к файлам этого языка:

| Префикс | Язык | Расширения |
|---------|------|-----------|
| `Go:` | Go | `.go` |
| `TS:` | TypeScript | `.ts`, `.tsx` |
| `Java:` | Java | `.java` |
| `Rust:` | Rust | `.rs` |
| `Docker:` | Docker | `Dockerfile` |
| `Terraform:` | Terraform | `.tf` |
| *(без префикса)* | Python | `.py` |

## Экспорт/импорт

```bash
# Экспорт лучших паттернов (≥50% эффективности)
gsc patterns export my-patterns.yaml

# Импорт из другого проекта
gsc patterns import shared-patterns.yaml --force
```

---

[Установка](INSTALL.md) | [Использование](USAGE.md) | [Конфигурация](CONFIG.md)
