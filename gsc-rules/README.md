# GSC Rule Registry — свой реестр YAML-правил

Декларативный pattern DSL: правила пишутся на YAML и компилируются в GSC-детекторы
без написания Python-кода (`gsc_core/gsc_yaml_rules.py`).

## Конвенция файлов

- **Один файл = одно правило** (или группа связанных правил под одним `rules:`).
- Имя файла = `<id>.yml` (например `no-unsafe-deserialization.yml`).
- Идентификатор правила (`id`) — kebab-case, уникален в реестре.

## Метаданные правила

```yaml
rules:
  - id: no-unsafe-deserialization      # обязателен, kebab-case
    severity: CRITICAL                  # CRITICAL|HIGH|MEDIUM|LOW (или ERROR/WARNING/INFO)
    confidence: 0.85                    # 0.0–1.0
    languages: [python]                 # python|javascript|go|java|ruby|...
    message: "Unsafe deserialization ..."  # обязателен — что и почему
    patterns:                           # обязателен — хотя бы один
      - regex: "pickle\\.loads\\("     # raw regex (GSC-стиль)
        title: "pickle.loads() — unsafe deserialization"
      # или декларативный паттерн:
      # - pattern: "pickle.loads($X)"   # → компилируется в regex
    not-patterns:                       # negation guards (необязательно)
      - regex: "yaml\\.safe_load"
    fix: "Use yaml.safe_load() or a allowlist"   # необязательно
    references:                         # необязательно
      - "https://cwe.mitre.org/data/definitions/502.html"
```

## Форматы паттернов

| Ключ | Семантика |
|------|-----------|
| `pattern: "eval($X)"` | декларативный — `$X`→метапеременная, `...`→ellipsis, компилируется в regex |
| `pattern-regex: "..."` | raw regex, как есть |
| `patterns: [{regex: ..., title: ...}]` | GSC-стиль: список regex + заголовок |
| `pattern-either: [...]` | OR альтернатив |
| `not-patterns` / `not` / `pattern-not` | negation guards — совпадение исключает находку |

## Команды

```bash
gsc registry list                    # скомпилированные + исходные YAML
gsc registry add <file.yml>          # скомпилировать и зарегистрировать (merge-safe)
gsc registry update <path|git-url>   # импорт community-правил
```

Скомпилированные детекторы попадают в `gsc_core/gsc_detectors/yaml_rules/`
и автоматически подключаются к реестру (`get_detectors()`) с `rule_id = YAML-<hash>`.

## Приоритет при конфликте с встроенными детекторами

Встроенные детекторы (`GS001`–`GS0xx`) имеют приоритет: не пишите YAML-правило,
если уязвимость уже покрыта встроенным детектором (это породит дубли-находки).
YAML-правила — для **новых** паттернов, которых нет в 47 детекторах.
