# DETECTOR BRIEF — GS033

## 1. Состояние

Детектор GS033 покрывает 14 паттернов CI/CD анти-паттернов. Основная проблема — **чрезмерно широкие регулярные выражения** без учёта контекста (комментарии, документация, примеры, не-CI секции YAML). Многие паттерны используют `(?i)` без ограничения на YAML-строки, что вызывает срабатывания на текстовых описаниях в комментариях и документации внутри CI-файлов.

**Ключевые риски FP:**
- Паттерны срабатывают на `name:` полях, которые являются просто описаниями шагов
- `(?i)` делает паттерны чувствительными к словам в комментариях
- Отсутствие проверки на YAML-комментарии (`#`) и строковые литералы
- Паттерн `secret_in_env_dump` срабатывает на любом упоминании `env | grep` даже в документации

## 2. FP root-cause (по группам)

### Группа A: Срабатывание на комментариях и документации
Паттерны `prod_deploy_no_staging`, `deploy_no_canary`, `secret_in_log`, `secret_in_env_dump` срабатывают на строках, начинающихся с `#` (комментарии YAML) или содержащих описания в `name:` полях. Пример: `# Deploy to production without staging` вызовет FP.

### Группа B: Ложные срабатывания на `name:` полях
Паттерн `prod_deploy_no_staging` ищет `name:\s*(?:deploy.*prod|...)`, но `name:` в GitHub Actions — это просто человекочитаемое название шага. `name: Deploy to production` — это НЕ признак отсутствия staging, это описание.

### Группа C: Чрезмерно широкая область действия `(?i)`
Паттерны `deploy_no_canary`, `secret_in_env_dump` используют `(?i)` без ограничения на YAML-ключи. Это приводит к срабатыванию на словах в произвольных строках (например, в `run:` скриптах, где `env | grep` — легитимная команда).

### Группа D: Паттерн `persist_credentials` не учитывает YAML-структуру
Паттерн `actions/checkout@v\d+(?!.{0,200}persist-credentials:\s*false)` не учитывает, что `persist-credentials` может быть в другом блоке YAML (например, в `with:` на следующей строке с отступом). Также не учитывает случай, когда `persist-credentials` указан как `persist-credentials: false` с пробелом после `:`.

### Группа E: Паттерн `pull_request_no_sandbox` не учитывает YAML-комментарии
Паттерн `pull_request_target(?!.{0,200}(?:environment:|environment\s*:))` не учитывает, что `environment:` может быть закомментирован или находиться в другом блоке.

## 3. Precision-фиксы (таблица)

| Root-cause | Фикс | FP-срез | TP-риск |
|---|---|---|---|
| **A: Комментарии** | Добавить фильтр `_is_yaml_comment(line)` — проверка, что строка начинается с `#` (после trim). Применять ко всем паттернам, кроме `secret_in_log` (там комментарий тоже может быть опасен, но реже). | Высокий (30-40% FP) | Низкий (TP в комментариях — редкость) |
| **B: `name:` поля** | Для `prod_deploy_no_staging` изменить regex на `(?:^|\n)\s*name:\s*(?:deploy.*prod\|production.*deploy\|release)` — требовать, чтобы `name:` был в начале строки (YAML-ключ), а не в середине текста. | Средний (15-20% FP) | Низкий (TP всегда в `name:` ключе) |
| **C: `(?i)` без контекста** | Для `deploy_no_canary` и `secret_in_env_dump` добавить фильтр `_is_in_run_script(line)` — проверка, что строка находится внутри блока `run:` (отступ ≥ 2 пробелов после `run:`). Если строка в `run:` — это скрипт, а не YAML-описание. | Средний (20-25% FP) | Средний (TP в `run:` скриптах — реальные случаи, но фильтр не отсекает их, а только убирает FP из `name:` и комментариев) |
| **D: `persist_credentials`** | Добавить фильтр `_has_persist_credentials_false(content, match_start)` — проверка наличия `persist-credentials:\s*false` в радиусе 5 строк от `actions/checkout@`. Учитывать YAML-отступы. | Средний (10-15% FP) | Низкий (TP всегда имеет `persist-credentials: false` в том же блоке) |
| **E: `pull_request_no_sandbox`** | Добавить фильтр `_has_environment_block(content, match_start)` — проверка наличия `environment:` в радиусе 10 строк от `pull_request_target`, игнорируя закомментированные строки. | Низкий (5-10% FP) | Низкий (TP всегда имеет `environment:` в том же workflow) |

### Дополнительные фильтры (реализация)

```python
def _is_yaml_comment(line: str) -> bool:
    """Проверка, что строка — YAML-комментарий."""
    stripped = line.strip()
    return stripped.startswith('#')

def _is_in_run_script(content: str, line_no: int) -> bool:
    """Проверка, что строка находится внутри блока run: (скрипт)."""
    lines = content.splitlines()
    if line_no < 1 or line_no > len(lines):
        return False
    # Ищем ближайший YAML-ключ выше
    for i in range(line_no - 1, -1, -1):
        line = lines[i]
        if re.match(r'^\s*\w+:', line):
            key = line.strip().split(':')[0]
            return key == 'run'
    return False

def _has_persist_credentials_false(content: str, match_start: int) -> bool:
    """Проверка наличия persist-credentials: false в радиусе 5 строк."""
    lines = content.splitlines()
    match_line = content[:match_start].count('\n')
    start = max(0, match_line - 5)
    end = min(len(lines), match_line + 5)
    for i in range(start, end):
        if re.search(r'persist-credentials:\s*false', lines[i], re.IGNORECASE):
            return True
    return False

def _has_environment_block(content: str, match_start: int) -> bool:
    """Проверка наличия environment: в радиусе 10 строк, игнорируя комментарии."""
    lines = content.splitlines()
    match_line = content[:match_start].count('\n')
    start = max(0, match_line - 10)
    end = min(len(lines), match_line + 10)
    for i in range(start, end):
        if _is_yaml_comment(lines[i]):
            continue
        if re.search(r'^\s*environment\s*:', lines[i], re.IGNORECASE):
            return True
    return False
```

### Применение фильтров в `detect()`

```python
# В цикле по matches:
for match in matches:
    line_no = content[:match.start()].count("\n") + 1
    line = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
    
    # Фильтр A: пропуск комментариев (кроме secret_in_log)
    if pattern_id != "secret_in_log" and _is_yaml_comment(line):
        continue
    
    # Фильтр B: для prod_deploy_no_staging — проверка, что name: в начале строки
    if pattern_id == "prod_deploy_no_staging":
        if not re.match(r'^\s*name:', line):
            continue
    
    # Фильтр C: для deploy_no_canary и secret_in_env_dump — пропуск если не в run:
    if pattern_id in ("deploy_no_canary", "secret_in_env_dump"):
        if not _is_in_run_script(content, line_no):
            continue
    
    # Фильтр D: для persist_credentials
    if pattern_id == "persist_credentials":
        if _has_persist_credentials_false(content, match.start()):
            continue
    
    # Фильтр E: для pull_request_no_sandbox
    if pattern_id == "pull_request_no_sandbox":
        if _has_environment_block(content, match.start()):
            continue
    
    # ... остальная логика
```

## 4. Требует pro-проверки

1. **[flash-гипотеза]** Фильтр `_is_in_run_script` для `secret_in_env_dump` — может отсечь TP, если `env | grep` используется в `run:` скрипте для вывода секретов. Нужна проверка на реальных примерах: как часто секреты выводятся через `env | grep` в `run:` блоках.

2. **[flash-гипотеза]** Фильтр `_is_yaml_comment` для `secret_in_log` — я исключил его из фильтра, но если в комментариях есть примеры `echo $SECRET` (документация), это FP. Нужно решить: оставить как есть (TP-риск выше) или добавить фильтр (FP-срез выше).

3. **[flash-гипотеза]** Для `prod_deploy_no_staging` — изменение regex на `(?:^|\n)\s*name:` может пропустить TP, если `name:` находится не в начале строки (например, вложенный YAML). Нужна проверка на реальных workflow.

4. **[flash-гипотеза]** Для `persist_credentials` — радиус 5 строк может быть недостаточен, если `persist-credentials` находится дальше (например, в `with:` блоке с большим количеством параметров). Нужна проверка на реальных примерах.

5. **[flash-гипотеза]** Для `pull_request_no_sandbox` — радиус 10 строк может не покрыть случай, когда `environment:` находится в другом job или в начале файла. Нужна проверка.

## 5. Рекомендуемая последовательность

1. **Сначала фильтр A** (комментарии) — самый большой FP-срез, минимальный TP-риск. Применить ко всем паттернам кроме `secret_in_log`.
2. **Затем фильтр B** (`name:` поля) — точечный фикс для `prod_deploy_no_staging`.
3. **Потом фильтр C** (`run:` скрипты) — для `deploy_no_canary` и `secret_in_env_dump`.
4. **Далее фильтр D** (`persist_credentials`) — точечный фикс.
5. **В конце фильтр E** (`environment:` блок) — точечный фикс для `pull_request_no_sandbox`.

Каждый фикс внедрять отдельно, прогоняя на выборке TP/FP после каждого шага. Допустимое падение TPR ≤ 3% — если фикс даёт большее падение, откатить и пересмотреть.
