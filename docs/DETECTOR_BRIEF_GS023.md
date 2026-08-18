# DETECTOR BRIEF — GS023

## 1. Состояние

Детектор GS023 (ECHELON 3) использует 17 regex-паттернов для поиска race conditions/TOCTOU в 9 языках. Текущий уровень шума — **высокий** (NOISE_TIER = "noisy"), что ожидаемо для семантического детектора, работающего на regex-уровне без AST-анализа.

**Ключевые проблемы архитектуры:**
- Паттерны с `\n` в regex требуют DOTALL, что создаёт ложные срабатывания на несвязанных строках (например, `exists()` в одном блоке, `open()` в другом, разделённых 50 строками кода)
- Нет проверки расстояния между совпадениями — паттерн `os.path.exists(...)\n.*open(...)` срабатывает даже если между вызовами 100 строк
- Нет проверки контекста (функция, класс, блок) — паттерны срабатывают на разных функциях
- Отсутствует анализ потока данных — `exists()` и `open()` могут работать с разными файлами

## 2. FP root-cause (по группам)

### Группа A: Многострочные паттерны с DOTALL — ложные связи между несвязанными строками
**Паттерны:** `os.path.exists→open`, `os.access→open`, `Path.exists→open`, `save→save`, `get→save`, `UPDATE→SELECT`, `await→await`, `coupon get→delete/update/save`

**Root-cause:** Regex с `\n.*` в DOTALL-режиме соединяет любые две строки, удовлетворяющие паттернам, независимо от:
- Расстояния между ними (может быть 100+ строк)
- Принадлежности к разным функциям/блокам
- Логической связи (разные переменные, разные файлы)

**Пример FP:** 
```python
def check_file(path):
    if os.path.exists(path):
        return True
    return False

def read_file(path):
    # 50 строк кода...
    with open(path, 'r') as f:
        return f.read()
```
Паттерн сработает, хотя это два независимых вызова.

### Группа B: Паттерны без проверки контекста — срабатывание на легитимном коде
**Паттерны:** `tempfile.mktemp/mkstemp/mkdtemp`, `os.symlink`, `async def + global/self`, `Promise.all`, `coupon redemption`

**Root-cause:** Паттерны слишком широкие:
- `tempfile.mkstemp` — безопасен по умолчанию (создаёт файл с O_EXCL)
- `os.symlink` — легитимная операция в большинстве случаев
- `async def + self.` — срабатывает на любом async-методе класса
- `Promise.all` — срабатывает на любом использовании, включая независимые промисы

### Группа C: Паттерны с IGNORECASE — ложные срабатывания на комментариях и строках
**Паттерны:** `coupon|promo|voucher|discount`, `redeem|claim|apply`, `idempotency_key`

**Root-cause:** IGNORECASE + отсутствие проверки на комментарий/строку. Паттерн `redeem|claim|apply.*coupon` сработает на:
- Комментариях: `# TODO: add coupon redemption`
- Строковых литералах: `message = "Please claim your coupon"`
- Документации: `"""Redeem coupon functionality"""`

### Группа D: Паттерны `save()+save()` — ложные срабатывания на разных объектах
**Паттерн:** `\.save\s*\(\).*\n.*\.save\s*\(\)`

**Root-cause:** Паттерн не проверяет, что `save()` вызывается на одном и том же объекте. Сработает на:
```python
user.save()
profile.save()  # разные объекты — нет гонки
```

### Группа E: Паттерны `get→save` — ложные срабатывания на разных моделях
**Паттерн:** `\.objects\.(?:get|filter)\s*\(.*\).*\n.*\.save\s*\(`

**Root-cause:** Не проверяется, что `get()` и `save()` относятся к одной модели. Сработает на:
```python
user = User.objects.get(id=1)
profile.save()  # другая модель
```

## 3. Precision-фиксы (таблица)

| # | Root-cause | Фикс | FP-срез | TP-риск |
|---|-----------|------|---------|---------|
| 1 | **A: Многострочные паттерны** | Добавить фильтр `_is_same_block(content, match_start, match_end)` — проверять, что между совпадениями ≤ 5 строк и нет пустых строк/отступов, указывающих на конец блока. Применять ко всем паттернам с `\n` | **высокий** (убирает ~60% FP по группе A) | **низкий** (реальные TOCTOU обычно в соседних строках) |
| 2 | **A: Разные объекты в save+save** | Модифицировать паттерн: `(\w+)\.save\s*\(\).*\n.*\1\.save\s*\(\)` — требовать одинаковое имя объекта | **средний** (убирает ~70% FP по save+save) | **низкий** (реальная гонка — на одном объекте) |
| 3 | **A: Разные модели в get→save** | Модифицировать паттерн: `(\w+)\.objects\.(?:get\|filter)\s*\(.*\).*\n.*\1\.save\s*\(` — требовать одинаковую модель | **средний** (убирает ~50% FP по get→save) | **низкий** (реальная гонка — на одной модели) |
| 4 | **B: tempfile.mkstemp** | Убрать `mkstemp` из паттерна (безопасен по умолчанию), оставить только `mktemp` (небезопасен) | **высокий** (убирает ~90% FP по tempfile) | **низкий** (mktemp — единственный реально опасный) |
| 5 | **B: os.symlink** | Добавить фильтр `_is_symlink_race(content, match)` — срабатывать только если symlink создаётся в /tmp или /var/tmp | **высокий** (убирает ~95% FP по symlink) | **низкий** (реальные symlink-атаки — в tmp) |
| 6 | **B: async def + self.** | Добавить фильтр `_is_shared_state_async(content, match)` — срабатывать только если в функции есть обращение к `self.balance`, `self.stock`, `self.counter` и т.п. | **высокий** (убирает ~80% FP по async) | **средний** (может пропустить гонки на нестандартных именах) |
| 7 | **B: Promise.all** | Добавить фильтр `_is_mutable_shared_state(content, match)` — срабатывать только если в Promise.all есть обращение к общим mutable-переменным (не const, не локальные) | **высокий** (убирает ~70% FP по Promise.all) | **средний** (сложно определить mutable без AST) |
| 8 | **C: Комментарии и строки** | Добавить фильтр `_is_in_comment_or_string(content, match_start)` — проверять, что совпадение не находится в комментарии (`#`, `//`, `/* */`, `"""`) или строковом литерале | **высокий** (убирает ~90% FP по группе C) | **низкий** (реальные паттерны — в коде, не в комментариях) |
| 9 | **C: coupon-паттерны** | Убрать IGNORECASE для паттернов `coupon|promo|voucher|discount` и `redeem|claim|apply` — требовать точное совпадение регистра | **средний** (убирает ~40% FP) | **низкий** (реальные названия — в camelCase или snake_case) |
| 10 | **D: save+save на разных объектах** | Добавить фильтр `_is_same_object(content, match)` — проверять, что оба `save()` вызываются на переменных, присвоенных из одного источника (например, `user = User.objects.get(...)` → `user.save()`) | **средний** (убирает ~30% FP) | **средний** (сложно определить без data-flow анализа) |

### Дополнительные фильтры (по образцу существующих):

```python
def _is_same_block(content: str, match_start: int, match_end: int) -> bool:
    """Проверяет, что между совпадениями ≤ 5 строк и нет конца блока."""
    before = content[:match_start]
    after = content[match_start:match_end]
    lines_between = after.count('\n')
    if lines_between > 5:
        return False
    # Проверяем, что нет пустых строк (конец блока)
    if re.search(r'\n\s*\n', after):
        return False
    return True


def _is_in_comment_or_string(content: str, match_start: int) -> bool:
    """Проверяет, что совпадение не в комментарии или строке."""
    before = content[:match_start]
    # Простая эвристика: считаем открывающие/закрывающие кавычки
    # и проверяем, не находимся ли мы внутри строки
    # (упрощённо — для Python/JS)
    line_start = before.rfind('\n') + 1
    line = content[line_start:match_start]
    # Проверяем комментарии
    if re.search(r'(#|//|/\*|\*)', line):
        return True
    # Проверяем строковые литералы (упрощённо)
    quotes = line.count('"') + line.count("'")
    if quotes % 2 == 1:
        return True
    return False


def _is_symlink_race(content: str, match_start: int) -> bool:
    """Проверяет, что symlink создаётся в tmp-директории."""
    before = content[:match_start]
    # Ищем ближайший os.symlink вызов и проверяем аргументы
    symlink_match = re.search(r'os\.symlink\s*\(\s*([^,]+),\s*([^)]+)\)', content[match_start:match_start+200])
    if symlink_match:
        target = symlink_match.group(2)
        return bool(re.search(r'/tmp|/var/tmp|tempfile', target))
    return False


def _is_shared_state_async(content: str, match_start: int) -> bool:
    """Проверяет, что async-функция обращается к shared state."""
    # Ищем тело функции после async def
    func_body = content[match_start:match_start+500]
    return bool(re.search(r'self\.(balance|stock|inventory|counter|ledger|amount|total)', func_body))
```

## 4. Требует pro-проверки

1. **Фикс #6 (async def + self.)** — фильтр `_is_shared_state_async` может пропустить гонки на нестандартных именах атрибутов (например, `self.account_balance`). Нужен анализ реальных FP/TP на выборке.

2. **Фикс #7 (Promise.all)** — определение mutable-состояния без AST-анализа крайне ненадёжно. Рекомендую заменить на проверку наличия `let`/`var` (не `const`) в области видимости Promise.all.

3. **Фикс #10 (save+save на разных объектах)** — фильтр `_is_same_object` требует data-flow анализа, что выходит за рамки regex. Возможно, лучше оставить как есть и полагаться на фильтр `_is_same_block`.

4. **Фикс #9 (убрать IGNORECASE)** — может пропустить реальные паттерны в нижнем регистре (например, `coupon.redeem()`). Нужна проверка на реальных примерах.

5. **Фильтр `_is_in_comment_or_string`** — упрощённая эвристика может давать ложные срабатывания на многострочных строках (f-strings, template literals). Требует тестирования на Python/JS/TS.

## 5. Рекомендуемая последовательность

**Фаза 1 — быстрые победы (низкий TP-риск, высокий FP-срез):**
1. Фикс #4 (tempfile.mkstemp) — убрать безопасный паттерн
2. Фикс #5 (os.symlink) — добавить фильтр tmp-директории
3. Фикс #8 (комментарии/строки) — добавить фильтр `_is_in_comment_or_string`
4. Фикс #1 (same_block) — добавить фильтр для всех многострочных паттернов

**Фаза 2 — средняя сложность (требует валидации):**
5. Фикс #2 (save+save на одном объекте) — модифицировать regex
6. Фикс #3 (get→save на одной модели) — модифицировать regex
7. Фикс #6 (async shared state) — добавить фильтр

**Фаза 3 — осторожные изменения (требует pro-проверки):**
8. Фикс #7 (Promise.all mutable) — добавить фильтр
9. Фикс #9 (убрать IGNORECASE) — модифицировать флаги
10. Фикс #10 (same_object) — добавить фильтр (или отложить)

**Критерий остановки:** после каждой фазы прогонять на выборке из 1000 реальных файлов, сравнивать FP/TP до и после. Если TPR падает > 3% — откатить фикс.
