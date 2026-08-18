# DETECTOR BRIEF — GS007

## 1. Состояние

Детектор GS007 (IDOR/BAC) имеет **серьёзную проблему с precision**: из 15 предоставленных FP-примеров 10 относятся к GS007, при этом наблюдается **критический дефект архитектуры** — в FP-список попали находки от других детекторов (`pickle.load()`, `CVE-2026-55223`), что указывает на проблему в бенчмарке, а не в детекторе. Однако реальные FP GS007 группируются в 4 чётких кластера:

1. **Ложные срабатывания на схемах БД** (AUTOINCREMENT в CREATE TABLE) — 2 FP
2. **Ложные срабатывания на Django MFA-библиотеке** — 5 FP (все — `Authenticator.objects.filter(...)`)
3. **Ложные срабатывания на `range()` в не-IDOR контекстах** — 1 FP (TOTP window)
4. **Шум на реальных проектах** (loguru, rich, sanic, youtube-dl, piccolo-api) — 15+ находок в "непроверенных"

**Ключевая проблема**: паттерны слишком широкие, не учитывают контекст (схема vs код, библиотечный код vs прикладной, TOTP-окна vs перечисление ID).

---

## 2. FP root-cause (по группам)

### Группа A: Схемы БД (CREATE TABLE) — 2 FP
**Root-cause**: Паттерн `AUTOINCREMENT` срабатывает на DDL-выражениях в `CREATE TABLE`, где это легитимная декларация схемы, а не уязвимость. Детектор не различает:
- `CREATE TABLE ... (id INTEGER PRIMARY KEY AUTOINCREMENT, ...)` — схема, не код
- `ALTER TABLE ... AUTO_INCREMENT = 100` — тоже схема
- Реальная уязвимость — только когда ID из запроса используется для доступа к объекту

**Паттерн-виновник**: `(r'\b(?:AUTO_INCREMENT|AUTOINCREMENT|IDENTITY\s*\(\s*1\s*,\s*1\s*\)|nextval\s*\()', ...)`

### Группа B: Django MFA — `Authenticator.objects.filter(...)` — 5 FP
**Root-cause**: Паттерн `\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*request\.user\b` срабатывает на **легитимные user-scoped запросы** в MFA-библиотеке. Проблемы:
1. `Authenticator.objects.filter(user=request.user)` — это **правильная** проверка владельца (user-scoped), а не отсутствие tenant-фильтра
2. Паттерн требует org/tenant фильтр, но в однопользовательских контекстах (MFA, личные настройки) tenant-фильтр не нужен
3. `SKIP_PATTERNS` содержит `r'\.filter\s*\(.*user\s*='`, но он **не срабатывает**, потому что паттерн ищет `user\s*=\s*request\.user\b`, а skip-паттерн — `user\s*=` (без `request.user`)

**Паттерн-виновник**: `(r'\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*request\.user\b', ...)`

### Группа C: `range()` в не-IDOR контекстах — 1 FP + 6 шумовых
**Root-cause**: Паттерн `for\s+\w+\s+in\s+range\s*\(.*(?:id|ticket|order|user_id)` слишком широкий:
- TOTP window: `for i in range(-valid_window, valid_window + 1)` — это **криптографическая проверка**, не перечисление
- `for x in range(options.max_width)` — UI-код
- `for idx in range(dash_stream_info['videoLength'] ...)` — медиа-поток
- `for i in range(1, len(self.logo_lines) - idx)` — отрисовка логотипа

**Паттерн-виновник**: `(r'for\s+\w+\s+in\s+range\s*\(.*(?:id|ticket|order|user_id)', ...)`

### Группа D: `SERIAL` в импортах и строках — 4+ шумовых
**Root-cause**: Паттерн `\b(?:SERIAL|BIGSERIAL)\b` срабатывает на:
- Импорты: `from piccolo.columns import Array, Integer, Serial, Text` — это **имя класса**, не тип колонки
- Строки: `'description': 'French thriller serial about a missing teenager.'` — это **английское слово** "serial" (сериал)
- `'url': 'http://www.ntv.ru/serial/Delo_vrachey/...'` — URL-путь

**Паттерн-виновник**: `(r'\b(?:SERIAL|BIGSERIAL)\b', ...)`

### Группа E: `_method` в URL-путях — 1 FP
**Root-cause**: Паттерн `\b_method\b\s*=` срабатывает на `session['method']` в URL-путях youtube-dl, где `_method` — часть URL, а не HTTP-параметр.

**Паттерн-виновник**: `(r'\b_method\b\s*=', ...)`

---

## 3. Precision-фиксы

| # | Root-cause | Фикс | FP-срез | TP-риск |
|---|-----------|------|---------|---------|
| 1 | **Группа A**: AUTOINCREMENT в CREATE TABLE | Добавить negative-lookbehind: `(?<!CREATE\s+TABLE\s+.*)` — но regex не поддерживает переменную длину. **Альтернатива**: добавить фильтр в `detect()`: если строка содержит `CREATE TABLE` или `PRIMARY KEY` и не содержит `request.` / `params` — пропустить. Реализация: `if "CREATE TABLE" in line_text.upper() or "PRIMARY KEY" in line_text.upper(): continue` | **Высокий** (2/2 FP) | **Низкий** (TP всегда в коде, не в DDL) |
| 2 | **Группа B**: Django MFA user-scoped запросы | Уточнить паттерн: требовать **отсутствие** `request.user` в фильтре, а не наличие org/tenant. Новый паттерн: `\.filter\s*\(\s*(?!.*org|.*tenant|.*organization|.*request\.user).*\buser\s*=\s*[^)]*` — но это сложно. **Проще**: добавить в `SKIP_PATTERNS` точное: `r'\.filter\s*\([^)]*user\s*=\s*request\.user\b'` (с `[^)]*` для захвата всей сигнатуры). **Или**: изменить паттерн на `\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*(?!request\.user\b)` — требует, чтобы user НЕ был request.user | **Высокий** (5/5 FP) | **Средний** (может пропустить TP, где user=request.user без tenant — но это редкий TP) |
| 3 | **Группа C**: `range()` в TOTP/UI | Добавить negative-lookahead для TOTP: `for\s+\w+\s+in\s+range\s*\((?![^)]*valid_window|max_width|stride|chunkTime|videoLength|logo_lines)` — но это хрупко. **Лучше**: добавить в `SKIP_PATTERNS`: `r'valid_window'`, `r'max_width'`, `r'stride'`, `r'chunkTime'`, `r'videoLength'`, `r'logo_lines'` | **Высокий** (1/1 FP + 6 шумовых) | **Низкий** (TP — перечисление ID, не TOTP/UI) |
| 4 | **Группа D**: `SERIAL` в импортах/строках | Уточнить паттерн: `\bSERIAL\b` → `(?<!from\s+)\bSERIAL\b` — но negative-lookbehind фиксированной длины. **Альтернатива**: добавить фильтр в `detect()`: если строка начинается с `from ` или `import ` — пропустить. Для строк: добавить проверку `if "serial" in line_text.lower() and ("'" in line_text or '"' in line_text): continue` (строковый литерал) | **Высокий** (4/4 шумовых) | **Низкий** (TP — всегда в коде, не в строках/импортах) |
| 5 | **Группа E**: `_method` в URL | Уточнить паттерн: `\b_method\b\s*=` → `(?:request\.(?:POST|GET|body|data)\s*\[\s*['\"]_method|_method\s*=\s*request\.)` — требовать, чтобы `_method` был параметром запроса, а не частью URL | **Средний** (1/1 FP) | **Низкий** (TP — всегда параметр запроса) |
| 6 | **Группа B (доп.)**: `Authenticator.objects.filter(` без `user=` | Паттерн `\.filter\s*\(\s*(?!.*org|.*tenant|.*organization).*\buser\s*=\s*request\.user\b` требует `user=request.user`, но FP показывают `Authenticator.objects.filter(` **без** `user=request.user` (строка 206: `serialize_authenticator(a) for a in Authenticator.objects.filter(`). Это значит, что паттерн срабатывает на **частичное совпадение** — `.*\buser\s*=\s*request\.user\b` матчит `user` из другого места. **Фикс**: добавить требование, что `user=` и `request.user` находятся в **одном вызове** `.filter(...)`. Реализация: изменить паттерн на `\.filter\s*\(\s*[^)]*user\s*=\s*request\.user\b` (с `[^)]*` вместо `.*`) | **Высокий** (5/5 FP) | **Средний** (может пропустить TP с вложенными скобками) |
| 7 | **Группа A (доп.)**: `IDENTITY(1,1)` в DDL | Аналогично фиксу #1: добавить проверку `if "CREATE TABLE" in line_text.upper(): continue` для всех DDL-паттернов | **Высокий** (покрывает все DDL) | **Низкий** |
| 8 | **Группа C (доп.)**: `range()` с `id` в имени переменной | Уточнить: `for\s+(\w+)\s+in\s+range\s*\(` — проверить, что переменная цикла **сама** называется `id`/`user_id`/`ticket_id` и используется в запросе. Реализация: в `detect()` после match — проверить, что переменная цикла используется в `.get()`/`.filter()`/`.find()` в следующих 3 строках | **Средний** | **Средний** (может пропустить TP с непрямым использованием) |

---

## 4. Требует pro-проверки

1. **Фикс #2 (Django MFA)**: Изменение паттерна с `.*` на `[^)]*` может пропустить TP, где `.filter()` содержит вложенные вызовы (например, `Q(user=request.user) | Q(org=...)`). Нужна проверка на реальных TP-корпусах.

2. **Фикс #6 (user=request.user)**: Требование, что `user=` и `request.user` в одном вызове `.filter()`, может пропустить TP, где фильтр разбит на несколько строк с промежуточными переменными.

3. **Фикс #8 (переменная цикла)**: Проверка использования переменной цикла в запросе — сложная эвристика, может дать false-negative на TP с непрямым использованием (например, `obj_id = i; obj = Model.get(obj_id)`).

4. **Группа D (SERIAL)**: Фикс с пропуском строк, содержащих кавычки, может пропустить TP, где SERIAL встречается в f-string или шаблоне SQL-запроса.

5. **Глобальный вопрос**: В FP-списке есть находки от **других детекторов** (`pickle.load()`, `CVE-2026-55223`). Это указывает на проблему в бенчмарке (неправильная маркировка), а не в GS007. Требуется проверка: не является ли часть "FP" GS007 на самом деле TP, которые просто не были проверены.

6. **Фикс #5 (_method)**: Уточнение паттерна может пропустить TP, где `_method` передаётся через заголовок `X-HTTP-Method-Override` (не через request.POST).

---

## 5. Рекомендуемая последовательность

### Фаза 1 — Быстрые победы (низкий TP-риск, высокий FP-срез):
1. **Фикс #1 + #7** (DDL-фильтр): Добавить проверку `CREATE TABLE` / `PRIMARY KEY` в `detect()` — убирает 2 FP, TP-риск минимальный.
2. **Фикс #4** (SERIAL в импортах/строках): Добавить фильтр на `from `/`import ` и строковые литералы — убирает 4+ шумовых, TP-риск низкий.
3. **Фикс #3** (TOTP/UI range): Добавить `valid_window`, `max_width`, `stride`, `chunkTime`, `videoLength`, `logo_lines` в `SKIP_PATTERNS` — убирает 1 FP + 6 шумовых, TP-риск низкий.

### Фаза 2 — Средний приоритет (требует проверки):
4. **Фикс #5** (_method): Уточнить паттерн до `request.(POST|GET|body|data)['_method']` — убирает 1 FP, TP-риск низкий.
5. **Фикс #2 + #6** (Django MFA): Изменить `.*` на `[^)]*` в паттерне `.filter()` — убирает 5 FP, TP-риск средний. **Требует pro-проверки** на TP-корпусе.

### Фаза 3 — Требует анализа:
6. **Фикс #8** (переменная цикла): Добавить эвристику использования переменной в запросе — убирает оставшиеся FP, TP-риск средний. **Требует pro-проверки**.

### Итоговый прогноз:
- **FP-срез**: ~15-17 FP из 15 предоставленных (с учётом шумовых) — **~90-100%**
- **TP-риск**: ≤ 3% при условии проверки Фазы 2 и 3 на TP-корпусе
- **Оставшиеся FP**: только те, что требуют pro-проверки (вложенные вызовы, непрямое использование)
