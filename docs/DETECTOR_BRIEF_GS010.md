# DETECTOR BRIEF — GS010

## 1. Состояние

Детектор **GS010** нацелен на поиск опасных конфигураций SSH-сервера в файлах `sshd_config`, `sshd_config.dist`, `sshd_config.template`. 

**Критическая проблема:** предоставленные FP-примеры и выборка шума **не относятся к GS010** — все они описывают находки `Bare except:` (Python), что является результатом работы **другого детектора** (вероятно, GS0xx для Python-исключений). Это указывает на **ошибку в калибровочном наборе** или на то, что GS010 в текущем виде не срабатывает на реальных данных, а шум генерируется соседним детектором.

**Второй вывод:** сам код GS010 содержит несколько логических дефектов, которые приведут к FP при попадании на реальные sshd_config файлы:

1. **Некорректный парсинг значений** — проверки `"yes" in stripped.lower().split()` не учитывают, что `yes` может быть подстрокой другого токена (например, `yesplease`), а также не обрабатывают `Match`-блоки.
2. **Отсутствие учёта контекста `Match`** — параметры внутри `Match`-блоков применяются только к определённым пользователям/группам, но детектор трактует их как глобальные.
3. **Ложное срабатывание на `AllowAgentForwarding`** — условие `"no" not in stripped.lower().split()` сработает на `AllowAgentForwarding yes` (TP), но также на `AllowAgentForwarding` без значения (синтаксически невалидно) и на `AllowAgentForwarding any` (невалидное значение).
4. **`MaxAuthTries` парсинг** — берётся первое число из строки, что может захватить номер порта или другое число из комментария (хотя комментарии отфильтрованы, но строка может содержать несколько чисел).

---

## 2. FP root-cause (по группам)

### Группа A: Некорректный калибровочный набор (внешний шум)
Все предоставленные FP-примеры (`Bare except:`) — это находки **другого детектора**. GS010 не имеет отношения к Python-исключениям. Это не FP самого GS010, а **артефакт процесса калибровки**.

### Группа B: Ложное срабатывание на `AllowAgentForwarding` без значения
```python
if "AllowAgentForwarding" in stripped and "no" not in stripped.lower().split():
```
Сработает на:
- `AllowAgentForwarding` (без значения) — синтаксически невалидно, но может встретиться в черновиках
- `AllowAgentForwarding yes` — TP (нужно сохранить)
- `AllowAgentForwarding 1` — невалидное значение, но сработает

### Группа C: Ложное срабатывание на `PermitRootLogin` с нестандартным форматированием
```python
if "PermitRootLogin" in stripped and "without-password" not in stripped.replace(" ", "").lower() ...
```
Проблема: `stripped.replace(" ", "").lower()` удаляет **все** пробелы, включая те, что внутри значения. Например:
- `PermitRootLogin prohibit-password` → `permitrootloginprohibit-password` — проверка `"prohibit-password" not in ...` вернёт `False` (не найдено), и условие сработает как FP.

### Группа D: `MaxAuthTries` — захват неверного числа
```python
for p in parts:
    try:
        val = int(p)
        if val > 6:
            ...
        break
```
Если строка содержит `MaxAuthTries 6 # comment with 10`, то `break` сработает на первом числе (6) — это корректно. Но если строка `Port 2222 MaxAuthTries 10` (невалидная, но возможна), то первое число `2222` будет интерпретировано как `MaxAuthTries`.

### Группа E: Отсутствие учёта `Match`-блоков
Параметры внутри `Match`-блоков применяются только к определённым условиям. Например:
```
Match User admin
    PermitRootLogin yes
```
Это не означает глобального разрешения root-логина, но детектор сработает.

---

## 3. Precision-фиксы (таблица)

| # | Root-cause | Фикс | FP-срез | TP-риск |
|---|-----------|------|---------|---------|
| 1 | **Группа A**: Калибровочный набор не относится к GS010 | **Не требует фикса кода.** Рекомендация: пересобрать калибровочный набор, исключив находки других детекторов. Если это невозможно — добавить фильтр по типу файла (`.py` исключить из GS010, что уже есть — GS010 проверяет только `sshd_config*`). | высокий (весь шум) | низкий |
| 2 | **Группа B**: `AllowAgentForwarding` без значения или с невалидным значением | Добавить проверку на наличие валидного значения `yes`/`true`/`1` (аналог `_is_placeholder`):<br>```python\n_ALLOW_AGENT_FORWARDING_VALUES = {"yes", "true", "1"}\n# ...\nif "AllowAgentForwarding" in stripped:\n    parts = stripped.lower().split()\n    if len(parts) >= 2 and parts[1] in _ALLOW_AGENT_FORWARDING_VALUES:\n        findings.append(...)\n``` | средний | низкий |
| 3 | **Группа C**: `PermitRootLogin` — удаление пробелов ломает проверку | Заменить `stripped.replace(" ", "").lower()` на нормализацию через `split()`:<br>```python\nparts = stripped.lower().split()\nif len(parts) >= 2 and parts[0] == "permitrootlogin":\n    value = parts[1]\n    if value not in ("without-password", "prohibit-password", "forced-commands-only", "no"):\n        findings.append(...)\n``` | средний | низкий |
| 4 | **Группа D**: `MaxAuthTries` — захват неверного числа | Добавить проверку, что число идёт сразу после ключевого слова:<br>```python\nparts = stripped.split()\nif len(parts) >= 2 and parts[0].lower() == "maxauthtries":\n    try:\n        val = int(parts[1])\n        if val > 6:\n            findings.append(...)\n    except ValueError:\n        pass\n``` | средний | низкий |
| 5 | **Группа E**: `Match`-блоки | Добавить отслеживание контекста `Match`-блоков. Если строка находится внутри `Match`-блока — понижать severity до `INFO` или пропускать (в зависимости от политики). Минимальный фикс: добавить флаг `in_match_block`, который сбрасывается при выходе из блока (пустая строка или новый `Match`):<br>```python\nin_match_block = False\nfor lineno, line in enumerate(lines, 1):\n    stripped = line.strip()\n    if not stripped or stripped.startswith("#"):\n        continue\n    if stripped.lower().startswith("match "):\n        in_match_block = True\n        continue\n    if in_match_block and not stripped[0].isspace():\n        in_match_block = False\n    if in_match_block:\n        continue  # или понизить severity\n``` | средний | средний (может пропустить TP внутри Match-блоков, но это осознанный trade-off) |
| 6 | **Группа C (доп.)**: `PasswordAuthentication` с нестандартным регистром | Уже обрабатывается через `stripped.lower().split()`, но добавить проверку, что `yes` — это отдельный токен, а не часть другого слова:<br>```python\nparts = stripped.lower().split()\nif len(parts) >= 2 and parts[0] == "passwordauthentication" and parts[1] == "yes":\n``` | низкий | низкий |
| 7 | **Группа B (доп.)**: `X11Forwarding` и `PermitUserEnvironment` — аналогичная проблема с `yes` как подстрокой | Применить тот же подход, что и в фиксе #2: проверять `parts[1] in {"yes", "true", "1"}` | низкий | низкий |

---

## 4. Требует pro-проверки

1. **Калибровочный набор**: необходимо подтвердить, что FP-примеры действительно относятся к GS010, а не к другому детектору. Если это ошибка набора — фиксы кода не требуются, достаточно пересобрать набор.
2. **Политика для `Match`-блоков**: нужно решение — пропускать ли находки внутри `Match`-блоков полностью или понижать severity. Это влияет на TPR (могут быть TP внутри `Match`-блоков, например, `Match User root PermitRootLogin yes`).
3. **Допустимые значения для `AllowAgentForwarding`**: в OpenSSH допустимы `yes`/`no` (и `local`/`remote` в новых версиях). Нужно подтвердить, какие значения считать опасными.
4. **`PermitRootLogin`**: проверка `"yes" in stripped.lower().split()` может пропустить `PermitRootLogin yes` (TP), но также сработает на `PermitRootLogin yesplease` (FP). Нужно решить, какие значения считать валидными.
5. **Влияние фикса #5 на TPR**: пропуск `Match`-блоков может снизить TPR более чем на 3%, если в калибровочном наборе есть TP внутри `Match`-блоков. Требуется замер.

---

## 5. Рекомендуемая последовательность

1. **Сначала**: исправить калибровочный набор (исключить находки других детекторов). Это даст наибольший FP-срез без изменения кода.
2. **Затем**: применить фиксы #2, #3, #4 (парсинг значений) — они низкорисковые и дают средний FP-срез.
3. **Потом**: фикс #6, #7 (унификация проверки `yes` как отдельного токена).
4. **В конце**: фикс #5 (`Match`-блоки) — только после замера влияния на TPR. Если TPR падает >3% — пересмотреть политику (понижать severity вместо пропуска).

**Важно**: фиксы #2–#4 и #6–#7 не затрагивают TP-паттерны (валидные конфигурации с опасными значениями), поэтому TP-риск минимален. Фикс #5 требует аккуратного замера.
