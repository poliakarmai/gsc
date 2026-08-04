# Command Injection (CWE-78)

## Связанные статьи
- [[cwe/injection/sql-injection]] — SQL Injection (похожий механизм)
- [[rules/gs004-dangerous-subprocess]] — правило GSC
- [[patterns/python/command-injection]] — Python паттерны

## Описание
Выполнение произвольных команд ОС через пользовательский ввод. Критично в Python (eval, exec, subprocess) и JS/Node.js.

## Паттерны детекта

### Python
```python
# ❌ CRITICAL: shell=True + пользовательский ввод
subprocess.call(f"ping -c 1 {host}", shell=True)
os.system(f"rm -rf {user_path}")
os.popen(f"cat {filename}")

# ❌ CRITICAL: eval/exec с пользовательским вводом
eval(user_input)
exec(f"result = {user_expr}")

# ❌ HIGH: pickle десериализация
pickle.loads(user_data)
yaml.load(user_yaml)  # не safe_load!

# ✅ Защищено
subprocess.call(["ping", "-c", "1", host])  # shell=False
shlex.quote(user_path) + валидация
ast.literal_eval(user_input)  # только литералы
yaml.safe_load(user_yaml)
```

### JavaScript/Node.js
```javascript
// ❌ CRITICAL
exec(`ping -c 1 ${host}`)
execSync(userCommand)

// ❌ HIGH
eval(userInput)
new Function('return ' + userInput)()

// ✅ Защищено
execFile('ping', ['-c', '1', host])  // без shell
// Валидация через whitelist перед exec
```

### Go
```go
// ❌ CRITICAL
exec.Command("sh", "-c", "ping -c 1 "+host)
exec.Command("bash", "-c", userCommand)

// ✅ Защищено
exec.Command("ping", "-c", "1", host)  // аргументы отдельно

// ❌ template injection
tmpl.Execute(w, userInput)
```

## Обходы защиты
- Валидация через blacklist (легко обойти)
- `shlex.quote()` без дополнительной валидации
- Environment variable injection ($PATH, $LD_PRELOAD)
- Command chaining: `;`, `&&`, `||`, `|`, `` ` ``
- Newline injection в заголовках

## Ложные срабатывания
- `subprocess.call(["ls", "-la"])` — нет пользовательского ввода
- `eval("2 + 2")` — константа
- `os.system("clear")` — нет переменных
- `yaml.safe_load()` — безопасный загрузчик
- CLI-инструменты с фиксированными командами

## GSC детектор: GS004
- **Тир:** precise
- **Эшелон:** 1 (source-driven)
- **Что ищет:** shell=True, eval, exec, os.system, subprocess с конкатенацией
- **Post-filter:** проверяет что аргумент содержит переменную, а не константу
- **Revalidate:** проверяет наличие валидации ввода

## Severity: CRITICAL
- CVSS: 9.8 (если shell=True + нет валидации)
- Impact: RCE на сервере
- Exploitability: высокая (одна строка)
