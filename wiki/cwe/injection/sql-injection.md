# SQL Injection (CWE-89)

## Связанные статьи
- [[cwe/injection/command-injection]] — другая форма injection
- [[rules/gs005-sql-injection]] — правило GSC
- [[patterns/python/sql-injection]] — Python паттерны
- [[references/owasp-top10]] — OWASP A03:2025

## Описание
Внедрение SQL-кода через пользовательский ввод. №1 в CWE Top 25 уже 15 лет.

## Паттерны детекта

### Уязвимые паттерны (все языки)
- Конкатенация строк с переменными в SQL
- f-строки / template literals с пользовательским вводом
- `%` форматирование с переменными
- Динамическое построение имён таблиц/колонок

### Python
```python
# ❌ Уязвимо
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# ✅ Защищено
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
session.query(User).filter(User.id == user_id)
```

### JavaScript/TypeScript
```javascript
// ❌ Уязвимо
const query = `SELECT * FROM users WHERE id = ${userId}`;
pool.query("SELECT * FROM users WHERE id = " + userId);

// ✅ Защищено
pool.query("SELECT * FROM users WHERE id = ?", [userId]);
await prisma.user.findUnique({ where: { id: userId } });
```

### Go
```go
// ❌ Уязвимо
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
db.Exec("SELECT * FROM users WHERE id = " + userID)

// ✅ Защищено
db.Query("SELECT * FROM users WHERE id = ?", userID)
```

### PHP
```php
// ❌ Уязвимо
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$query = "SELECT * FROM users WHERE id = $userId";

// ✅ Защищено
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

## Обходы параметризации
- **ORDER BY / GROUP BY** — нельзя параметризовать, нужен whitelist
- **Имена таблиц/колонок** — только whitelist или экранирование
- **Second-order injection** — данные из БД попадают в другой запрос
- **Unicode нормализация** — обход WAF через нормализацию

## Ложные срабатывания
- `f"SELECT 1"` — нет пользовательского ввода
- `f"SELECT * FROM {TABLE_NAME}"` — TABLE_NAME = константа
- ORM с параметризацией (SQLAlchemy, Prisma, GORM)
- Подготовленные запросы (prepared statements)
- Конфигурационные SQL-файлы (миграции, сиды)

## GSC детектор: GS005
- **Тир:** precise
- **Эшелон:** 2 (security)
- **Что ищет:** f-строки, конкатенацию, %-форматирование в SQL
- **Post-filter:** проверяет что переменная — действительно пользовательский ввод
- **Revalidate:** проверяет использование prepared statements

## Severity: CRITICAL
- CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Impact: полная компрометация БД
- Exploitability: тривиально (sqlmap, ручной)
