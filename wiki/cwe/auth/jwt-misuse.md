# JWT Vulnerabilities (CWE-347)

## Связанные статьи
- [[cwe/auth/hardcoded-credentials]] — жёсткие секреты (слабые JWT-ключи)
- [[rules/gs011-jwt-vulnerabilities]] — правило GSC

## Описание
Некорректная верификация JWT-токенов: alg:none, слабые секреты, отсутствие проверки audience/issuer.

## Паттерны детекта

### alg:none (САМЫЙ КРИТИЧНЫЙ)
```python
# ❌ Код НЕ проверяет алгоритм
jwt.decode(token, verify=False)  # явная дыра
jwt.decode(token, options={"verify_signature": False})

# ❌ Библиотека позволяет alg:none
# PyJWT < 2.0 принимала alg:none по умолчанию
# jsonwebtoken (Node.js) — если не указан algorithms

# ✅ Защищено
jwt.decode(token, key, algorithms=["HS256"])
```

### Слабый секрет
```python
# ❌ Слабый секрет
JWT_SECRET = "secret"
JWT_SECRET = "my-secret-key"
JWT_SECRET = "password123"

# ❌ Секрет в коде
JWT_SECRET = "my-256-bit-secret-key-here-12345"

# ✅ Из окружения
JWT_SECRET = os.getenv("JWT_SECRET")
# ключ минимум 256 бит для HS256
```

### Отсутствие проверок
```python
# ❌ Нет проверки audience
payload = jwt.decode(token, key, algorithms=["HS256"])
# НЕ проверяется payload.get("aud")

# ❌ Нет проверки issuer
# НЕ проверяется payload.get("iss")

# ❌ Нет проверки expiration
# НЕ проверяется payload.get("exp") и jwt.ExpiredSignatureError

# ✅ Полная проверка
payload = jwt.decode(
    token,
    key,
    algorithms=["HS256"],
    audience="my-api",
    issuer="my-auth-server",
    options={"require": ["exp", "aud", "iss"]}
)
```

### Node.js / JavaScript
```javascript
// ❌ alg:none
jwt.verify(token, secret, { algorithms: ["none", "HS256"] })

// ❌ Слабый секрет
const secret = "my-secret";

// ❌ Нет проверок
jwt.verify(token, secret)  // без опций

// ✅ Полная проверка
jwt.verify(token, secret, {
    algorithms: ["HS256"],
    audience: "my-api",
    issuer: "my-auth-server"
});
```

### Go
```go
// ❌ alg:none
token, _ := jwt.Parse(tokenString, nil)

// ❌ Без проверки
token, _ := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    return []byte("secret"), nil
})

// ✅ Полная проверка
token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
    }
    return []byte(secret), nil
})
```

## Другие JWT-атаки
- **kid injection** — подмена ключа через kid в заголовке
- **jku injection** — подмена JWK Set URL
- **RS256 → HS256 confusion** — публичный ключ как HMAC-секрет
- **Substitution attack** — JWT от одного сервиса к другому

## Ложные срабатывания
- `verify=False` в тестах (но всё равно подсветить!)
- `jwt.decode(token, options={"verify_signature": False})` в отладке
- Не-production код (development-ключи)

## GSC детектор: GS011
- **Тир:** precise
- **Эшелон:** 2 (security)
- **Что ищет:** alg:none, verify=False, слабые секреты, отсутствие audience/issuer
- **Post-filter:** исключает тестовые файлы
- **Revalidate:** проверяет контекст использования

## Severity: CRITICAL
- CVSS: 9.8 (если alg:none)
- Impact: подделка JWT → доступ к любой учётной записи
- Exploitability: тривиально (jwt.io, скрипт в 5 строк)
