# Hardcoded Credentials (CWE-798)

## Связанные статьи
- [[cwe/auth/hardcoded-credentials]] — эта статья
- [[cwe/crypto/weak-crypto]] — слабая криптография
- [[rules/gs001-hardcoded-secrets]] — правило GSC

## Описание
Жёстко закодированные учётные данные (пароли, ключи, токены) в исходном коде. Самый частый баг в Open Source проектах.

## Паттерны детекта

### Ключи API
```python
# ❌ Hardcoded
OPENAI_API_KEY = "sk-abc123def456"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ✅ Из окружения
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
```

### Пароли
```python
# ❌ Hardcoded
DB_PASSWORD = "admin123"
REDIS_PASSWORD = "password"

# ✅ Из окружения / vault
DB_PASSWORD = os.getenv("DB_PASSWORD")
```

### Токены
```python
# ❌ Hardcoded
TELEGRAM_BOT_TOKEN = "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz"
JWT_SECRET = "my-secret-key"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T/B/Q"

# ✅ Из окружения / зашифровано
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
JWT_SECRET = os.getenv("JWT_SECRET")
```

### Паттерны для regex (GS001)
```
# API keys
(sk-[a-zA-Z0-9]{32,})
(ghp_[a-zA-Z0-9]{36})
(AKIA[0-9A-Z]{16})
(AIza[0-9A-Za-z\-_]{35})

# Passwords
(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]
(secret|token)\s*[:=]\s*['"][^'"]+['"]

# Private keys
-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

## Обходы детекта
- Base64-encoded секреты
- ROT13/Caesar (серьёзно, бывает)
- Секреты в бинарных файлах (.pyc)
- Секреты собранные из частей: `"gh" + "p_" + token_part`
- Переменные окружения в Dockerfile (ENV SECRET=...)

## Ложные срабатывания
- Placeholder'ы и примеры: `API_KEY = "your-api-key-here"`
- Тестовые файлы с тестовыми ключами
- Документация с примерами
- Пустые строки: `PASSWORD = ""`
- base64-encoded НЕ-секреты (изображения, бинарные данные)

## GSC детектор: GS001
- **Тир:** precise
- **Эшелон:** 1 (source-driven)
- **Что ищет:** API-ключи, токены, пароли, приватные ключи
- **Post-filter:** исключает тестовые файлы, примеры, документацию
- **Revalidate:** проверяет контекст (рядом ли `os.getenv`)

## Severity: CRITICAL
- CVSS: 9.8
- Impact: полный доступ к сервису/системе
- Exploitability: тривиально (grep по репозиторию)
- Восстановление: ротация ВСЕХ ключей, не только найденного
