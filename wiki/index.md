# GSC Security Wiki

Karpathy-style перелинкованная база знаний по безопасности кода.  
Интегрирована с GSC (Git Security Checker) для обогащения находок.

## Навигация

### По CWE
- [[cwe/injection/sql-injection]] — CWE-89: SQL Injection (→ GS005)
- [[cwe/injection/command-injection]] — CWE-78: Command Injection (→ GS004)
- [[cwe/auth/hardcoded-credentials]] — CWE-798: Hardcoded Secrets (→ GS001)
- [[cwe/auth/jwt-misuse]] — CWE-347: JWT Vulnerabilities (→ GS011)
- [[cwe/crypto/weak-crypto]] — CWE-327: Weak Cryptography

### По языку
- [[patterns/python/sql-injection]] — Python: SQL Injection паттерны
- [[patterns/python/command-injection]] — Python: Command Injection
- [[patterns/javascript/xss-dom]] — JavaScript: XSS/DOM
- [[patterns/go/sql-injection]] — Go: SQL Injection

### Правила GSC
- [[rules/gs001-hardcoded-secrets]] — GS001: API keys, tokens, passwords
- [[rules/gs004-dangerous-subprocess]] — GS004: shell=True, eval, exec
- [[rules/gs005-sql-injection]] — GS005: f-string SQL, raw queries

### Ресурсы
- [[references/owasp-top10]] — OWASP Top 10 2025
- [[references/cwe-top25]] — CWE Top 25 Most Dangerous

## Как использовать

1. **GSC нашёл уязвимость** → посмотреть статью в Wiki для контекста
2. **Пишешь новый детектор** → дополнить Wiki паттернами
3. **Dual-track research** → Wiki + веб-поиск параллельно
4. **Обучение** → читать статьи последовательно по ссылкам
