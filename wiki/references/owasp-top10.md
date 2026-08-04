# OWASP Top 10 (2025)

## Связанные статьи
- [[cwe/injection/sql-injection]] — A03: Injection
- [[cwe/auth/hardcoded-credentials]] — A04: Cryptographic Failures
- [[cwe/auth/jwt-misuse]] — A07: Identification & Authentication Failures

## A01:2025 — Broken Access Control
Каждый второй баг. Missing auth checks, IDOR, path traversal.
→ GS007 (IDOR), GS014 (credential exposure), GS016 (privilege escalation)

## A02:2025 — Cryptographic Failures
Weak crypto, hardcoded keys, missing encryption at rest/in transit.
→ GS001 (hardcoded secrets), GS010 (weak SSH), GS011 (JWT)

## A03:2025 — Injection
SQL, NoSQL, Command, LDAP, XPath injection.
→ GS005 (SQL injection), GS004 (command injection)

## A04:2025 — Insecure Design
Missing rate limiting, no input validation by design.
→ Нет прямого детектора (архитектурный)

## A05:2025 — Security Misconfiguration
Default credentials, verbose errors, missing headers.
→ GS010 (SSH config), GS013 (GraphQL)

## A06:2025 — Vulnerable Components
Outdated libraries, known CVEs.
→ GS009 (supply chain, Bumblebee scanner)

## A07:2025 — Identification & Authentication Failures
Weak passwords, missing MFA, JWT flaws.
→ GS011 (JWT), GS012 (mass assignment)

## A08:2025 — Software & Data Integrity Failures
CI/CD pipeline attacks, untrusted dependencies.
→ GS009 (supply chain)

## A09:2025 — Security Logging & Monitoring Failures
No audit trail, missed breaches.
→ GS003 (debug code — косвенно)

## A10:2025 — Server-Side Request Forgery (SSRF)
Подделка запросов от сервера к внутренним сервисам.
→ Нет прямого детектора (dynamic analysis)

## Маппинг GSC → OWASP

| Детектор | OWASP | CWE |
|----------|-------|-----|
| GS001 | A02 | CWE-798 |
| GS004 | A03 | CWE-78 |
| GS005 | A03 | CWE-89 |
| GS007 | A01 | CWE-639 |
| GS009 | A06, A08 | CWE-1104 |
| GS010 | A05 | CWE-16 |
| GS011 | A07 | CWE-347 |
| GS012 | A07 | CWE-915 |
| GS013 | A05 | CWE-200 |
| GS014 | A01 | CWE-200 |
