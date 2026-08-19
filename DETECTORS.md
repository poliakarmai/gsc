# Detectors

Сгенерировано из registry — `scripts/gsc_detector_matrix.py`. SSOT по числам: `gsc_meta.py`.

Всего registry-детекторов: **38** (+ 4 standalone движка: Secrets/SCA/IaC/Invariants = 42).

| Rule ID | Echelon | Noise | Fixture | Description |
|---------|---------|-------|---------|-------------|
| GS001 | 1 | normal | ✅ | Hardcoded secrets in source code (API keys, tokens, passwords, JWT, connection strings) |
| GS002 | 2 | normal | ✅ | World-readable sensitive files (keys, certs, env files) |
| GS003 | 1 | normal | ✅ | Debug / diagnostic statements left in production code |
| GS004 | 2 | normal | ✅ | Dangerous subprocess/shell usage (command injection, shell=True, os.system, eval) |
| GS005 | 2 | normal | ✅ | GS005: SQL/NoSQL injection — 78 patterns, 9 languages, per-pattern precision tracking (v2.0) |
| GS007 | 2 | normal | ✅ | Broken Access Control — IDOR, sequential ID enumeration, cross-tenant access, admin panel exposure, unprotected file downloads, unauthorized ticket operations |
| GS008 | 1 | normal | ✅ | Dead code: constants and feature flags declared but never used |
| GS009 | 2 | normal | ✅ | Supply chain scanner: detects packages, editor extensions, MCP configs, and developer-tool metadata across package ecosystems (npm, PyPI, Go, Ruby, Composer, Homebrew, MCP, editor-extension, browser-extension, agent-skill). Powered by Perplexity Bumblebee. |
| GS010 | 2 | normal | ✅ | Weak SSH server configuration — dangerous sshd_config settings |
| GS011 | 2 | normal | ✅ | JWT/JOSE vulnerabilities — weak signatures, alg:none, hardcoded secrets |
| GS012 | 2 | normal | ✅ | Mass Assignment — unfiltered request data in model create/update |
| GS013 | 2 | normal | ✅ | GraphQL security — introspection, depth limiting, error disclosure |
| GS014 | 2 | normal | ✅ | Credential exposure — stored credentials, backup auth files, weak sudoers |
| GS015 | 1 | normal | ✅ | Entry-point coverage — marks HTTP handlers for AI review (noisy matcher) |
| GS016 | 2 | normal | ✅ | Linux privilege escalation paths — SUID, cron, sudo, capabilities, world-readable secrets |
| GS017 | 2 | normal | ✅ | Weak & default passwords — admin:admin, default creds, weak password policies, hardcoded DB passwords |
| GS018 | 2 | normal | ✅ | Payment logic abuse — double cashback, promo code abuse, race conditions, rounding, missing idempotency |
| GS019 | 2 | normal | ✅ | Auth/session weaknesses — SMS exhaustion, session fixation, weak tokens, missing cookie flags, immortal JWT, OTP brute-force |
| GS020 | 1 | normal | ✅ | XSS / HTML / Template Injection — reflected, stored, DOM, SSTI (Web Hacking 101) |
| GS021 | 2 | normal | ✅ | CSRF / SSRF — missing tokens, internal URL fetches (Bug Hunting) |
| GS022 | 2 | normal | ✅ | Open Redirect / URL Manipulation — redirect params, validation bypass (Web Hacking 101) |
| GS023 | 3 | noisy | ✅ | Race Conditions / TOCTOU — double-spend, async races, fs races (Bug Hunting) |
| GS025 | 2 | normal | ✅ | GS025: AI-Code Provenance — detect AI-favored insecure defaults |
| GS032 | 1 | sensitive | ⬜ | GS032: Prompt Injection — detect AI agent hijack via code/docs/issues |
| GS033 | 1 | sensitive | ⬜ | GS033: CI/CD Anti-Patterns — detect unsafe GitHub Actions/GitLab CI patterns |
| GS034 | 1 | sensitive | ⬜ | GS034: npm Malware Patterns — detect ChainDrop worms, dependency confusion, typosquatting in package.json |
| GS035 | 1 | sensitive | ✅ | GS035: PHP Vulnerability Detection — SQLi, XSS, LFI, command injection, deserialization |
| GS036 | 1 | sensitive | ✅ | GS036: Node.js Vulnerability Detection — prototype pollution, eval, command injection, SSRF, NoSQLi |
| GS037 | 1 | sensitive | ✅ | GS037: Python Vulnerability Detection — pickle, eval, SSTI, command injection, deserialization |
| GS038 | 1 | sensitive | ⬜ | GS038: Go Vulnerability Detection — SSTI, SQLi, command injection, hardcoded secrets, weak crypto |
| GS039 | 1 | sensitive | ✅ | GS039: Ruby Vulnerability Detection — YAML RCE, mass assignment, SSTI, SQLi, Marshal |
| GS040 | 1 | normal | ✅ | GS040: PII & Information Disclosure — hardcoded emails, secrets in comments, debug tokens, private IPs in config |
| GS024 | 2 | precise | ✅ | LLM-based SQL injection (pilot — replaces 87 regex patterns) |
| YAML-36ACF0AD | 2 | custom | ⬜ | Use of eval() or exec() with dynamic input can lead to code injection |
| YAML-ECB85AD8 | 2 | custom | ⬜ | DEBUG=True in production Django/Flask config |
| YAML-B39DC08C | 2 | custom | ⬜ | Printing potentially sensitive data to stdout |
| YAML-A7E2F001 | 2 | custom | ⬜ | Reverse shell one-liner detected — definitive backdoor indicator |
| YAML-SSTI001 | 2 | custom | ⬜ | Server-Side Template Injection (SSTI): user input flowing into template render without sanitization — can lead to RCE |
