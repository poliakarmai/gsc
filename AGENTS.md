# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — self-learning audit system.

## Что это

Трёхэшелонный аудитор кода с самообучением. 200+ seed-паттернов, SQLite DB, Obsidian-отчёты.  
Каждая находка становится паттерном для будущих аудитов.

## Структура

```\ngsc/\n├── gsc.py              ← CLI entry point (scan, init, dashboard, patterns, db)\n├── gsc_detectors/      ← Plugin detector system (CVE Lite-inspired, v0.6, 26.06.2026)\n│   ├── __init__.py     ← AuditContext, Finding, Detector interface\n│   ├── registry.py     ← ALL_DETECTORS, get_detectors(), run_detectors()\n│   ├── gs001_hardcoded_secret.py  ← API keys, tokens, passwords in code\n│   ├── gs002_world_readable.py    ← Sensitive files with permissive permissions\n│   └── gs003_debug_prints.py      ← print() / console.log left in production\n├── patterns/           ← Seed patterns (OWASP Top 10, CWE Top 25, Python)\n│   ├── owasp.json      ← OWASP 2021 Top 10\n│   ├── cwe.json        ← CWE Top 25\n│   └── python.json     ← Python-specific anti-patterns\n├── dashboard/          ← Web dashboard\n├── tests/              ← Tests\n├── AGENTS.md           ← This file\n└── README.md           ← User documentation\n```

## Как запускать

```bash
cd ~/gsc

# CLI
python3 gsc.py scan pci-index          # аудит проекта
python3 gsc.py scan bybit-ws --json    # JSON-вывод
python3 gsc.py init                    # инициализация в проекте
python3 gsc.py dashboard               # веб-дашборд (:8080)
python3 gsc.py patterns --seed 200     # засеять 200 паттернов
python3 gsc.py patterns --list         # список активных паттернов
python3 gsc.py db "SELECT COUNT(*) FROM findings"  # запрос к БД
```

## Архитектура

```\ngsc scan <project>\n  ├── load_patterns (DB + seed files)\n  ├── E1: Source-driven (grep patterns + plugin detectors GS001, GS003)\n  ├── E2: Security (regex + file permissions + plugin detector GS002)\n  ├── E3: Adversarial (semantic patterns)\n  └── save_findings → SQLite + Obsidian\n```\n\n### Plugin Detector System (v0.6)\n\nInspired by OWASP CVE Lite CLI override detectors. Each detector is an independent module:\n\n```python\ndef detect(ctx: AuditContext) -> list[Finding]:\n    # Check condition → return Finding with rule_id, severity, fix_suggestion, references\n```\n\n**Detectors:**\n| Rule | Category | Echelon | Description |\n|------|----------|---------|-------------|\n| GS001 | CRITICAL | 1 | Hardcoded secrets (API keys, tokens, passwords) |\n| GS002 | HIGH | 2 | World-readable sensitive files (.pem, .key, .env) |\n| GS003 | LOW | 1 | Debug/diagnostic code left in production (print, console.log) |
| GS004 | MEDIUM | 1 | Dangerous subprocess calls (shell=True, unsafe commands) |
| GS005 | HIGH | 2 | SQL injection patterns (string formatting in queries) |
| GS007 | HIGH | 2 | Insecure Direct Object Reference (IDOR) |
| GS008 | LOW | 1 | Dead code: constants and feature flags declared but never used |\n\n**Adding a detector:**\n1. Create `gsc_detectors/gsNNN_name.py` with `detect(ctx)`, `RULE_ID`, `ECHELON`, `description`\n2. Register in `gsc_detectors/registry.py` → `import ... as _gsNNN` + `DetectorEntry(...)`\n3. Done — `gsc scan` picks it up automatically

## Инварианты

1. **Самообучение обязательно.** После каждого аудита находки сохраняются в DB.
2. **Patterns first.** Перед grep — DB. Перед LLM — grep. Экономия токенов.
3. **CLI over delegate_task.** `gsc scan` = автономный, не требует Hermes-агента.
4. **DB — SSOT.** `~/.hermes/state/gsc_audit.db` — единственный источник правды.

## Связанные компоненты

| Компонент | Путь |
|-----------|------|
| GSC DB | `~/.hermes/state/gsc_audit.db` |
| Seed patterns | `~/gsc/patterns/*.json` |
| Loader script | `~/.hermes/scripts/gsc_load_patterns.py` |
| Saver script | `~/.hermes/scripts/gsc_save_findings.py` |
| Obsidian reports | `~/obsidian-vault/audits/` |
