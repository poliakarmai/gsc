# AGENTS.md — GSC

> Навигация для AI-агентов. Git Security Checker — self-learning audit system.

## Что это

Трёхэшелонный аудитор кода с самообучением. 200+ seed-паттернов, SQLite DB, Obsidian-отчёты.  
Каждая находка становится паттерном для будущих аудитов.

## Структура

```
gsc/
├── gsc.py              ← CLI entry point (scan, init, dashboard, patterns, db)
├── patterns/           ← Seed patterns (OWASP Top 10, CWE Top 25, Python)
│   ├── owasp.json      ← OWASP 2021 Top 10
│   ├── cwe.json        ← CWE Top 25
│   └── python.json     ← Python-specific anti-patterns
├── dashboard/          ← Web dashboard
├── tests/              ← Tests
├── AGENTS.md           ← This file
└── README.md           ← User documentation
```

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

```
gsc scan <project>
  ├── load_patterns (DB + seed files)
  ├── E1: Source-driven (grep patterns)
  ├── E2: Security (regex + file permissions)
  ├── E3: Adversarial (semantic patterns)
  └── save_findings → SQLite + Obsidian
```

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
