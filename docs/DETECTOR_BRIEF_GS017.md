# Бриф: GS017 — Weak & Default Passwords (precision-улучшение)

> Самодостаточный бриф для внешнего агента **без доступа к репозиторию**.
> Весь код детектора вшит внутрь. Задача — **снизить FP при неизменном recall (TPR drop ≤ 3%)**.
> Формат и контракт — по образцу `DETECTOR_BRIEF_GS020.md` / `DETECTOR_BRIEF_GS022.md`.

---

## 1. Что это за детектор

**GS017 — Weak & Default Passwords**, Echelon 2 (SECURITY). Ищет:
- default-креды (`admin:admin`, `root:root`, русские/enterprise дефолты);
- слабые пароли в connection strings (`mysql://user:password@...`);
- Docker `ENV`/`ARG` с дефолтным паролем;
- хардкод переменных `PASSWORD/PWD/SECRET/...` с коротким значением;
- слабую парольную политику (min length < 8);
- короткие пароли в `.env`;
- закомментированные пароли;
- слабые хеши паролей (`md5/sha1/crypt($password)`).

**Проблема:** на живых сканах GS017 даёт **852 HIGH** находки, из которых подавляющее большинство — FP. Цель брифа — срезать этот шум, не потеряв реальные weak/default пароли.

## 2. Срез из живой БД (снимок 2026-08-17)

```
GS017 по severity:  HIGH 852 | CRITICAL 6 | LOW 1  (итого 859)
```

Раскладка по проектам (откуда шум):

| Проект | Находок | Что это |
|---|---|---|
| `/tmp/gsc-perf-h_xcndkh/1m` | 664 | **перф-корпус (синтетика, `mod_*.py`)** |
| `/tmp/gsc-perf-h_xcndkh/100k` | 67 | перф-корпус |
| `/tmp/gsc-hunt-4` | 28 | hunt-скан (real code) |
| `benchmark/real_world/sanic` | 24 | **фреймворк Sanic (real code)** |
| `twisted` | 14 | фреймворк Twisted (real code) |
| `/tmp/gsc-perf-ud1o1lji/10k` | 7 | перф-корпус |
| `benchmark/real_world/youtube-dl` | 9 | youtube-dl (real code) |
| `benchmark/real_world/piccolo-api` | 6 | piccolo-api (real code) |
| … остальное | <4/проект | httpie, sphinx, pipenv, Telegram-shop и т.д. |

**Ключевой вывод:** ~86% шума (738 из 852) приходит из **перф-корпусов `/tmp/gsc-perf-*/`** — это синтетические файлы `mod_0000.py … mod_0499.py` с автогенерированными строками `password = 'SuperSecretNNN'`. Остальной шум — **реальный код фреймворков**, где детектор ловит `key=None`, `pwd=None`, `key=key`, `password = pwd` и т.п.

---

## 3. Код детектора (вшит целиком)

Файл: `gsc_core/gsc_detectors/gs017_weak_passwords.py` (229 строк).

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS017 — Weak & Default Passwords Detector
Echelon: 2 (SECURITY)
Category: CRITICAL

Detects weak and default credentials — a top-3 fintech vulnerability per 2026 pentests:
- Hardcoded default passwords (admin:admin, root:root)
- Weak password policies (no complexity, short minimums)
- Default credentials in configs, Dockerfiles, .env files
- Common Russian/enterprise default passwords
- Database connection strings with weak passwords

Sources: 2026 Fintech Pentest Report, OWASP ASVS V2.1, PCI-DSS 8.3
"""
import re
from pathlib import Path
from . import AuditContext, Finding

RULE_ID = "GS017"
ECHELON = 2
NOISE_TIER = "normal"
description = (
    "Weak & default passwords — admin:admin, default creds, "
    "weak password policies, hardcoded DB passwords"
)

# ── Default credential pairs ─────────────────────────────────────────────────

# Common Russian/enterprise default:password pairs
DEFAULT_CREDS = re.compile(
    r'(?:^|\n)\s*'
    r'(?:'
    r'(?:admin|administrator|root|sa|postgres|mysql|guest|test|user|operator|manager|supervisor|support)'
    r')\s*[:=]\s*'
    r'[\'"](?:admin|password|passw0rd|123456|12345678|qwerty|root|test|guest|changeme|P@ssw0rd|'
    r'secret|default|temp|temp123|Welcome1|Summer202[0-9]|Winter202[0-9])[\'"]\s*',
    re.IGNORECASE,
)

# Connection strings with weak passwords
WEAK_DB_PASSWORDS = re.compile(
    r'(?:mongodb|mysql|postgres(?:ql)?|sqlite|oracle|mssql|redis)://'
    r'[^:]*:'
    r'(?:admin|password|root|123456|qwerty|test|guest|changeme|secret|passw0rd)'
    r'@',
    re.IGNORECASE,
)

# Docker ENV with weak password defaults
DOCKER_DEFAULT_PASSWORDS = re.compile(
    r'^\s*(?:ENV|ARG)\s+'
    r'(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|SA_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|'
    r'REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|ADMIN_PASSWORD|DEFAULT_PASSWORD)\s+'
    r'(?:admin|password|root|123456|qwerty|changeme|secret)\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Hardcoded passwords in variable assignments
HARDCODED_PASSWORD_VARS = re.compile(
    r'^\s*(?:PASSWORD|PASSWD|PASS|PWD|SECRET|ADMIN_PASS|DB_PASS|DB_PASSWORD|API_SECRET)'
    r'\s*[:=]\s*[\'"]([^\'"]{1,20})[\'"]\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Weak password policy (min length < 8, no complexity)
WEAK_PASSWORD_POLICY = re.compile(
    r'(?:min(?:imum)?[_\s]*(?:password|pwd)[_\s]*(?:length|len|size))\s*[:=]\s*([0-7])\b',
    re.IGNORECASE,
)

# .env files with short passwords (< 8 chars)
SHORT_ENV_PASSWORDS = re.compile(
    r'^\s*(?:PASSWORD|PASS|PWD|SECRET|KEY)\s*=\s*[\'"]?([^\s\'"]{1,7})[\'"]?\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# Known weak password hashes (unsalted MD5, SHA1)
WEAK_HASH_ALGORITHMS = re.compile(
    r'\b(?:md5|sha1|crypt)\s*\(\s*[\'"]\$password[\'"]',
    re.IGNORECASE,
)

# Password in comments/documentation
COMMENTED_PASSWORDS = re.compile(
    r'^\s*(?:#|//|<!--|;)\s*'
    r'(?:password|пароль)\s*[:=]\s*\S+\s*$',
    re.IGNORECASE | re.MULTILINE,
)


def _is_placeholder(value: str) -> bool:
    """Filter out placeholder/example values."""
    return any(skip in value.lower() for skip in (
        '***', 'your-', 'changeme', 'placeholder', 'example',
        'test', 'xxxx', 'secrethere', 'put_your', 'replace',
        'ваш_', 'пример',
    ))


def _lineno(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS017" in ctx.skipped_detectors:
        return []
    findings = []

    scan_extensions = (".py", ".js", ".ts", ".go", ".java", ".rb", ".php",
                       ".env", ".toml", ".yaml", ".yml", ".json", ".cfg",
                       ".ini", ".conf", ".cnf", ".xml", ".sh", ".bash",
                       ".sql", "Dockerfile", ".dockerfile")

    for fp in ctx.get_source_files(extensions=scan_extensions):
        try:
            content = fp.read_text()
        except Exception:
            continue
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Default credential pairs
        for match in DEFAULT_CREDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title=f"Default credentials: {match.group(0).strip()[:80]}",
                detail="Hardcoded default credential pair detected. Common in pentests.",
                fix_suggestion="Remove hardcoded credentials. Use secrets manager or env vars with strong unique passwords.",
                noise_tier="precise",
            ))

        # 2. Weak DB connection strings
        for match in WEAK_DB_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="CRITICAL",
                title="Database connection string with weak password",
                detail=f"Weak DB password in connection string: {match.group(0)[:100]}",
                fix_suggestion="Use strong randomly-generated passwords for all DB connections. Store in secure vault.",
                noise_tier="precise",
            ))

        # 3. Docker default passwords
        for match in DOCKER_DEFAULT_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Docker default password in ENV/ARG",
                detail=match.group(0).strip(),
                fix_suggestion="Use build-time secrets or docker secrets instead of hardcoded defaults.",
                noise_tier="precise",
            ))

        # 4. Hardcoded password variables (short values only)
        for match in HARDCODED_PASSWORD_VARS.finditer(content):
            password_value = match.group(1)
            if _is_placeholder(password_value):
                continue
            if len(password_value) >= 20:
                continue  # Skip long random-looking strings
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Hardcoded password variable: {match.group(0).strip()[:100]}",
                detail=f"Password variable with short value ({len(password_value)} chars).",
                fix_suggestion="Move to secure secrets manager. Use env vars with fallback to generated secrets.",
                noise_tier="normal",
            ))

        # 5. Weak password policy
        for match in WEAK_PASSWORD_POLICY.finditer(content):
            min_len = int(match.group(1))
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title=f"Weak password policy: min length = {min_len}",
                detail=f"Password minimum length set to {min_len} (PCI-DSS requires 8+, ASVS 12+).",
                fix_suggestion="Enforce minimum 12 characters with complexity requirements per ASVS V2.1.",
                noise_tier="normal",
            ))

        # 6. Short .env passwords
        for match in SHORT_ENV_PASSWORDS.finditer(content):
            env_value = match.group(1)
            if len(env_value) < 5:
                findings.append(Finding(
                    rule_id=RULE_ID, file_path=rel_path,
                    line=_lineno(content, match.start()),
                    severity="HIGH",
                    title=f"Very short password in .env: {match.group(0).strip()[:80]}",
                    detail=f"Password length = {len(env_value)} chars.",
                    fix_suggestion="Use minimum 20+ character random passwords for all secrets.",
                    noise_tier="precise",
                ))

        # 7. Commented passwords
        for match in COMMENTED_PASSWORDS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="LOW",
                title="Password visible in comment",
                detail=match.group(0).strip(),
                fix_suggestion="Remove passwords from comments. Use references to secrets manager.",
                noise_tier="normal",
            ))

        # 8. Weak hash algorithms for passwords
        for match in WEAK_HASH_ALGORITHMS.finditer(content):
            findings.append(Finding(
                rule_id=RULE_ID, file_path=rel_path,
                line=_lineno(content, match.start()),
                severity="HIGH",
                title="Weak password hashing algorithm (MD5/SHA1/CRYPT)",
                detail=match.group(0).strip(),
                fix_suggestion="Use bcrypt, argon2id, or scrypt for password hashing.",
                noise_tier="precise",
            ))

    return findings
```

---

## 4. Реальные FP (из БД, file:line → что заматчилось)

### 4.1 `SHORT_ENV_PASSWORDS` — главный источник шума в реальном коде

Название правила — «.env short passwords», но оно выполняется на **всех** расширениях (`.py/.js/.sh/.go/...`). На реальном коде фреймворков ловит мусор:

| file:line | заматчилось | почему FP |
|---|---|---|
| `sanic/cookies/response.py:292,306` | `key=key,` | keyword-arg `key=key` |
| `sanic/response/types.py:164,206` | `key=key,` | keyword-arg |
| `sanic/cli/app.py:286` | `key = (` | вызов/продолжение, не пароль |
| `sanic/http/tls/creators.py:96` | `key = (` | то же |
| `src/twisted/python/util.py:17,21` | `pwd = None` / `pwd = _pwd` | default arg / импорт |
| `src/twisted/conch/checkers.py:70` | `pwd = None` | default arg |
| `youtube_dl/utils.py:6552` | `key = None` | default arg |
| `youtube_dl/extractor/common.py:1164` | `password = None` | default arg |
| `scripts/install.sh:525,771,1745…` | `key="$1"`, `key="$2"` | shell positional params |
| `django_rls/context.py:120` | `key=key,` | keyword-arg |
| `taser/exp/web/httpauth.py:63` | `password = pwd,` | HTTP-auth param |
| `seo_recommend.py:167` | `key = pair` | dict-пример `{key: pair}` |
| `database/models.py:14` | `KEY = "key"` | имя==значение |

**Корень:** значение `([^\s'"]{1,7})` жадно хватает любой короткий токен — `None`, `(`, `$1`, `$2`, `_pwd`, `key`, `pair`, `pwd` — плюс глотает хвостовую запятую (`key=key,`).

### 4.2 `HARDCODED_PASSWORD_VARS` — флагует не-слабые значения

| file:line | заматчилось | почему FP |
|---|---|---|
| `mod_0499.py:666` … `mod_0000.py` | `password = 'SuperSecret331'` (и NNN=000…331) | 13 симв., mixed-case+digits, **не слабый** пароль |
| `scripts/install.sh:384` | `secret="${4:-0}"` | shell default, не пароль |
| `docker-compose-prod.yaml:8` | `PASSWORD: "demopassword"` | *(это TP — реальный дефолт, не трогать)* |

**Корень:** правило ловит ЛЮБОЙ `PASSWORD/PWD/SECRET = "<1-19 симв.>"`, не проверяя, слабое ли значение. `SuperSecret331` — сильная строка, к «Weak & Default Passwords» отношения не имеет.

---

## 5. Лиды (по приоритету)

> Каждый лид — самостоятельный фикс. Принимаются только подтверждённые на реальном коде (`FP↓ при TP-константе`). Не резать recall.

### Лид 1 (максимум эффекта) — перф-корпуса `/tmp/gsc-perf-*` не должны попадать в находки
**Симптом:** 664 + 67 + 7 = 738 HIGH из перф-корпусов `mod_*.py`.
**Фикс (на выбор, не в самом детекторе, а на уровне сбора проектов):**
- исключить пути `/tmp/gsc-perf-*` из precision-замера/БД (это bench-запуски производительности, а не аудит реального кода);
- либо в детекторе добавить path-exclusion для синтетических `mod_\d{4}\.py` (но это костыль — лучше чинить источник).

### Лид 2 (главный детекторный баг) — `SHORT_ENV_PASSWORDS` выполнять только на `.env`-файлах
**Фикс:** гейт по расширению. `SHORT_ENV_PASSWORDS` — про `.env`, значит применять только к `.env`, `.env.*`, `.env.example`, `.env.local`, `.env.production` и т.п. (и, опционально, к `.ini/.conf/.cnf/.cfg` секциям с `KEY=`).
**Ожидание:** снимает sanic/twisted/youtube-dl/httpie/piccolo-api/install.sh шум (~90% реального кода), сохраняя настоящие `.env` секреты.

### Лид 3 — `SHORT_ENV_PASSWORDS`: выкинуть `None`/`null`/`nil`/`true`/`false` и знаки в значении
**Фикс:** значение не должно быть `None`/`null`/`nil`/`true`/`false`; и класс значения сузить до `[A-Za-z0-9_\-@#$.]{1,7}` (никаких `(`, `,`, `$`, пробелов). Плюс: значение ≠ имени ключа (отсекает `key=key`, `KEY="key"`).

### Лид 4 — `HARDCODED_PASSWORD_VARS`: проверять, что значение реально слабое
**Фикс:** добавить `_is_weak_value()` — значение срабатывает только если:
- входит в common/слабый словарь (`123456`, `password`, `admin`, `qwerty`, `admin123`, …), ИЛИ
- полностью в нижнем регистре без цифр/смешанного регистра (`demopassword`, `testuser`), ИЛИ
- чистые цифры/короткий (< 8).
`SuperSecret331` (mixed-case+digits) — пропускаем. Это выравнивает правило с названием детектора («Weak & Default»).

### Лид 5 — `HARDCODED_PASSWORD_VARS`: shell-подстановки `${N:-...}` / `$N` не пароли
**Фикс:** пропускать значения вида `$...` и `${...}` (shell positional/default). `secret="${4:-0}"` → FP.

### Лид 6 (косметика) — дубликаты в БД
Одна и та же находка (file:line:title) повторяется 3–4 раза (напр. `sanic/cookies/response.py:292` ×4). Это накопление по разным `run_id`, не баг детектора. Для отчётов — dedup по `finding_key` внутри одного `run_id`. **Не трогать сам детектор.**

---

## 6. Контракт верификации (обязателен перед приёмкой)

1. **Smoke** на синтетических TP/FP в `/tmp/gs017_smoke.py` через `AuditContext(project, path)`:
   - **TP должны остаться:** `admin:admin`, `root:root` (DEFAULT_CREDS); `mysql://user:password@host` (WEAK_DB); `ENV MYSQL_ROOT_PASSWORD password` (DOCKER); `.env` с `SECRET=abc` (короткий реальный секрет); `password = "admin123"`; слабая политика `min_length=6`; `md5($password)`.
   - **FP должны уйти:** `key=None`, `pwd=None`, `password=None`, `key=key`, `key = pair`, `key = (`, `KEY="key"`, `secret="${4:-0}"`, `key="$1"`, `password = 'SuperSecret331'`.
2. **Полный прогон:** `python3 -m pytest -q` (ожидание 294 passed), `python3 tests/test_regression.py` (16/16), `python3 tests/test_compliance_secrets.py` (8/8) — они standalone, запускать `python3 tests/...` напрямую.
3. **Проверка на живом коде:** перегнать GS017 на `benchmark/real_world/sanic` и `twisted` — FP-счёт должен упасть в разы, TP не потеряны.

## 7. Жёсткие инварианты (нарушать нельзя)

- `RULE_ID = "GS017"` и `finding_key` не менять.
- TP-кейсы не резать (TPR drop ≤ 3%).
- Severity-шкалу не менять (`CRITICAL`/`HIGH`/`LOW` как есть).
- Детектор целиком не отключать — только фильтры/сужения/гейты.
- `_is_placeholder()` — расширять аккуратно, не ломая `changeme`/`example`/`test` (эти значения в TP-словаре DEFAULT_CREDS/DOCKER — не дублировать фильтрацию).
- Код-стиль: только stdlib (`re`, `pathlib`); `Finding` — dict-like (`severity=`, `file_path=`, `line=`); `ctx.get_source_files(extensions=...)`.

---

*Файл детектора: `gsc_core/gsc_detectors/gs017_weak_passwords.py`.*
*Срез БД: `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE rule_id LIKE 'GS017%' GROUP BY rule_id, category;"` — переснять перед работой.*
