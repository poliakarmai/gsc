# Бриф: GS014 — Credential Exposure (precision-улучшение)

> Самодостаточный бриф для внешнего агента **без доступа к репозиторию**.
> Весь код детектора вшит внутрь. Задача — **снизить FP при неизменном recall (TPR drop ≤ 3%)**.
> Формат и контракт — по образцу `DETECTOR_BRIEF_GS017.md`.

---

## 1. Что это за детектор

**GS014 — Credential Exposure**, Echelon 2 (SECURITY). Ищет:
- Unquoted service paths / Windows-креды (SAM/SYSTEM, `ntds.dit`, DPAPI, `SiteList.xml`);
- Stored credential files (RDP/`.rdg`/`credentials.xml`);
- приватные ключи (`id_rsa`, `*.pem`, `*.key`);
- env/credential файлы (`.env`, `.envrc`, `.credentials`);
- unattended-файлы (`autounattend.xml`, `kickstart`, `preseed.cfg`);
- shell-history в репо (`.bash_history`, `.zsh_history`);
- контентные паттерны: base64-пароль в unattend, WireGuard `PrivateKey`, **PostgreSQL connection string с паролем**, sudoers `NOPASSWD:ALL` / `ALL=(ALL) ALL`.

**Проблема:** на живых сканах GS014 даёт **1347 находок**, из которых ~96% — FP. Почти весь шум сосредоточен в **трёх** паттернах из девяти:
1. glob приватных ключей (`id_rsa`, `*.pem`, `*.key`) — **1243 MEDIUM** (92.3%);
2. regex `postgres(?:ql)?://user:pass@` — **78 HIGH** (5.8%);
3. glob env/credential (`*.env`, `*credentials*`) — **26 LOW** (1.9%).

Остальные 6 паттернов (SAM/DPAPI/RDP/unattend/history/WireGuard/sudoers/base64-unattend) в текущем срезе БД дают **0 находок** — их FP не подтверждён, их не трогаем.

## 2. Срез из живой БД (снимок 2026-08-18)

```
GS014 по title:
  Private key file — verify proper permissions …  1243  (MEDIUM)
  PostgreSQL connection string with embedded pass   78  (HIGH)
  Environment/credential file — check for …         26  (LOW)
  ────────────────────────────────────────────────────
  ИТОГО                                            1347
```

Раскладка по проектам (откуда шум):

| Проект | Находок | Что это |
|---|---|---|
| `cryptography` | 1220 | **тест-векторы** `vectors/cryptography_vectors/**/*.pem` (публичные ключи для тестов) |
| `sqlalchemy` | 27 | docstring-примеры `postgresql://scott:***@localhost/test` |
| `urllib3` | 20 | тестовые сертификаты `dummyserver/certs/*`, `test/*.pem` |
| `pydantic` | 15 | docstring-примеры `PostgresDsn` / `MultiHostUrl` |
| `/tmp/gsc-hunt-4` | 13 | **real code** (remnawave): compose/install.sh — mix TP/FP |
| `peewee` | 12 | docstring-примеры `postgresql://` |
| `polars` | 12 | docstring-примеры `postgresql://` |
| `uv` | 6 | `credentials.rs` (source) + docstring postgres |
| `pandas` | 4 | docstring `read_sql_table` |
| `redis-py` | 4 | `redis/credentials.py` (source-код) |
| `twisted` | 4 | `cred/credentials.py` (source) + postgres doc |
| `youtube-dl` (benchmark/real_world) | 3 | `test/testcert.pem` |
| `ansible` | 3 | `test/integration/.../types.env` (fixture) |
| `salt` | 3 | `highstate_doc.py` (docstring postgres) |
| `/tmp/gsc-hunt-3` | 1 | `test.env` |

**Ключевой вывод:** 1240 из 1243 «private key» приходят из **`cryptography` — это тест-векторы криптобиблиотеки** (публичные ключи, нужны тестам). 78 «PostgreSQL» — это **docstring-примеры с уже замаскированным паролем `***`** (`scott:***@`) в SQLAlchemy/pydantic/pandas/peewee/polars. 26 «env/credential» — это **исходники `credentials.py`/`credentials.rs`**, пойманные слишком широким glob `*credentials*`.

---

## 3. Код детектора (вшит целиком)

Файл: `gsc_core/gsc_detectors/gs014_credential_exposure.py` (170 строк).

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS014 — Credential Exposure Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects credential exposure patterns from Redteam Kit:
- Unquoted service paths (Windows)
- Stored credentials in config files
- SAM/SYSTEM backup files
- Credential files in home directories
- AlwaysInstallElevated registry equivalent (Linux sudoers)
- DPAPI/Credential Manager files
- MacAfee SiteList.xml passwords
- Unattended installation files (autounattend.xml, kickstart)

Sources: Window Privilege Escalation, SSH Hardening & Offensive Mastery,
2025 Playbooks (Credential Stuffing)
"""
from . import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS014"
ECHELON = 2
description = "Credential exposure — stored credentials, backup auth files, weak sudoers"


# Files that indicate credential exposure
CREDENTIAL_FILE_PATTERNS = [
    # Windows-like credential files
    (["*.sam", "*.sam.bak", "SYSTEM", "SYSTEM.bak", "ntds.dit"],
     "Potential SAM/SYSTEM backup — Windows credential database",
     "CRITICAL", "SAM/SYSTEM backups allow offline credential extraction."),

    # DPAPI master keys
    (["*/DPAPI/*", "*/Microsoft/Protect/*"],
     "DPAPI master key file — encrypted credential storage",
     "MEDIUM", "DPAPI keys may contain decryptable credentials if user password is known."),

    # Credential manager files
    (["*.rdp", "*.rdg", "credentials.xml", "SiteList.xml"],
     "Stored credential file (RDP/MacAfee/credential manager)",
     "HIGH", "RDP and credential manager files may contain saved passwords."),

    # SSH keys with weak paths
    (["id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key"],
     "Private key file — verify proper permissions and no passphrase",
     "MEDIUM", "Private keys should have 600 permissions and passphrase protection."),

    # Config files with potential credentials
    (["*.env", ".env.*", "*.envrc", ".credentials", "*credentials*"],
     "Environment/credential file — check for hardcoded secrets",
     "LOW", "These files should be gitignored. Verify no secrets are committed."),

    # Unattended installation files
    (["autounattend.xml", "unattend.xml", "Unattend.xml",
      "*.kickstart", "preseed.cfg", "answerfile*"],
     "Unattended installation file — may contain encoded passwords",
     "CRITICAL", "Unattended files often contain base64-encoded admin passwords."),

    # Shell history files (shouldn't be in repo)
    ([".bash_history", ".zsh_history", ".fish_history", ".psql_history", ".mysql_history"],
     "Shell history file in repo — may contain credentials in command lines",
     "MEDIUM", "Shell history files may contain passwords passed as command arguments."),
]

# Content-based patterns
CONTENT_PATTERNS = [
    # Base64-encoded admin password in autounattend
    (re.compile(r'<AdministratorPassword>.*?<Value>([^<]{20,})</Value>', re.I | re.DOTALL),
     "Base64-encoded admin password in unattend file", "CRITICAL",
     "Windows autounattend.xml contains encoded Administrator password. "
     "This is trivially decodable (base64)."),

    # WireGuard/OpenVPN keys in config
    (re.compile(r'PrivateKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}', re.I),
     "WireGuard private key in config", "HIGH",
     "WireGuard PrivateKey exposed in configuration file. "
     "Use external key storage or environment variable."),

    # PostgreSQL connection strings with password
    (re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@', re.I),
     "PostgreSQL connection string with embedded password", "HIGH",
     "Database URL contains password in plaintext. Use environment variable."),

    # sudoers: NOPASSWD for ALL commands
    (re.compile(r'^\s*\S+\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*NOPASSWD\s*:\s*ALL', re.I | re.MULTILINE),
     "sudoers NOPASSWD:ALL — unrestricted sudo without password", "HIGH",
     "NOPASSWD on ALL commands allows privilege escalation without re-authentication. "
     "Restrict to specific commands with NOPASSWD."),

    # sudoers: user with ALL=(ALL) ALL
    (re.compile(r'^\s*(\S+)\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*ALL', re.I | re.MULTILINE),
     "sudoers: full sudo access — verify it's intentional", "LOW",
     "Full sudo access detected. Verify user requires full privileges."),
]


def _match_glob(path: Path, pattern: str) -> bool:
    """Simple glob matching for credential file patterns."""
    import fnmatch
    # Handle path patterns like */DPAPI/*
    if "/" in pattern or "\\" in pattern:
        return fnmatch.fnmatch(str(path).replace("\\", "/"), pattern)
    return fnmatch.fnmatch(path.name, pattern)


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS014" in ctx.skipped_detectors:
        return []
    findings = []

    # Get ALL files (not just source — credential files may be in any location)
    all_files = ctx.get_files()

    for fp in all_files:
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Check filename patterns
        for patterns, title, severity, detail in CREDENTIAL_FILE_PATTERNS:
            for pat in patterns:
                if _match_glob(fp, pat):
                    # Don't flag SSH keys in .ssh/ directories (user home)
                    if fp.suffix in (".pem", ".key") or fp.name.startswith("id_"):
                        if ".ssh/" in str(fp):
                            continue  # Expected location for SSH keys

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=1,
                        severity=severity,
                        title=title,
                        detail=detail,
                        fix_suggestion="Remove from repository. Add to .gitignore. "
                                       "Rotate any exposed credentials.",
                        references=["Window Privilege Escalation Guide",
                                    "SSH Hardening & Offensive Mastery"]
                    ))
                    break  # One finding per file

        # 2. Check content-based patterns (only for text files)
        if fp.suffix in (".xml", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json",
                         ".txt", ".md", ".sh", ".bash", ".py", ".rb", ""):
            try:
                content = fp.read_text()
            except Exception:
                continue

            for pattern, title, severity, detail in CONTENT_PATTERNS:
                for match in pattern.finditer(content):
                    lineno = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity=severity,
                        title=title,
                        detail=detail,
                        fix_suggestion="Remove hardcoded credential. Use environment variables "
                                       "or secrets manager. Rotate exposed secrets.",
                        references=["Redteam Kit", "2025 Playbooks - Credential Stuffing"]
                    ))

    return findings
```

---

## 4. Реальные FP (из БД, file:line → что заматчилось)

### 4.1 `Private key` glob (`id_rsa`, `*.pem`, `*.key`) — 1243 MEDIUM, главный шум

`*.pem`/`*.key` матчатся по **имени файла** (`fnmatch(path.name, pattern)`), без разбора содержимого. Единственный skip — `.ssh/`-каталог. Всё остальное — тест-векторы и публичные сертификаты:

| file:line | заматчилось | почему FP |
|---|---|---|
| `vectors/cryptography_vectors/asymmetric/DH/dhkey.pem:1` | `*.pem` | **тест-вектор** (публичный ключ для юнит-тестов) |
| `vectors/cryptography_vectors/asymmetric/EC/secp256r1-explicit-seed.pem:1` | `*.pem` | тест-вектор |
| `vectors/cryptography_vectors/asymmetric/Ed25519/ed25519-pkcs8.pem:1` | `*.pem` | тест-вектор |
| `vectors/cryptography_vectors/asymmetric/MLKEM/mlkem768.pem:1` | `*.pem` | тест-вектор |
| … (ещё ~1216 файлов `vectors/cryptography_vectors/**`) | `*.pem`/`*.key` | все — фикстуры крипто-тестов |
| `dummyserver/certs/cacert.pem:1` (urllib3) | `*.pem` | **публичный CA-сертификат** тестового сервера |
| `dummyserver/certs/server.key:1` (urllib3) | `*.key` | тестовый ключ dummyserver |
| `test/contrib/duplicate_san.pem:1` (urllib3) | `*.pem` | тестовый сертификат |
| `test/testcert.pem:1` (urllib3, youtube-dl) | `*.pem` | тестовый сертификат |

**Корень:** glob по имени файла не отличает (а) тестовые фикстуры от реальных кредов, (б) публичные ключи/сертификаты от приватных. `*.pem` ловит `cacert.pem`, `*pub*.pem`, `*.crt` — всё это НЕ приватные ключи.

### 4.2 `PostgreSQL connection string` — 78 HIGH, docstring-примеры с замаскированным паролем

Regex `postgres(?:ql)?://[^:]+:[^@]+@` хватает любой `user:pass@` в **документации**. Пароль в примерах SQLAlchemy — это `scott:***` (канонический пример с уже отредкетированным паролем):

| file:line | заматчилось | почему FP |
|---|---|---|
| `lib/sqlalchemy/dialects/postgresql/psycopg.py:81,103` | `postgresql://scott:***@localhost/test` | docstring-пример, пароль = `***` (уже redacted) |
| `lib/sqlalchemy/ext/automap.py:150,180` | `postgresql://scott:***@localhost/test` | docstring-пример |
| `lib/sqlalchemy/dialects/oracle/base.py:195` | `postgresql://…` в доке | docstring-пример |
| `lib/sqlalchemy/sql/events.py:76` | `postgresql://…` | docstring |
| `lib/sqlalchemy/testing/provision.py:126` | `postgresql://…` | тестовый provision-код |
| `pydantic/networks.py:765,767,770,773,775,778,786` | `postgres://user:***@localhost:5432/foobar` | docstring `PostgresDsn`/`MultiHostUrl`, пароль `***` |
| `pandas/io/sql.py:369,683` | `postgresql://user:pass@…` | docstring `read_sql_table` |
| `peewee.py:4410,4487,4549` | `postgresql://user:password@…` | docstring `PostgresqlDatabase` |
| `playhouse/cockroachdb.py:62,68`, `playhouse/flask_utils.py:99,111` | `postgresql://…` | docstring-примеры |
| `py-polars/.../frame.py:4417,4445`, `io/database/functions.py:367,438,445,458` | `postgresql://…` | docstring-примеры |
| `salt/modules/highstate_doc.py:217` | `postgresql://…` | документация |
| `test/typing/plain_files/engine/engines.py:33` | `postgresql://…` | typing-тест |

**НЕ трогать (TP):** `/tmp/gsc-hunt-4/docker-compose.remnawave-dev.yml`, `/tmp/gsc-hunt-4/scripts/install.sh`, `/tmp/gsc-hunt-4/backend/scripts/import_legacy.py` — там реальные default-креды `remnawave:remnawave@` (username == password), это настоящий credential exposure.

**Корень:** regex не различает (а) docstring/комментарий vs код, (б) пароль-плейсхолдер (`***`, `pass`, `password`, `scott`, `tiger`) vs реальное значение.

### 4.3 `Environment/credential file` glob (`*credentials*`, `*.env`) — 26 LOW

| file:line | заматчилось | почему FP |
|---|---|---|
| `redis/credentials.py:1` (redis-py) | `*credentials*` | **исходник** — класс `CredentialProvider` |
| `crates/uv-auth/src/credentials.rs:1` (uv) | `*credentials*` | исходник (Rust) |
| `crates/uv-git/src/credentials.rs:1` (uv) | `*credentials*` | исходник |
| `src/twisted/cred/credentials.py:1` (twisted) | `*credentials*` | исходник — `twisted.cred` интерфейс |
| `test/integration/targets/config/files/types.env:1` (ansible) | `*.env` | тестовая фикстура |
| `test.env:1` (/tmp/gsc-hunt-3) | `*.env` | тестовый env |
| `deploy/dev/remnawave-stands/2.7.4/stand.env:1` … `3.2.3/stand.env:1` (hunt-4) | `.env.*` | dev-stand env (граничный случай — возможно TP) |

**Корень:** glob `*credentials*` ловит любые **исходники с именем "credentials"** (`credentials.py`/`credentials.rs` — это код авторизации, не файл с сохранёнными секретами). `*.env`/`.env.*` ловит тестовые и example-фикстуры.

---

## 5. Лиды (по приоритету)

> Каждый лид — самостоятельный фикс. Принимаются только подтверждённые на реальном коде (`FP↓ при TP-константе`). Не резать recall.

### Лид 1 (максимум эффекта, ~92% шума) — path-exclusion для тест-векторов/фикстур в `Private key`-glob
**Симптом:** 1243 MEDIUM, из них 1220 (`cryptography` vectors) + 20 (urllib3 dummyserver/test) + 3 (youtube-dl test) — всё тестовые публичные ключи/сертификаты.
**Фикс:** гейт в `detect()` по пути (`rel_path`) — пропускать приватные ключи в тестовых/фикстурных каталогах:
`vectors/`, `testdata/`, `fixtures/`, `tests/`, `test/`, `dummyserver/`, `*/test/*`, `*/tests/*`, `*.example`, `*.sample`.
**Ожидание:** 1243 → ~0. Реальные приватные ключи в корне/конфигах репо остаются.

### Лид 2 (главный контентный баг, ~6% шума) — PostgreSQL: пропускать redacted/placeholder пароли и docstring
**Симптом:** 78 HIGH, из них ~73 — docstring-примеры с `scott:***@` / `user:pass@` / `user:password@`.
**Фикс (двухступенчатый):**
1. **Пароль-плейсхолдер:** не матчить, если значение пароля (между `:` и `@`) ∈ `{***, pass, password, secret, changeme, example, your, xxx, pwd, scott, tiger, user, test, admin}` (case-insensitive, слово целиком). Это снимает `scott:***@` и `user:pass@`, но **сохраняет** `remnawave:remnawave@` (не в словаре).
2. **Контекст docstring:** пропускать матч, если ближайший выше по строке стоит неэкранированный `"""`/`'''` (match внутри docstring) или строка закомментирована (`#`/`//`/`--`). Опционально — но надёжнее пароль-фильтра.
**Ожидание:** 78 → ~5 (остаются hunt-4 compose/install.sh TP).

### Лид 3 — `*credentials*` glob ловит исходники
**Симптом:** `redis/credentials.py`, `twisted/cred/credentials.py`, `uv-auth/src/credentials.rs`, `uv-git/src/credentials.rs` — это **код**, не файлы с сохранёнными секретами.
**Фикс:** сузить паттерн — заменить `*credentials*` на явные имена файлов с секретами (`.credentials`, `credentials.yml`, `credentials.json`, `credentials.ini`, `.netrc`), **либо** исключить source-расширения (`.py`, `.rs`, `.js`, `.ts`, `.java`, `.go`, `.rb`, `.php`) для этого паттерна. Файл `credentials.py` — модуль авторизации, не хранилище.
**Ожидание:** снимает 12 из 26 LOW (redis-py, uv×2, twisted).

### Лид 4 — `*.env`/`.env.*` glob: исключить example/test env-фикстуры
**Симптом:** `test.env`, `test/integration/targets/config/files/types.env` — тестовые env-файлы, не реальные секреты.
**Фикс:** пропускать имена `*.env.example`, `*.env.sample`, `*.env.template`, `*.env.test`, `test.env`, а также env-файлы внутри `test/`/`tests/`/`fixtures/` (пересекается с Лидом 1).
**Ожидание:** снимает `test.env`, ansible fixture. **Граница:** `deploy/dev/remnawave-stands/*/stand.env` — dev-stand env, может быть TP; резать аккуратно, только `.example/.sample/.template/.test`.

### Лид 5 — `*.pem`/`*.key`: отличать приватный ключ от публичного/сертификата по содержимому
**Симптом:** `*.pem` матчит `cacert.pem`, `*pub*.pem`, `*.crt`, `ed25519-pub.pem` — публичные материалы.
**Фикс:** для текстовых `.pem`/`.key` читать первые байты и срабатывать только при наличии приватного PEM-маркера (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`). Публичные (`BEGIN CERTIFICATE`, `BEGIN PUBLIC KEY`, `BEGIN X509`) и бинарные/пустые — пропускать. Это превращает грубый name-glob в контентный чек и снимает `cacert.pem`/`*pub*.pem`.
**Ожидание:** дополнительный срез MEDIUM на реальных проектах (urllib3 dummyserver, если не покрыт Лидом 1).

### Лид 6 (данные/косметика, НЕ детектор) — дубликаты и расщеплённый `rule_id`
1. **Дубликаты:** одна и та же находка повторяется ×4 (`redis/credentials.py:1`), ×3 (`test/testcert.pem:1`), ×2 (`pydantic/networks.py:778`) — накопление по разным `run_id`. Для отчётов dedup по `finding_key` внутри `run_id`. **Детектор не трогать.**
2. **Расщеплённый `rule_id`:** часть находок под `GS014`, часть под `GS014 (Credential exposure — stored credentials, backup auth files,)` — старый баг задания `rule_id` (title попал в rule_id). Это ломает инвариант `finding_key = sha256(rule_id+file+snippet)`: одни и те же находки дают разные ключи. Считать срез как `LIKE 'GS014%'`. Мигрировать правило в БД (`UPDATE findings SET rule_id='GS014' …`), **в коде детектора `RULE_ID = "GS014"` уже корректен — не менять.**

---

## 6. Контракт верификации (обязателен перед приёмкой)

1. **Smoke** на синтетике в `/tmp/gs014_smoke/` через `AuditContext(project, path)`:
   - **TP должны остаться:** `id_rsa` в корне репо; `server.key` вне `.ssh/`/`test/`; `autounattend.xml` с `<AdministratorPassword><Value>…base64…</Value>`; WireGuard `PrivateKey = <44 base64 chars>`; `postgresql://remnawave:remnawave@postgres:5432/remnawave` (username==password); `sudoers` `deploy ALL=(ALL) NOPASSWD: ALL`; `.bash_history`; `.credentials` (без расширения).
   - **FP должны уйти:** `vectors/**/dhkey.pem`, `test/testcert.pem`, `dummyserver/certs/cacert.pem`; `postgresql://scott:***@localhost/test`, `postgresql://user:pass@host/db`, `postgres://user:password@…` (в docstring); `redis/credentials.py`, `credentials.rs`; `test.env`, `*.env.example`.
2. **Полный прогон:** `python3 -m pytest -q`, `python3 tests/test_regression.py` — standalone, запускать `python3 tests/...` напрямую.
3. **Проверка на живом коде:** перегнать GS014 на `cryptography`, `sqlalchemy`, `urllib3`, `pydantic` — FP-счёт должен упасть с 1347 до ~десятков, TP в `/tmp/gsc-hunt-4` (compose/install.sh) не потеряны.

## 7. Жёсткие инварианты (нарушать нельзя)

- `RULE_ID = "GS014"` и `finding_key` не менять.
- TP-кейсы не резать (TPR drop ≤ 3%): реальные `id_rsa`/`*.key` вне тестовых каталогов, `remnawave:remnawave` в compose, WireGuard `PrivateKey`, sudoers, unattend/base64 — остаются.
- Severity-шкалу не менять (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW` как в `CREDENTIAL_FILE_PATTERNS`/`CONTENT_PATTERNS`).
- Детектор целиком не отключать — только path-exclusion / regex-сужение / context-анализ.
- `references` и `fix_suggestion` сохранить (совместимость с отчётами).
- Код-стиль: stdlib (`re`, `pathlib`, `fnmatch`); `Finding` — dict-like (`severity=`, `file_path=`, `line=`); файлы через `ctx.get_files()` (этот детектор сканирует ВСЕ файлы, не только source — не сужать до `get_source_files`).
- Лид 6 (дубликаты/rule_id) — правка БД/отчётов, **не** детектора.

---

*Файл детектора: `gsc_core/gsc_detectors/gs014_credential_exposure.py`.*
*Срез БД: `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE rule_id LIKE 'GS014%' GROUP BY rule_id, category;"` — переснять перед работой (учесть расщеплённый rule_id, см. Лид 6).*
