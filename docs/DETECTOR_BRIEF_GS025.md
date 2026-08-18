# Бриф: GS025 — AI-Code Provenance (precision-улучшение)

> Самодостаточный бриф для внешнего агента **без доступа к репозиторию**.
> Весь код детектора вшит внутрь. Задача — **снизить FP при неизменном recall (TPR drop ≤ 3%)**.
> Формат и контракт — по образцу `DETECTOR_BRIEF_GS017.md` / `DETECTOR_IMPROVEMENT_BRIEF.md`.

---

## 1. Что это за детектор

**GS025 — AI-Code Provenance Scanner**, Echelon 2 (SECURITY). Две задачи:
1. оценить вероятность AI-происхождения файла (`ai_provenance_score` — только metadata, НЕ гейтит выдачу);
2. ловить «AI-favored insecure defaults» — небезопасные дефолты, которые чаще всего ставит AI-ассистент:
   - `permissive_cors` — `CORS(allow_origins=["*"])` / `Access-Control-Allow-Origin: *`;
   - `debug_mode` — `debug = True` / `DEBUG = True` / `app.run(debug=True)`;
   - `wildcard_bind` — `host = "0.0.0.0"`;
   - `eval_usage` — `eval(` / `exec(` / `child_process … eval`;
   - `hardcoded_secret` — `api_key/secret/password/token/client_secret = "…12+ символов…"`;
   - `insecure_random` — `random.random()` / `Math.random()` рядом с auth/token/session/otp;
   - `no_rate_limit_auth` — route-декоратор `@app.route/@router.*` с `login/signin/auth/token/password` в URL.

**Ключевая особенность (из docstring):** «GS025 patterns are real vulnerabilities — **always reported**. AI score only boosts confidence». То есть это НЕ «детектор AI-кода», а **обычные insecure-дефолты с приклеенной AI-меткой** — отчасти дублирует GS001 (hardcoded secrets) и другие детекторы. AI-скор ни на что не влияет, только добавляет metadata.

**Проблема:** под `rule_id LIKE 'GS025%'` в БД лежит **3 553 находки**, но сам bucket «GS025» сломан: его 664 HIGH — это **не AI-provenance**, а чужие находки (CVE + file-permissions), застрявшие под чужим rule_id. Цель брифа — разобрать шум по слоям (БД-уровень + детектор-уровень), не потеряв реальные insecure-дефолты.

## 2. Срез из живой БД (снимок 2026-08-18)

```
GS025 по rule_id (raw):
  GS025 (plain, БЕЗ суффикса)                 CRITICAL 30 | HIGH 664 | MEDIUM 927      = 1 621
  GS025 (GS025: AI-Code Provenance — …)       LOW 508                                 = 508
  GS025-debug_mode                            HIGH 10 | MEDIUM 131                     = 141
  GS025-eval_usage                            HIGH 95 | MEDIUM 147                     = 242
  GS025-hardcoded_secret                      CRITICAL 110 | MEDIUM 720                = 830
  GS025-no_rate_limit_auth                    MEDIUM 72                                = 72
  GS025-permissive_cors                       HIGH 4                                   = 4
  GS025-wildcard_bind                         MEDIUM 135                               = 135
  ИТОГО GS025%                                                                           = 3 553
```

**Три разных «сорта» под одним префиксом:**

| Сорт | Кол-во | Что это реально |
|---|---|---|
| `GS025` (plain) | **1 621** (30/664/927) | **0% AI-заголовков.** Только `CVE-2026-*` (Information disclosure 865, Privilege escalation 379, Buffer overflow 62, SSRF 28, Path traversal 39, Auth bypass 13, Command injection 11) + `World-readable file: … (664/644)` + `chmod: World-readable configs`. Это находки **SCA/CVE-движка и file-permission детектора**, ошибочно записанные с `rule_id="GS025"`. |
| `GS025 (GS025: AI-Code Provenance — …)` | 508 (LOW) | **Баг форматирования rule_id** — записано `f"{RULE_ID} ({description})"`. Но заголовки настоящие AI (`eval_usage` 253, `debug_mode` 199, `hardcoded_secret` 43, `wildcard_bind` 8, `insecure_random` 3, `permissive_cors` 2). |
| `GS025-<pattern_id>` | 1 424 | **Настоящий детектор** (текущая схема). Из них **1 168 строк — с пустым `file_path` и `line_number=0`** (legacy до фикса bridge). |

**Проекты — plain `GS025` (загрязнение):**

| Проект | Находок | Что это |
|---|---|---|
| `/tmp/gsc-perf-h_xcndkh/1m` | 664 | перф-корпус (`mod_*.py`, mode 664) → «World-readable file» |
| `benchmark/real_world/thefuck` | 285 | real code → `CVE-2026-56233: Privilege escalation` (sudo-правила) |
| `/tmp/gsc-hunt-3`, `hunt-2` | 79 / 69 | hunt-сканы |
| `/tmp/gsc-perf-h_xcndkh/100k` | 67 | перф-корпус |
| `/tmp/gsc-external/web-lgsm`, `harvestr`, `LinuxReport` | 62 / 30 / 21 | external-сканы |
| `httpie`, `youtube-dl`, `sanic`, `loguru`, `rich` | 18 / 18 / 16 / 15 / 15 | real frameworks → «World-readable .yml» |

**Проекты — `GS025-<pattern>` (реальный детектор):**

| Проект | Находок | Что это |
|---|---|---|
| `/tmp/gsc-hunt-4` | 622 | hunt-скан: `backend/src/routers/*.py` → no_rate_limit_auth / permissive_cors / wildcard_bind |
| `benchmark/real_world/sanic` | 280 | фреймворк |
| `fastapi-users` | 66 | фреймворк |
| `youtube-dl` | 48 | real code |
| `loguru` | 35 | real code |
| `thefuck` | 18 | real code (`eval`/`exec` в rules) |
| `Hyperion`, `django-mfa`, `piccolo-api`, `rich`, `hunt-5/1/2` | 14…8 | real/hunt |

**Вывод:** 664 HIGH, приписываемые GS025 как «шум» — это **загрязнение rule_id** (CVE + file-permissions), а не AI-provenance. Реальный шум детектора — в суффиксных `GS025-*` правилах (раздел 4).

---

## 3. Код детектора (вшит целиком)

Файл: `gsc_core/gsc_detectors/gs025_ai_provenance.py`.

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS025 — AI-Code Provenance Scanner.

Two tasks:
  1. Estimate AI provenance likelihood (ai_provenance_score).
  2. Catch insecure defaults that AI assistants set most often
     (permissive CORS, debug=True, wildcard bind, hardcoded secrets,
      eval, insecure random, missing rate limits).

Design: GS025 patterns are real vulnerabilities — always reported.
AI score only boosts confidence and adds metadata. Not a duplicate
of existing 23 detectors: focus is on "AI-favored insecure defaults".
Deduplication via finding_key in gsc_external.
"""
from __future__ import annotations

import re
from typing import Any

from . import AuditContext, Finding

# ── AI provenance markers (comment patterns across languages) ──────
AI_MARKERS: list[tuple[str, float]] = [
    (r"(?:#|//|\*)\s*(?:Generated|Created|Written|Assisted|Authored|Scaffolded)"
     r"\s+by\s+(?:AI|Copilot|GPT[-\s]?\d*|Claude|Cursor|ChatGPT|an?\s+assistant)", 0.40),
    (r"(?:#|//)\s*TODO:\s*(?:review|verify|check|audit|harden|secure)\b", 0.15),
    (r'(?:#|//|"""|\*)\s*Examples?:\s*\n', 0.10),
    (r"\b(?:openai|anthropic|langchain|llama_index|ChatCompletion)\b", 0.10),
]

# ── AI-favored insecure defaults ──────────────────────────────────
AI_VULN_PATTERNS: list[tuple[str, str, str, float]] = [
    ("permissive_cors",
     r'CORS\([^)]*allow_origins=\[\s*["\']\*["\']\s*\]'
     r'|Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*',
     "HIGH", 0.70),
    ("debug_mode",
     r"\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|\bapp\.run\([^)]*debug\s*=\s*True",
     "HIGH", 0.75),
    ("wildcard_bind",
     r'host\s*=\s*["\']0\.0\.0\.0["\']',
     "MEDIUM", 0.55),
    ("eval_usage",
     r"\beval\s*\(|\bexec\s*\(|\bchild_process\b.*\beval\b",
     "HIGH", 0.70),
    ("hardcoded_secret",
     r"(?:api[_-]?key|secret|password|passwd|token|client_secret)"
     r"\s*[:=]\s*[\"'][A-Za-z0-9_\-./+]{12,}[\"']",
     "CRITICAL", 0.80),
    ("insecure_random",
     r"\brandom\.random\(\).*(?:auth|token|session|otp)"
     r"|\bMath\.random\(\).*(?:auth|token|session|otp)",
     "MEDIUM", 0.60),
    ("no_rate_limit_auth",
     r"@(?:app\.route|router\.(?:get|post|put|delete))\([^)]*"
     r"(?:login|signin|auth|token|password)[^)]*\)",
     "MEDIUM", 0.50),
]

AI_THRESHOLD = 0.5


class GS025Detector:
    """AI-Code Provenance + AI-favored insecure defaults. Regex-only, fork-safe."""

    rule_id = "GS025"
    name = "AI Code Provenance Scanner"
    requires_llm = False

    def detect(self, file_path: str, content: str, language: str = "auto") -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if not content:
            return findings

        ai_score = self._ai_likelihood(content)

        for pattern_id, regex, severity, base_conf in AI_VULN_PATTERNS:
            for match in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = self._snippet(content, line_no)

                confidence = base_conf
                if ai_score >= AI_THRESHOLD:
                    confidence = min(0.95, base_conf + ai_score * 0.2)

                findings.append({
                    "rule_id": f"GS025-{pattern_id}",
                    "title": f"AI-favored insecure default: {pattern_id}",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "file": file_path,
                    "line": line_no,
                    "snippet": snippet,
                    "language": language,
                    "metadata": {
                        "ai_provenance_score": round(ai_score, 2),
                        "ai_generated_likely": ai_score >= AI_THRESHOLD,
                        "pattern_id": pattern_id,
                    },
                })
        return findings

    def _ai_likelihood(self, content: str) -> float:
        score = 0.0
        for regex, weight in AI_MARKERS:
            if re.search(regex, content, re.IGNORECASE):
                score += weight
        lines = content.splitlines()
        if len(lines) > 200:
            comment_count = sum(1 for ln in lines if ln.strip().startswith(("#", "//", "/*", "*")))
            if comment_count < 5:
                score += 0.10
        return min(1.0, score)

    def _snippet(self, content: str, line_no: int, window: int = 2) -> str:
        lines = content.splitlines()
        start = max(0, line_no - 1 - window)
        end = min(len(lines), line_no + window)
        return "\n".join(lines[start:end])


# ── Registry bridge (module-level interface expected by DetectorEntry) ──
RULE_ID = "GS025"
ECHELON = 2
NOISE_TIER = "normal"
description = "GS025: AI-Code Provenance — detect AI-favored insecure defaults"


def detect(ctx) -> list[Finding]:
    """Bridge function for registry compatibility.

    Converts GS025Detector's internal dicts to the Finding contract
    (file_path/line_number/detail) so downstream consumers can locate
    findings. Previously returned raw dicts with 'file'/'line' keys,
    which resolved to file_path=None in gsc_external.
    """
    det = GS025Detector()
    findings = []
    files = ctx.files if ctx.files else list(ctx.path.rglob("*"))
    for fp in files:
        if not fp.is_file():
            continue
        if fp.suffix not in {'.py', '.js', '.ts', '.tsx', '.go', '.rs', '.java', '.rb', '.php'}:
            continue
        try:
            content = ctx.file_contents.get(str(fp), fp.read_text(errors='replace'))
        except Exception:
            continue
        rel = str(fp.relative_to(ctx.path)) if ctx.path in fp.parents else str(fp)
        for raw in det.detect(rel, content):
            findings.append(Finding(
                rule_id=raw["rule_id"],
                category=raw["severity"],
                title=raw["title"],
                file_path=raw["file"],
                line=raw["line"],
                detail=raw.get("snippet", ""),
                confidence=raw.get("confidence"),
                metadata=raw.get("metadata"),
                language=raw.get("language"),
            ))
    return findings
```

---

## 4. Реальные FP (из БД, file:line → что заматчилось)

### 4.0 Слои шума на уровне БД (не детектор, но 80% объёма)

| file:line (пример) | заматчилось | почему это НЕ GS025 |
|---|---|---|
| `benchmark/real_world/sanic/mkdocs.yml:0` | `World-readable file: mkdocs.yml (664)` | находка **file-permission детектора**, rule_id замазан на `GS025` |
| `benchmark/real_world/thefuck/thefuck/rules/sudo.py:25` | `CVE-2026-56233: Privilege escalation` | находка **SCA/CVE-движка**, rule_id замазан на `GS025` |
| `benchmark/real_world/httpie/httpie/ssl_.py:89` | `CVE-2026-56219: Authentication bypass` | то же |
| `…/rich/tools/make_width_tables.py:14` | `CVE-2026-56233: Path traversal` | то же |
| `<1 168 строк GS025-*>` | `file_path='' , line_number=0, detail=''` | legacy-строки до фикса bridge (docstring прямо это описывает) |
| `/tmp/tmp2ri0jisy/test.py:1,2` × ~55 клонов | `password = "my-super-secret-password"` / `API_TOKEN="ghp_abc...123"` | **самоскан тест-фикстуры** (см. `tests/test_regression.py` t10/t14) |
| `/tmp/tmp3tzy2jfn/test.py:1` × клоны | `def exec(u): return eval(u)` | **самоскан калибровочной фикстуры** `scripts/gsc_setup_calibration.py:11` (`eval-demo`, GS008) |

### 4.1 `debug_mode` — матчит комментарии, conditional, Django-boilerplate

| file:line | заматчилось | почему FP |
|---|---|---|
| `app/config.py:873` (hunt-2) | `The trap being warned about is unchanged. @LeeNX set ``DEBUG=true``…` | **комментарий/docstring**, `DEBUG=true` (lowercase) матчится под IGNORECASE |
| `app/main.py:472` (hunt-2) | `# He set DEBUG=true, read "debug OFF"…` | комментарий |
| `app/server.py:24` (deck) | `debug=True if session.config.DEBUG else False,` | **conditional** флаг, не хардкод-дефолт |
| `EcommerceBackend/settings.py:37` (hunt-3) | `DEBUG = True` под `# SECURITY WARNING: don't run with debug…` | **Django scaffold-дефолт**, есть в каждом Django-проекте |
| `digikala/settings.py:24` | `DEBUG = True` (scaffold) | то же |
| `scripts/sim_crashloop.py:27` (hunt-2) | `class Cfg: debug = True` | **симулятор crash-loop**, не production |

### 4.2 `no_rate_limit_auth` — флагует ЛЮБОЙ auth-названный route, rate-limit не проверяется

| file:line | заматчилось | почему FP |
|---|---|---|
| `app/core/auth/endpoints_auth.py:923` (Hyperion) | `@router.post("/auth/introspect")` | OAuth-метаданные, `token`-подстрока |
| `app/core/auth/endpoints_auth.py:1110,1119` | `@router.get("/oidc/.../jwks_uri")`, `@router.get("/.well-known/oauth-authorization-server")` | OIDC discovery, `auth`-подстрока |
| `app/core/documents/endpoints_documents.py:479` | `@router.get("/documents/{document_id}/token")` | `token` в path документа |
| `src/fastapi_oauth2/router.py:8,15` | `@router.get("/{provider}/authorize")`, `/{provider}/token` | OAuth-callback route |
| `app/routes/web/login.py:14` (deck) | `@router.get('/osu-login.php')` | legacy redirect-route |
| `project/app/api/v1/endpoints/auth.py:127` (hunt-1) | `@router.post("/login")` | route есть, но rate-limit может стоять middleware'ом — детектор этого не проверяет |

### 4.3 `hardcoded_secret` — матчит имена ключей, print/комментарии, тестовые данные

| file:line | заматчилось | почему FP |
|---|---|---|
| `apps/web/src/features/ai/model/apiKeyStorage.ts:2` (hunt-5) | `const AI_CREDENTIALS_KEY = 'markinote.ai.credentials.v1'` | **имя ключа**, не секрет-значение |
| `contoh_docker_sandbox.py:26` (localLLM) | `print("ERROR: OPENAI_API_KEY tidak ditemukan!")` | строка в print, только упоминает имя ключа |
| `contoh_openhands.py:21,24,42` (localLLM) | `# export OPENAI_API_KEY='***'`, `# API_KEY = 'sk-…'` | **комментарии**/README-пример |
| `fix_install.py:113`, `task_assistant.py:11` (localLLM) | `$env:OPENHANDS_CLOUD_API_KEY = "sk-oh-…"` | usage-строка/дока |
| `account_api/tests.py:136` (hunt-3) | `email='account-staff@example.com'` | **тестовая фикстура** |
| `sale_api/tests.py:22,28,123…` (hunt-3) | `password='test…'`, `email='…@example.com'` | тестовые данные |
| `generate_themed_logo.py:10` (LinuxReport) | `1. Get an OpenRouter API key from …` | README-инструкция |

### 4.4 `wildcard_bind` / `permissive_cors` (мало, но тоже шум)

| file:line | заматчилось | почему FP |
|---|---|---|
| `webhook_server.py:224` (Telegram-shop) | `app.run(host='0.0.0.0', port=5000, debug=False)` | 0.0.0.0 за reverse-proxy/docker — намеренно |
| `backend/src/routers/hls.py:292` (hunt-4) | `headers={"Access-Control-Allow-Origin": "*"}` | ACAO:* для **медиа-стриминга** (публичный контент), не API-auth bypass |
| `backend/src/routers/media.py:155` (hunt-4) | `"Access-Control-Allow-Origin": "*"` | то же |

---

## 5. Лиды (по приоритету)

> Каждый лид — самостоятельный фикс. Принимаются только подтверждённые на реальном коде (`FP↓ при TP-константе`). Не резать recall. Лиды 1–3 — на уровне сбора/БД, лиды 4–6 — в самом детекторе.

### Лид 1 (максимум эффекта, сбор/БД) — plain `GS025` = чужие находки, не трогать детектор
**Симптом:** 1 621 находка (30 CRIT / 664 HIGH / 927 MED) под `rule_id="GS025"` без суффикса; **0% заголовков AI** — только `CVE-2026-*` и `World-readable file` / `chmod: World-readable`.
**Корень:** при записи в БД `rule_id` затирается на `"GS025"` для находок SCA/CVE-движка и file-permission детектора (те же заголовки существуют под корректными `rule_id="CVE-2026-56233: Path traversal"`, `"chmod: World-readable"`).
**Фикс:** найти точку записи, где чужой `rule_id` перетирается модульным `RULE_ID="GS025"`; для precision-замера GS025 исключить/remap plain-`GS025` на корректные rule_id. **Детектор не менять.**

### Лид 2 (сбор/БД) — legacy-строки с пустым `file_path`/`line_number=0`
**Симптом:** 1 168 из 1 424 суффиксных находок нелокализуемы (`hardcoded_secret` 720/830, `eval_usage` 147/242, `debug_mode` 131/141, `wildcard_bind` 130/135, `no_rate_limit_auth` 40/72).
**Корень:** docstring bridge прямо описывает баг — «Previously returned raw dicts with 'file'/'line' keys, which resolved to file_path=None». Строки записаны до фикса.
**Фикс:** purge этих строк + re-scan. **Не детектор** (фикс уже в коде — `detect(ctx)` конвертирует в `Finding`).

### Лид 3 (сбор/БД) — самоскан тест-фикстур + третий вариант rule_id
**Симптом:** `GS025-hardcoded_secret` CRITICAL 110 — все `test.py:1,2` (`password = "my-super-secret-password"` + `API_TOKEN="ghp_abc...123"`), размножены по десяткам `/tmp/tmp*` клонов; `GS025-eval_usage` non-empty — все `test.py:1` `def exec(u): return eval(u)` (фикстура `scripts/gsc_setup_calibration.py:11`, `eval-demo`). Плюс 508 находок с rule_id `"GS025 (GS025: AI-Code Provenance — …)"` — `f"{RULE_ID} ({description})"`.
**Фикс:** (a) исключить GSC-собственные фикстуры/калибровочный корпус из реальных сканов (path-exclusion `test.py`/`/tmp/tmp*`/`calibration/`); (b) починить запись rule_id (двойной баг: `RULE_ID` вместо `raw["rule_id"]` и конкатенация с description).

### Лид 4 (детектор, `debug_mode`) — сузить regex: не матчить комментарии/conditional/scaffold
**Фикс:**
- пропускать строки-комментарии и docstring (`^\s*(#|//|/\*|\*|"""|''')\s*…`, с учётом `re.MULTILINE`);
- требовать **настоящее присваивание флага**, а не lowercase `true` в прозе: матчить только `\bDEBUG\s*=\s*(?:True|true)\b` в **коде**, не в комментарии; либо убрать `re.IGNORECASE` и матчить ровно `debug = True` / `DEBUG = True`;
- пропускать conditional: `debug\s*=\s*(?:True|False)\s*if\s+` / `… else …`;
- опционально skip Django-scaffold: строка `DEBUG = True` в `settings.py` сразу под `# SECURITY WARNING: don't run with debug turned on in production`.
**Убирает:** `app/config.py:873`, `app/main.py:472`, `app/server.py:24`, `EcommerceBackend/settings.py:37`, `digikala/settings.py:24`, `scripts/sim_crashloop.py:27`.

### Лид 5 (детектор, `no_rate_limit_auth`) — «missing rate limit» не проверяет отсутствие rate-limit
**Фикс (на выбор):**
- сузить URL-матчинг с substring до **точных эндпоинтов** `(?:/|\")login(?:/|\")|signin|/password|/register` — отсекает `authorize`/`authorization`/`introspect`/`jwks_uri`/`/documents/{id}/token`/`/{provider}/token`;
- либо (корректнее) **искать доказательство отсутствия rate-limiter**: если в файле есть `@ratelimit` / `limiter.limit` / `RateLimit` / `slowapi` / `throttle` — не флагать (context analysis ±N строк).
**Убирает:** `endpoints_auth.py:923,1110,1119`, `endpoints_documents.py:479`, `fastapi_oauth2/router.py:8,15`, `login.py:14`.

### Лид 6 (детектор, `hardcoded_secret`) — не матчить имена ключей, print/комментарии, тесты
**Фикс:**
- пропускать **имена ключей/констант**: `const/let/var NAME = '…'` в JS/TS, `NAME = "…"` где `NAME` содержит `KEY/TOKEN/SECRET` (это идентификатор, не значение);
- пропускать строки в **print/комментариях/README** (строка, где до `=` идёт `print(`/`#`/`//`/`echo`/`$env:`);
- path-exclusion тестовых файлов: `*_test.*`, `*.test.*`, `tests.py`, `tests/`, `test_*.py`;
- оставить только **реальное присваивание значения переменной** (`^\s*(?:api_key|secret|password|passwd|token|client_secret)\s*=\s*["'][…]{12,}["']`), не substring в произвольном коде.
**Убирает:** `apiKeyStorage.ts:2`, `contoh_docker_sandbox.py:26`, `contoh_openhands.py:21,24,42`, `fix_install.py:113`, `account_api/tests.py:136`, `sale_api/tests.py:22…`.

---

## 6. Контракт верификации (обязателен перед приёмкой)

1. **Smoke** на синтетических TP/FP в `/tmp/gs025_smoke.py` через `AuditContext(project, path)` / `detect(ctx)`:
   - **TP должны остаться:** `api_key = 'abcdefghijklmnop'` (16-симв. секрет → hardcoded_secret; это `tests/test_regression.py` t10); `app.run(debug=True)` в app.py; `CORS(allow_origins=["*"])` / `Access-Control-Allow-Origin: *` (permissive_cors, CWE-1188); `host = "0.0.0.0"` в app.run; `eval(user_input)` / `exec(code)`; route `@router.post("/login")`.
   - **FP должны уйти:** `# He set DEBUG=true…` (комментарий); `debug=True if session.config.DEBUG else False`; Django `DEBUG = True` под `# SECURITY WARNING`; `const AI_CREDENTIALS_KEY = 'markinote.ai.credentials.v1'`; `print("…OPENAI_API_KEY tidak ditemukan")`; `# API_KEY = 'sk-…'`; `@router.get("/{provider}/token")`; `@router.get("/.well-known/oauth-authorization-server")`; `password='test…'` в `*_test.py`.
2. **Полный прогон:** `python3 -m pytest -q`; отдельно `python3 tests/test_regression.py` (там `t10` «GS025: findings carry file_path» — все находки обязаны иметь `file_path`), `python3 tests/test_compliance_secrets.py` (строка 27: `compliance_for("GS025-permissive_cors")["cwe"] == "CWE-1188"`).
3. **Проверка на живом коде:** перегнать GS025 на `/tmp/gsc-hunt-4` (или `benchmark/real_world/sanic`) — счётчик FP по `no_rate_limit_auth`/`debug_mode`/`hardcoded_secret` должен упасть, TP не потеряны.
4. **БД-лиды (1–3) верифицировать отдельно:** после фикса записи — переснять срез `SELECT rule_id, category, COUNT(*) FROM findings WHERE rule_id LIKE 'GS025%' GROUP BY rule_id, category;` и убедиться, что plain-`GS025` больше не получает чужие CVE/World-readable заголовки.

## 7. Жёсткие инварианты (нарушать нельзя)

- `RULE_ID = "GS025"`, схему `rule_id = "GS025-<pattern_id>"` и `finding_key` не менять (иначе ломаются 98K находок + self-learning + compliance-mapping `GS025-permissive_cors → CWE-1188`).
- `Finding(...)` с полями `rule_id=`, `category=` (severity), `title=`, `file_path=`, `line=`, `detail=` — НЕ dict руками с `file=`/`line=` (это и был legacy-баг).
- Severity-шкалу не менять (`permissive_cors`/`debug_mode`/`eval_usage`=HIGH, `hardcoded_secret`=CRITICAL, `wildcard_bind`/`insecure_random`/`no_rate_limit_auth`=MEDIUM).
- TP-кейсы не резать (TPR drop ≤ 3%): реальные `debug=True` в продакшене, реальные `api_key = "…"`, `CORS(allow_origins=["*"])` на API-эндпоинтах.
- Детектор целиком не отключать — только фильтры/сужения/гейты (правило пользователя).
- `ai_provenance_score` — только metadata, **не** делать его гейтом для выдачи (иначе сломается заявленный «always reported» и recall).
- Код-стиль: только stdlib (`re`, `typing`); расширения файлов `.py/.js/.ts/.tsx/.go/.rs/.java/.rb/.php` не менять.

---

*Файл детектора: `gsc_core/gsc_detectors/gs025_ai_provenance.py`.*
*Срез БД: `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE rule_id LIKE 'GS025%' GROUP BY rule_id, category;"` — переснять перед работой.*
*Колонки БД: `category` (=severity), `file_path`, `line_number` (НЕ `line`), `detail`.*
