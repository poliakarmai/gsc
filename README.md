# 🛡️ GSC — Git Security Checker

[![GSC on GitHub Marketplace](https://img.shields.io/badge/Marketplace-GSC%20Security%20Audit-blue)](https://github.com/marketplace/actions/gsc-security-audit)
[![Plugin Security Scan](https://github.com/poliakarmai/gsc/actions/workflows/plugin-scan.yml/badge.svg)](https://github.com/poliakarmai/gsc/actions/workflows/plugin-scan.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## English

**GSC is a self-learning AppSec platform that proves exploits, verifies fixes, and heals CI.**

```
detect → prove → fix → verify → heal → learn
```

```console
$ gsc scan . --ci --json
[{"rule_id": "GS001", "severity": "CRITICAL", "title": "Hardcoded API key",
  "file_path": "app.py", "line": 1, "fix_suggestion": "Move this value to an env var"}]
```

Most scanners report matches. GSC **proves them**: every finding can be turned into a
runnable proof-of-concept, validated in a sandbox, then fixed and re-verified by
re-running the exploit.

**What makes it different:**

- **68 detectors** across SAST, SCA, secrets and IaC — plus a YAML rule DSL.
- **PoC auto-generation** with a safe-exploitation gate: a finding ships with a working exploit, not just a line number.
- **Proof-of-Fix** — a patch is only accepted after the exploit stops firing in a sandbox.
- **Self-learning** — detectors are re-scored nightly against a calibration network; noisy patterns are auto-deactivated at <30% TP. Federated feedback is privacy-first (`{tenant_hash, rule_id, tp, fp}` + DP noise).
- **Priority by exploitability, not CVSS** — EPSS + CISA KEV + ExploitDB.
- **BYO-LLM** — the engine, detectors and PoC logic are ours; LLM revalidation runs on *your* key (any OpenAI-compatible endpoint, including a local Ollama). No key → fast regex-only mode.

**Who it is for:** platform/DevSecOps teams that need findings *proven* before a PR blocks;
AppSec engineers triaging noisy regex output; AI coding agents that need a scanner tool over MCP.

**Use it as a GitHub Action** (see below), from the **CLI / Docker image**, or as an
**MCP server** for AI coding agents — ten tools (`scan_repo`, `scan_diff`,
`list_findings`, `get_finding`, `get_poc`, `verify_finding`, `verify_findings`,
`verify_fix`, `doctor`, `list_detectors`) over stdio or HTTP.
Read-only towards your repository: no patching, no PRs, no writes to the working tree.
(`verify_finding` does execute a PoC — see the safety notes in the MCP section.)

**Proven on real code:** [HALL_OF_FAME.md](HALL_OF_FAME.md) ·
first public case study: [CASE_STUDY_CYBERBRO.md](CASE_STUDY_CYBERBRO.md)

### Measured on 100 real GitHub projects

The same fixed corpus is re-scanned after detector changes — 100 real repositories
(90 clean + 10 known-vulnerable), pinned to specific commits, **regex-only, no LLM key**.
Same projects every run, so a delta is the fix and not a new dataset.

| | 2026-08-21 (baseline) | 2026-08-28 (after FP fixes) |
|---|---|---|
| Findings | 64,831 | 41,127 |
| CRITICAL | 4,302 | 414 |
| HIGH | 37,246 | 2,187 |
| Known-vulnerable projects flagged | 8 / 10 | **10 / 10** |
| Clean projects with ≥1 false CRITICAL | 48 / 90 | 41 / 90 |

CRITICAL precision on a labeled review of 434 findings: **~4–5% at baseline → 31.1%**
(TP = 135, FP = 299, 2026-08-26). That is still noisy. The remaining false-positive mass is
concentrated in GS001 (secrets), GS005 (SQLi), GS020 (XSS) and GS037 (path traversal) and is
worked down rule by rule — we publish the numbers we have, not the numbers we would like.

*Method note:* corpus, severity counting and per-rule aggregation are ours; the engine ships as
a closed image, so reproducing this means running `gsc scan --ci --json` over the same pinned
projects and aggregating the same way. No clean-room comparison against other vendors is implied.

**License:** this repo (Action, docs, marketing) is **Apache-2.0**. The engine ships as a
closed Docker image `ghcr.io/poliakarmai/gsc-scanner` under **BSL 1.1** (free to scan your own
repos; competing SaaS requires a commercial license; converts to Apache-2.0 on 2030-08-06).

### Case study: XSS in a 698★ OSINT platform (stars as of 2026-10-26)

First public proof — [`stanfrbd/cyberbro`](https://github.com/stanfrbd/cyberbro) (46,677 LOC, 281 files):

| | |
|---|---|
| Finding | **CWE-79** XSS via search highlight — `static/history.js:50`, `p.innerHTML = p.title.replace(...)` |
| Severity | MEDIUM (CVSS 5.4) — reflected XSS без аутентификации |
| Detector | **GS020** (`gs020_xss_injection`) |
| Fix | 9 lines, 1 file — exploit re-run in sandbox confirms it no longer fires |

Full write-up → [CASE_STUDY_CYBERBRO.md](CASE_STUDY_CYBERBRO.md) ·
more findings in production OSS → [HALL_OF_FAME.md](HALL_OF_FAME.md)

---

**GSC — самообучающаяся AppSec-платформа полного цикла.**

```
detect → prove → fix → verify → heal → learn
```

## 🚀 Быстрый старт — GitHub Action

Проверьте свой репозиторий за 30 секунд. Добавьте файл `.github/workflows/gsc.yml`:

```yaml
name: GSC Audit
on:
  pull_request:
    branches: [main, master]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: poliakarmai/gsc@v1   # для воспроизводимости — pin на commit SHA
        with:
          fail_on_critical: false   # true = блокировать merge при CRITICAL
```

Откройте pull request — GSC отсканирует код, пришлёт комментарий с находками
(CRITICAL / HIGH) и поставит оценку безопасности. Ядро поставляется как
закрытый Docker-образ `ghcr.io/poliakarmai/gsc-scanner` — исходный код движка
не публикуется.

> **Воспроизводимость.** `@v1` и тег образа — плавающие ссылки: результат может
> измениться без изменения вашего workflow. Для аудита/CI фиксируйте
> `poliakarmai/gsc@<commit-sha>` и образ по digest
> (`ghcr.io/poliakarmai/gsc-scanner@sha256:<digest>`).

**Входные параметры:**

| Вход | По умолчанию | Что делает |
| --- | --- | --- |
| `path` | `.` | Что сканировать (корень репозитория) |
| `deep_scan` | `true` | Глубокий скан (Echelon 4, медленнее) |
| `fail_on_critical` | `false` | `true` — упасть при CRITICAL |
| `fail_on_score` | `0` | Упасть, если score ниже порога. `0` = выключено, диапазон 1–100 |
| `max_findings_to_comment` | `10` | Сколько строк показывать в комментарии на каждую секцию |
| `llm_api_key` | `''` | BYO-LLM ключ для ревалидации (без него — regex-only) |
| `llm_base_url` | `''` | Свой OpenAI-совместимый эндпоинт (DeepSeek/OpenRouter/Ollama) |
| `llm_model` | `''` | Имя модели для ревалидации |
| `sarif` | `false` | Дополнительно отдать SARIF для GitHub Code Scanning |
| `reachability` | `false` | Понизить находки в недостижимых файлах (import-graph) |

**Выходы:** `score` (0–100) и `grade` (A+ … F).

> Комментарий в PR считает находки **по локациям** (`file:line`), а не по
> срабатываниям детекторов: один секрет, пойманный четырьмя правилами, — это
> одна строка с перечислением правил, а не четыре. `Total` в таблице всегда
> равен сумме категорий.


LLM-ревалидация — на вашем ключе (BYO-LLM):
```yaml
- uses: poliakarmai/gsc@v1
  with:
    llm_api_key: ${{ secrets.DEEPSEEK_API_KEY }}   # DeepSeek / OpenRouter / GMI / Ollama
```
Без ключа — быстрый regex-only скан (уязвимости находит; confirmed-вердикты — с ключом).

### Локально: CLI или Docker

```bash
gsc scan . --ci --json          # JSON-находки в stdout
gsc scan . --fail-on-blocking   # exit 1 при CRITICAL/HIGH — гейт для pre-commit / CI
```

```bash
# тот же движок без установки
docker run --rm -v "$PWD:/repo:ro" ghcr.io/poliakarmai/gsc-scanner:v1 scan /repo --ci --json
```

`scan` — точка входа; `pof` (Proof-of-Fix), `verify-fix`, `report`, `--compliance …`
и остальные ≈80 подкоманд — в `gsc --help`.

## Что умеет

| Слой | Возможности |
|---|---|
| **SAST** | 68 детекторов (SAST · SCA · Secrets · IaC), YAML rule DSL, LLM-триаж с confidence scoring |
| **Доказательство** | PoC auto-generation — рабочий эксплойт для находки *(CLI `--with-poc`, MCP `get_poc`/`verify_finding`)* |
| **Исправление** | Proof-of-Fix — патч верифицируется перезапуском эксплойта в sandbox; self-healing CI (авто-PR) *(CLI, требует явного флага)* |
| **Приоритизация** | EPSS + CISA KEV + ExploitDB (не сырой CVSS), БДУ ФСТЭК |
| **Recon** | passive reconnaissance: subdomain / tech / DNS / HTTP |
| **Supply chain** | SBOM (CycloneDX / SPDX) + VEX |
| **Compliance** | маппинг находок на ГОСТ Р 56939-2024, PCI DSS 4.0, SOC2, ISO 27001, CWE, OWASP — отчёт для ФСТЭК / КИИ / аудита |
| **Интеллект** | security archaeology, predictive forecasting, NL-policy, federated self-learning |

> **Где что доступно.** Возможности движка не равны возможностям Action/MCP:
>
> | Возможность | Action | MCP | CLI / engine image |
> |---|---|---|---|
> | Скан (SAST/SCA/Secrets/IaC) | ✅ | ✅ | ✅ |
> | PoC auto-generation | — | ✅ (`get_poc`, `verify_finding`) | ✅ (`--with-poc`) |
> | Proof-of-Fix | — | ✅ (`verify_fix`) | ✅ (`pof generate`) |
> | Self-healing CI (авто-PR) | — | — | ✅ (`--create-pr`, human-approval) |
>
> В MCP **нет** деструктивных действий (auto-patch/PR) — осознанно, они остаются
> в CLI/human-лупе. `verify_finding` перезапускает PoC в sandbox, то есть по
> побочным эффектам это не «чисто read-only».

### Что уже внутри (код, а не план)

Исходники движка в публичном репо не публикуются (закрытый образ, BSL 1.1) — колонка «Где» называет модуль, а не путь в этом репозитории.

| Механика | Где | Что делает |
|---|---|---|
| **Мутационный re-attack PoF** | движок: PoC-мутатор → Proof-of-Fix | после фикса PoC перезапускается в мутированных формах (url-encode, double-encode, HTML-entities, case-swap, tab/space) — ловит «залатали симптом, а не причину». Детерминированно, без LLM |
| **Positive control + taint-recheck** | движок: PoF-sandbox + taint-recheck тесты | PoC обязан срабатывать на уязвимом варианте и молчать на исправленном |
| **OS-изоляция hostile-PoC** | движок: `_isolation_backend()` | docker/podman (`--network none`, read-only, cap-drop, non-root) на хосте, **bubblewrap внутри образа** (`--unshare-all`: mount/pid/net/user/ipc/uts, `--clearenv`, read-only системные деревья, writable только workspace, `--die-with-parent`) — докер-демон и проброс сокета не нужны. Уровень изоляции (`docker` / `podman` / `bwrap`) возвращается в каждом результате и в ответе `verify_finding` (`isolation`); без OS-изоляции движок fail-closed и отвечает `unavailable`, а не «не воспроизводится» |
| **Quick-режим без LLM** | CLI: `gsc external-scan --scan-mode quick` | regex-only: находки без LLM-вердиктов, 0 токенов |

## 🎯 Наша фишка: BYO-LLM — движок наш, судья твой

GSC — это **движок + детекторы + PoC**, а не очередная обёртка над LLM.

- **От GSC:** 68 детекторов, V3-scoring, FP-фильтр, PoC/PoF, self-learning — закрытый IP в Docker-образе.
- **От вас:** LLM-ключ (любой OpenAI-совместимый — DeepSeek/OpenRouter/GMI/локальный Ollama).

Почему это выгодно вам:
- **Ноль расходов на чужие токены** — ревалидация на вашем ключе.
- **Никакой привязки к провайдеру** — хоть бесплатный локальный Ollama.
- **Вы платите за детекторы и логику**, а не за вызовы LLM.

## 🧠 Второй столп: Self-Learning — детекторы обновляются сами, каждую ночь

Помимо BYO-LLM у GSC есть **замкнутый контур обучения без LLM** (0 токенов, детерминированный):

```
скан → авто-разметка findings по calibration-сети (13 проектов: 9 clean + 4 vuln)
     → авто-деактивация шумных паттернов (<30% TP)
     → пополнение эталонов из security-фидов
     → federated feedback (приватно: только {tenant_hash, rule_id, tp, fp} + DP-шум)
```

Детекторы учатся на **реальных находках клиентов** через federated-контур — то,
чего мейнстрим сознательно избегает (риск дрейфа). GSC обходит это консервативным
self-learning: разметка по фиксированной сети + дискретные деактивации, без
переписывания весов — скорость ежедневного апдейта без катастрофического дрейфа.

| Вендор | Как обновляет правила | Self-learning |
|---|---|---|
| Semgrep | вручную (`semgrep-rules`) | ❌ |
| GitHub CodeQL | вручную (Security Lab) | ❌ |
| Snyk Code | офлайн-ML, «never customer data» | ❌ |
| SonarQube | вручную (SonarSource) | ❌ |
| **GSC** | **ежедневно · 0-LLM · federated** | ✅ |

**Никто не замыкает петлю обучения в проде — GSC закрывает этот зазор.**
Подробно, с пруф-базой (доки вендоров + research-статьи) →
[SELF_LEARNING.md](SELF_LEARNING.md).

> **Честная рамка.** GSC не заменяет Semgrep/CodeQL: у них шире покрытие языков и
> зрелее правила. GSC закрывает то, чего они не делают — доказывает находку PoC,
> верифицирует фикс перезапуском эксплойта, учится на TP/FP. Рабочая схема — вместе:
> зрелый сканер на массовый охват + GSC на закрытие конкретных находок.

## 🔌 Интеграции

### MCP — подключи GSC к Claude Code / Cursor / Codex

Движок отдаёт 10 инструментов по MCP (read-only по отношению к репозиторию — не патчит
и не делает PR; `verify_finding` исполняет PoC в bubblewrap-песочнице внутри образа — см. границы ниже): `scan_repo`,
`scan_diff`, `list_findings`, `get_finding`, `get_poc`, `verify_finding`, `verify_findings`,
`verify_fix`, `doctor`, `list_detectors`.
Сервер уже внутри образа — `.mcp.json` в корне проекта (Claude Code):

```json
{
  "mcpServers": {
    "gsc": {
      "command": "docker",
      "args": ["run", "--rm", "-i",
               "--security-opt", "seccomp=unconfined",
               "--security-opt", "apparmor=unconfined",
               "-v", "${PWD}:/repo:ro",
               "-v", "gsc-state:/app/.hermes/state",
               "ghcr.io/poliakarmai/gsc-scanner:v1", "mcp"],
      "env": { "GSC_ALLOWED_ROOTS": "/repo" }
    }
  }
}
```

Cursor и любой другой MCP-клиент — та же форма (`command` + `args`).
По умолчанию транспорт `stdio`; всё не-протокольное идёт в stderr.

HTTP (общий сервер, токен обязателен — fail-closed):

```bash
docker run --rm -p 127.0.0.1:8001:8001 -e GSC_MCP_TOKEN=your-secret \
  ghcr.io/poliakarmai/gsc-scanner:v1 mcp --transport http --host 0.0.0.0 --port 8001
```

> ⚠️ `--host 0.0.0.0` слушает все интерфейсы контейнера: порт привязан к `127.0.0.1` намеренно.
> Нужен доступ извне — ставьте перед сервером reverse-proxy с TLS, не публикуйте `-p 8001:8001`
> в интернет: эндпоинт исполняет PoC.

> ⚠️ **На том конце — агент, и честно о границах:**
>
> - Деструктивных действий нет: ни auto-patch, ни PR — они в CLI/human-лупе.
> - `verify_finding` **исполняет PoC в этом образе** — через bubblewrap
>   (`--unshare-all`: mount/pid/net/user/ipc/uts, `--clearenv`, read-only системные
>   деревья, writable только workspace). Докер-демон не нужен, проброс `docker.sock`
>   не нужен и запрещён (это выдача PoC хостового демона, эквивалент root).
>   Для user-namespace контейнеру нужны `--security-opt seccomp=unconfined
>   --security-opt apparmor=unconfined`; без них тул честно отвечает
>   `status: "unavailable"` (PoC не запускался — это не вердикт о находке).
>   В ответе есть `isolation` (`bwrap` / `docker` / `podman`) и `exploit_success`.
> - PoC прикрепляется к находке **при скане**: сначала детерминированный шаблон
>   (curl-payload под класс уязвимости — работает и в regex-only режиме, без
>   LLM-ключа и без `confidence`), затем LLM-PoC для находок с `confidence ≥ 0.80`.
>   Шаблоны есть под XSS/SSTI, command injection, SQLi, path traversal, SSRF, IDOR,
>   deserialization, XXE, open redirect; DESTRUCTIVE-шаблоны не прикрепляются никогда.
>   Если PoC нет вообще — `verify_finding` отвечает `error_code: "UNAVAILABLE"` с
>   текстом «no PoC attached», и это тоже **не** «не воспроизводится».
> - `scan_repo` ограничен бюджетом: `GSC_SCAN_TIMEOUT` (default 300 с) на свип
>   детекторов, `GSC_MAX_FILES` (default 50 000) на инвентарь. Упёрлись в лимит —
>   в ответе `status: "partial"`, `truncated: true` и список детекторов, которые
>   не запускались. Мало находок там **не значит** «чисто»; такой скан в БД не
>   сохраняется.
> - `GSC_ALLOWED_ROOTS` ограничивает `scan_repo`/`scan_diff` смонтированными путями.
> - `scan_repo` сохраняет находки в БД (`persisted: true` в ответе), поэтому
>   `list_findings` и `get_finding` их видят сразу. `get_finding` отвечает из БД
>   (`source: "database"`), без пересканирования; ~30–60 с — только если ключа
>   в БД нет и он пересобирает скан.
> - Нужен **writable** volume на `/app/.hermes/state` — там SQLite. Каталог уже есть в
>   образе и принадлежит uid/gid 999, поэтому `-v gsc-state:/app/.hermes/state` работает
>   сразу. Ритуал `chown` нужен только для томов, созданных до v1.4.1 (там каталог от root):
>   `docker run --rm -v gsc-state:/s --user 0 <image> chown -R 999:999 /s`, либо просто
>   `docker volume rm gsc-state` и создать заново. Без этого `scan_repo` вернёт
>   `persisted: false` (скан работает, БД — нет), а `--read-only` вообще не годится.
> - Без `llm_api_key`/`DEEPSEEK_API_KEY` работают только regex-детекторы.

### Paperclip — «найми GSC как сотрудника по безопасности»

[Paperclip](https://github.com/paperclipai/paperclip) (107K★, open-source оркестратор AI-агентов)
подключает GSC через MCP Tool Gateway — любой нанятый агент (Claude Code / Codex / Hermes)
получает GSC-инструменты и роль «Security Engineer».

> 📦 Интеграция идёт через MCP-сервер образа (см. раздел MCP выше). Гайд и skill
> `gsc-security-review` поставляются с коммерческим доступом (репозиторий
> `gsc-core`, `docs/integrations/paperclip/`) — в публичном репо их нет.
- **Транспорт:** `local_stdio` (subprocess) или `mcp_remote` (HTTP)

Подключение за минуты: зарегистрируй `ToolStdioCommandTemplate`, создай gateway — и GSC сканирует репозитории твоей Paperclip-компании.

## Лицензия и доступ

**Этот репозиторий (GitHub Action, документация, маркетинг) — Apache License 2.0.** Свободно используйте Action в своих репозиториях.

Движок GSC (детекторы, PoC/PoF, калибровочная сеть, LLM-слой) поставляется отдельно как закрытый Docker-образ `ghcr.io/poliakarmai/gsc-scanner` под **Business Source License 1.1 (BSL 1.1)**:

- **Свободное использование** — включая сканирование собственных репозиториев в production — разрешено всегда.
- **Коммерческий SaaS/SAST-сервис** для третьих лиц, конкурирующий с GSC, — требует коммерческой лицензии (после NDA).
- **Change Date 2030-08-06** → движок автоматически переходит на Apache 2.0.

Для демо, пилота или приобретения — свяжитесь с автором.

**Участие и безопасность:** [CONTRIBUTING.md](CONTRIBUTING.md) (PRs welcome) ·
[SECURITY.md](SECURITY.md) — приватный канал для уязвимостей, не публичный issue.

© 2026 Алексей Поляков.
