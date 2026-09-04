# 🛡️ GSC — Git Security Checker

[![GSC on GitHub Marketplace](https://img.shields.io/badge/Marketplace-GSC%20Security%20Audit-blue)](https://github.com/marketplace/actions/gsc-security-audit)

**SAST, которое доказывает эксплойт, верифицирует фикс и лечит CI само.**

GSC — самообучающаяся AppSec-платформа полного цикла:

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
      - uses: poliakarmai/gsc@v1
        with:
          fail_on_critical: false   # true = блокировать merge при CRITICAL
```

Откройте pull request — GSC отсканирует код, пришлёт комментарий с находками
(CRITICAL / HIGH) и поставит оценку безопасности. Ядро поставляется как
закрытый Docker-образ `ghcr.io/poliakarmai/gsc-scanner` — исходный код движка
не публикуется.

**Входные параметры:** `path`, `deep_scan`, `fail_on_critical`, `fail_on_score`,
`max_findings_to_comment`, `llm_api_key`, `llm_base_url`, `llm_model`, `sarif`, `reachability`.

LLM-ревалидация — на вашем ключе (BYO-LLM):
```yaml
- uses: poliakarmai/gsc@v1
  with:
    llm_api_key: ${{ secrets.DEEPSEEK_API_KEY }}   # DeepSeek / OpenRouter / GMI / Ollama
```
Без ключа — быстрый regex-only скан (уязвимости находит; confirmed-вердикты — с ключом).

## Что умеет

| Слой | Возможности |
|---|---|
| **SAST** | 53 детектора (SAST · SCA · Secrets · IaC), YAML rule DSL, LLM-триаж с confidence scoring |
| **Доказательство** | PoC auto-generation — рабочий эксплойт для каждой находки |
| **Исправление** | Proof-of-Fix — патч верифицируется перезапуском эксплойта в sandbox; self-healing CI (авто-PR) |
| **Приоритизация** | EPSS + CISA KEV + ExploitDB (не сырой CVSS), БДУ ФСТЭК |
| **Recon** | passive reconnaissance: subdomain / tech / DNS / HTTP |
| **Supply chain** | SBOM (CycloneDX / SPDX) + VEX |
| **Интеллект** | security archaeology, predictive forecasting, NL-policy, federated self-learning |

## 🎯 Наша фишка: BYO-LLM — движок наш, судья твой

GSC — это **движок + детекторы + PoC**, а не очередная обёртка над LLM.

- **От GSC:** 53 детектора, V3-scoring, FP-фильтр, PoC/PoF, self-learning — закрытый IP в Docker-образе.
- **От вас:** LLM-ключ (любой OpenAI-совместимый — DeepSeek/OpenRouter/GMI/локальный Ollama) **или** ваш AI-агент (Claude/Cursor) через MCP.

Почему это выгодно вам:
- **Ноль расходов на чужие токены** — ревалидация на вашем ключе.
- **Никакой привязки к провайдеру** — хоть бесплатный локальный Ollama.
- **Вы платите за детекторы и логику**, а не за вызовы LLM.

## 🧠 Второй столп: Self-Learning — детекторы обновляются сами, каждую ночь

Помимо BYO-LLM у GSC есть **замкнутый контур обучения без LLM** (0 токенов, детерминированный):

```
скан → авто-разметка findings по calibration-сети (16 проектов: 9 clean + 7 vuln)
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

## Реальные результаты

Найденные и исправленные уязвимости в production open-source проектах — см. [HALL_OF_FAME.md](HALL_OF_FAME.md).

Первый публичный кейс: [CASE_STUDY_CYBERBRO.md](CASE_STUDY_CYBERBRO.md).

## 🔌 Интеграции

### Paperclip — «найми GSC как сотрудника по безопасности»

[Paperclip](https://github.com/paperclipai/paperclip) (79K★, open-source оркестратор AI-агентов)
подключает GSC через MCP Tool Gateway — любой нанятый агент (Claude Code / Codex / Hermes)
получает GSC-инструменты и роль «Security Engineer».

- **5 MCP-инструментов:** `scan_repo` · `list_findings` · `verify_finding` · `get_finding` · `list_detectors`
- **Гайд + skill `gsc-security-review`** — в `docs/integrations/paperclip/` (репозиторий gsc-core)
- **Транспорт:** `local_stdio` (subprocess) или `mcp_remote` (HTTP)

Подключение за минуты: зарегистрируй `ToolStdioCommandTemplate`, создай gateway — и GSC сканирует репозитории твоей Paperclip-компании.

## Лицензия и доступ

Ядро GSC (детекторы, PoC/PoF-движок, калибровочная сеть, LLM-слой) — **проприетарное (closed-source)** и не публикуется в этом репозитории.

- **GitHub Action** — публичный канал: движок поставляется как закрытый Docker-образ, исходный код не раскрывается.
- **SaaS / On-prem** — full-функционал (PoC, PoF, self-healing, multi-tenancy) по коммерческой лицензии после NDA.

Для демо, пилота или приобретения — свяжитесь с автором.

© 2026 Алексей Поляков. All rights reserved.
