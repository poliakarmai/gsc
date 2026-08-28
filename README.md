# 🛡️ GSC — Git Security Checker

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

**Входные параметры:** `path`, `with_poc`, `with_chains`, `deep_scan`,
`fail_on_critical`, `fail_on_score`, `max_findings_to_comment`.

## Что умеет

| Слой | Возможности |
|---|---|
| **SAST** | 50 детекторов (SAST · SCA · Secrets · IaC), YAML rule DSL, LLM-триаж с confidence scoring |
| **Доказательство** | PoC auto-generation — рабочий эксплойт для каждой находки |
| **Исправление** | Proof-of-Fix — патч верифицируется перезапуском эксплойта в sandbox; self-healing CI (авто-PR) |
| **Приоритизация** | EPSS + CISA KEV + ExploitDB (не сырой CVSS), БДУ ФСТЭК |
| **Recon** | passive reconnaissance: subdomain / tech / DNS / HTTP |
| **Supply chain** | SBOM (CycloneDX / SPDX) + VEX |
| **Интеллект** | security archaeology, predictive forecasting, NL-policy, federated self-learning |

## Реальные результаты

Найденные и исправленные уязвимости в production open-source проектах — см. [HALL_OF_FAME.md](HALL_OF_FAME.md).

Первый публичный кейс: [CASE_STUDY_CYBERBRO.md](CASE_STUDY_CYBERBRO.md).

## Лицензия и доступ

Ядро GSC (детекторы, PoC/PoF-движок, калибровочная сеть, LLM-слой) — **проприетарное (closed-source)** и не публикуется в этом репозитории.

- **GitHub Action** — публичный канал: движок поставляется как закрытый Docker-образ, исходный код не раскрывается.
- **SaaS / On-prem** — full-функционал (PoC, PoF, self-healing, multi-tenancy) по коммерческой лицензии после NDA.

Для демо, пилота или приобретения — свяжитесь с автором.

© 2026 Алексей Поляков. All rights reserved.
