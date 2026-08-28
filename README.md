# 🛡️ GSC — Git Security Checker

**SAST, которое доказывает эксплойт, верифицирует фикс и лечит CI само.**

GSC — самообучающаяся AppSec-платформа полного цикла:

```
detect → prove → fix → verify → heal → learn
```

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

Этот репозиторий — публичная витрина продукта. Полный исходный код доступен по **коммерческой лицензии** после NDA. Для демо, пилота или приобретения — свяжитесь с автором.

© 2026 Алексей Поляков. All rights reserved.
