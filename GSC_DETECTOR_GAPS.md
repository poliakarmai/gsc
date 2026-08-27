# Детекторы: пропуски и статус

> Август 2026. 44 registry-детектора + 4 движка + 79 pattern_id в GS005.

## Активные (44 registry + 4 движка)

| # | Файл | Статус |
|---|------|--------|
| GS001–GS005 | base detectors | ✅ active |
| GS007–GS025 | vulnerability-specific | ✅ active |
| GS029–GS039 | cross-cutting / language-specific | ✅ active |
| YAML-* | custom YAML rules | ✅ active |
| GS005-*-*-* | 79 pattern_ids (GS005 decomposition) | ✅ active |

## Пропуски

| # | Причина | План |
|---|--------|------|
| GS006 | Зарезервирован под CI/CD pipeline security — не реализован | Отложен до фазы 3 (после precision ≥ 50%) |
| GS026 | Зарезервирован под LLM XSS detector — не реализован | Отложен до фазы 3 |
| GS027 | Зарезервирован под LLM CmdInj detector — не реализован | Отложен до фазы 3 |
| GS028 | Зарезервирован — не использован | Может быть переиспользован |

## Примечание

GS026/GS027 запланированы в дорожной карте (Фаза 3 — LLM-детекторы для XSS и Command Injection). 
Не будут реализованы пока Precision CRITICAL не достигнет ≥ 50% (gate фазы 2).
