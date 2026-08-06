# Enterprise Hybrid Agent (v0.31)

> 8 коммитов. Тесты 98→106. Сканер в инфраструктуре клиента.

## Границы

| Входит | Не входит |
|---|---|
| Agent-runner в инфраструктуре клиента | Управление репо из облака |
| Регистрация через activation key | Remote shell / доступ к коду |
| Ingest API: findings → cloud, код локально | Хранение кода в облаке |
| Локальный кэш + offline | Real-time стриминг |
| Политики из облака | LLM через облако (off by default) |
| Air-gap экспорт (JSON/SARIF) | Автообновление агента |

## Коммиты

| # | Что | Гейт |
|---|---|---|
| 1 | Schema S5 + agent_api skeleton | psql + RLS |
| 2 | Agent runner core cycle | import check |
| 3 | Registry + activation key | uuid-mismatch 403 |
| 4 | Ingest API: findings → cloud | source='agent' |
| 5 | Local cache + offline flush | unsynced logic |
| 6 | Policy sync from cloud | fallback to cache |
| 7 | Air-gap export (JSON/SARIF) | 0 network calls |
| 8 | Tests (+8 → 106/106) | 106/106 |

## Ключевые решения

- **Инверсия управления:** облако НЕ вызывает агента — агент сам сканирует и пушит
- **Activation key одноразовый**, с привязкой к agent_uuid
- **Session token с Redis TTL 24h**
- **Код не покидает периметр** — в облако только findings (без полных файлов)
