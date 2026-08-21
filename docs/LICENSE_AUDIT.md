# LICENSE_AUDIT.md — аудит лицензий зависимостей GSC

> Назначение: подтвердить, что дерево зависимостей GSC **не содержит copyleft/GPL**,
> что критично для dual-license модели (Apache-2.0 + Commercial — см. [LICENSE](../LICENSE)
> и [COMMERCIAL.md](../COMMERCIAL.md)). Copyleft-зависимость обязывала бы раскрывать исходники
> коммерческого tier.
> Проверено: 21.08.2026. Источник: PyPI JSON API (`license_expression` + classifiers).

## Методология

1. Источник деклараций: `pyproject.toml` (`[project].dependencies` + `[project.optional-dependencies]`),
   `requirements.txt`, `requirements-dev.txt`, `gsc-vscode/package.json`.
2. Для каждого Python-пакета запрошен `https://pypi.org/pypi/<name>/json` → поле `license_expression`
   (PEP 639) и `License ::` classifiers.
3. VSCode-зависимости проверены по манифесту (только `devDependencies`, без runtime).

## Результат

### Python — runtime (core)

| Пакет | Версия (pin) | Лицензия | Класс |
|---|---|---|---|
| PyYAML | 6.0.3 | MIT | permissive |
| requests | 2.33.0 | Apache-2.0 | permissive |

### Python — cloud/cli (optional extras)

| Пакет | Лицензия | Класс |
|---|---|---|
| fastapi | MIT | permissive |
| uvicorn | BSD-3-Clause | permissive |
| pydantic | MIT | permissive |
| httpx | BSD-3-Clause | permissive |
| PyJWT | MIT | permissive |
| stripe | MIT | permissive |
| Scrapy | BSD-3-Clause | permissive |
| fastmcp | Apache-2.0 | permissive |

### Python — dev/test

| Пакет | Лицензия | Класс |
|---|---|---|
| pytest | MIT | permissive |
| pytest-cov | MIT | permissive |
| fakeredis | BSD-3-Clause | permissive |
| Authlib | BSD-3-Clause | permissive |
| redis (redis-py) | MIT | permissive |

### VSCode-расширение (только dev, без runtime-зависимостей)

| Пакет | Лицензия |
|---|---|
| @types/mocha, @types/node, @types/vscode | MIT |
| typescript | Apache-2.0 |

## Вердикт

✅ **Нет GPL / AGPL / LGPL / SSPL / EUPL / MPL** — все зависимости permissive
(MIT / BSD / Apache-2.0).

Совместимо с dual-license: permissive-лицензии не накладывают copyleft-обязательств,
поэтому коммерческий tier может распространяться под проприетарной лицензией без
раскрытия исходников.

## Ограничения проверки

- Проверены **прямые** зависимости. Транзитивные (зависимости зависимостей) не перечислены —
  для полной картины рекомендуется `pip install pip-licenses && pip-licenses` в чистом venv
  (включает транзитивные).
- `Scrapy` (collector extra) и `fastmcp` (mcp extra) не входят в production-деплой,
  только в опциональные extras.
