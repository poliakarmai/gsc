# TESTING.md — GSC

Как устроены тесты, маркеры и политика skip (GSC roadmap 6.7 / 6.9).

## Маркеры (`pyproject.toml` → `[tool.pytest.ini_options]`)

| Маркер | Что это | Пример запуска |
|--------|---------|----------------|
| `unit` | быстрые, без внешних зависимостей | `pytest -m unit` |
| `integration` | требуют docker/postgres/nuclei/network | `pytest -m integration` |
| `sandbox` | PoF sandbox isolation (container runtime) | `pytest -m sandbox` |
| `cloud` | multi-tenant cloud/SaaS | `pytest -m cloud` |
| `slow` | >10s | `pytest -m "not slow"` |
| `smoke` | registry/import smoke (быстрый подмножество) | `pytest -m smoke` |

## Skip reason policy (6.7)

Тесты пропускаются (`pytest.skip`) **только** когда отсутствует внешний ресурс,
который тест реально проверяет — и причина всегда пишется в skip-сообщение:

| Условие skip | Причина (обязательная) | Тест |
|--------------|------------------------|------|
| нет docker/podman | «no container runtime — sandbox boundary N/A» | sandbox-тесты |
| нет flask в образе | web PoC требует flask в sandbox-образе | `test_sandbox_fmt.py` |
| нет nuclei | DAST не установлен | verify-fix DAST |

Правило: **никогда не skip по «временно сломано»** — если тест падает, это баг,
а не повод для skip. Skip = только отсутствующая внешняя зависимость.

## Smoke vs full

- **Smoke** (`-m smoke`) — быстрый контракт работоспособности (каждый детектор
  импортируется и возвращает `list`). Запускается в CI всегда.
- **Full** (`pytest tests/`) — всё, включая integration/sandbox (там, где есть runtime).

## Calibration (отдельно от pytest)

Калибровка детекторов (`scripts/gsc_calibration.py`) — это **не** pytest: отдельный
прогон на наборе `calibration/`, не входит в `tests/` и не в CI matrix.
