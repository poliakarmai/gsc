# GITLEAKS_AUDIT.md — аудит истории на утечку секретов

> Назначение: прогнать всю git-историю GSC на секреты (Трек 0.3) и подтвердить,
> что в репозитории нет реально утёкших ключей/токенов.
> Инструмент: `gitleaks 8.21.2`, режим полной истории (`--log-opts=--all`).
> Проверено: 21.08.2026.

## Результат

- **Отсканировано:** 550 коммитов (вся история).
- **Находок:** 44.
- **Вердикт:** ✅ **0 реальных утечек** — все находки относятся к тестовым фикстурам,
  примерам в документации, benchmark-артефактам и ложным срабатываниям gitleaks.

## Разбор 44 находок по категориям

| Категория | Кол-во | Файлы | Вердикт |
|---|---|---|---|
| Тестовые фикстуры (фейковые ключи) | 14 | `tests/test_gs041_crypto_secrets.py`, `test_gs014_credential_exposure.py`, `test_compliance_secrets.py`, `test_corpus.py`, `test_integration_final.py`, `test_nuclei_export.py` | ✅ фейк (`***`/`...`-плейсхолдеры) |
| Примеры в документации | 4 | `docs/DETECTOR_BRIEF_GS001/029/038.md`, `wiki/cwe/auth/hardcoded-credentials.md` | ✅ учебные примеры |
| Benchmark-артефакты (чужие скан-результаты) | 17 | `benchmark/real_world/youtube-dl_scan.json`, `thefuck_scan.json`, `benchmark/ghsa_benchmark.py` | ✅ секреты чужих проектов + фейковые benchmark-токены (`ghp_12...1234`) |
| Setup-скрипт калибровки | 3 | `scripts/gsc_setup_calibration.py` | ✅ `API_TOKEN="***"` уже отредактировано |
| **Ложные срабатывания gitleaks** | 4 | `graphify-out/cache/stat-index.json` | ⚠️ SHA-хеши файлов, ошибочно приняты за API-ключи |
| Build-артефакты (дубли) | 2 | `build/lib/scripts/gsc_setup_calibration.py` | ✅ копия уже удалённого `build/lib` |

### Конкретные проверенные значения (реальные, не «по памяти»)

| Правило | Значение | Оценка |
|---|---|---|
| github-pat | `ghp_12...1234` | фейк (плейсхолдер) |
| aws-access-token | `AKIA12...CDEF` | фейк (плейсхолдер) |
| generic-api-key | `API_TOKEN="***"` | уже отредактировано |
| generic-api-key | `API_KEY = "sk-123...cdef"` | фейк (плейсхолдер) |
| private-key | `-----BEGIN OPENSSH PRIVATE KEY-----` + обрывок | фейк (тест-фикстура GS014) |
| generic-api-key (graphify) | `8117f36…60` и т.п. | **SHA-хеши файлов**, FP gitleaks |

## Выводы

1. **Реальных утечек нет.** Ни одного валидного ключа AWS/Stripe/GitHub/приватного ключа
   в истории — всё либо `***`-отредактировано, либо `…`-плейсхолдеры в тестах/бенчмарках.
2. **Repo hygiene (не секреты):** в историю попадали артефакты `build/lib/`, `graphify-out/`,
   `benchmark/real_world/*.json` — это мусор, который уже удалён из рабочего дерева
   (см. Трек 0.7.8), но остаётся в истории. Не требует ротации ключей.
3. **gitleaks даёт FP** на длинных hex-строках (SHA-хеши кэша graphify) — при автоматизации
   нужно `.gitleaks.toml` с allowlist'ом тестовых путей (`tests/`, `benchmark/`, `docs/`).

## Рекомендация

Опционально добавить `.gitleaks.toml` с allowlist'ом для `tests/`, `benchmark/`, `docs/`,
чтобы CI-скан истории не шумел на заведомо фейковых фикстурах.
