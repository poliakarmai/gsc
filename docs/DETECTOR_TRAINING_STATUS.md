# Статус обучения детекторов GSC

> Рабочий журнал precision-улучшения детекторов. Дополняется после каждой сессии.
> Методология и контракт — в `DETECTOR_IMPROVEMENT_BRIEF.md`.

---

## Принцип работы (повторяется каждый раз)

1. Взять **один** детектор из очереди (не «улучшить всё»).
2. Найти реальные FP — по живой БД (`sqlite3 ~/.hermes/state/gsc_audit.db`,
   `SELECT file_path, COUNT(*) FROM findings WHERE rule_id LIKE 'GS0XX%' GROUP BY file_path ...`)
   и по исходникам.
3. Починить (path-exclusion / regex-сужение / context-analysis / downgrade).
4. Smoke-тест на синтетических TP/FP (`/tmp/gsXXX_smoke.py`), затем полный прогон:
   `python3 -m pytest -q` + `python3 tests/test_regression.py` + `python3 tests/test_compliance_secrets.py`.
5. Коммит `fix(gsc): GS0XX ...` + push — **только по явной команде пользователя**.

**Жёсткие инварианты:** `rule_id`/`finding_key` не менять; TP-кейсы не резать (TPR drop ≤ 3%);
severity-шкалу не менять; детектор целиком не отключать — только фильтры.

---

## Готово (закрыто)

| Детектор | Фиксы | Верификация | Коммит |
|---|---|---|---|
| GS001 hardcoded secret | Luhn-валидация PAN, symbolic-constant, placeholder UUID | pytest + regression | `dbe2056` |
| GS005 SQL injection | сужение `.format()`/конкатенации до реальной интерполяции | pytest + regression | `dbe2056` |
| GS029 secrets | placeholder-значения, AWS example keys, loopback DB URL | pytest + compliance | `dbe2056` |
| GS022 open redirect | INFO-urlparse без redirect-контекста, ASP.NET сужение, Django safe-валидация | smoke 6/6 | `dbe2056` |
| GS020 XSS | static innerHTML/eval/setTimeout literal → FP, reflected без taint → downgrade, JSP recall, dangerouslySetInnerHTML static | smoke 10/10 | `1e9ecc7` |
| GS002 world-readable | убраны *.conf/*.config/authorized_keys/known_hosts, credentials*/secrets* → data-файлы, id_rsa точное имя, skip vectors/dummyserver/demo | smoke 6/6 | `6820e32` |
| GS004 subprocess | static shell=True/os.popen (константа) → downgrade HIGH→MEDIUM | smoke 9/9 | `5f6cc14` |
| GS017 weak passwords | `_is_weak_value`: длинные mixed-case → не weak, KEY/mixed-case gates, path-exclusion | pytest + regression | `6691959` |
| GS002 world-readable (config) | config/data-файлы (.yaml/.yml/.json/.log) → не sensitive, сужен список суффиксов | regression + reconcile | `e50afca` |

---

## Очередь (по шуму из живой БД, CRITICAL/HIGH)

| Приоритет | Детектор | Файл | Шум (БД) | Зацепка |
|---|---|---|---|---|
| 1 | GS018 payment abuse | `gsc_core/gsc_detectors/gs018_*.py` | 266 HIGH | price/amount манипуляции → FP на легитимных вычислениях |
| 2 | GS014 credential exposure | `gsc_core/gsc_detectors/gs014_*.py` | 73 HIGH | логи/дебаг с кредами → FP |
| 3 | GS005 SQLi (верификация) | `gsc_core/gsc_detectors/gs005_*.py` | 4 258 CRITICAL | f-string/raw-concat SQLi → переснять после двухшаговых паттернов |

> Числа — снимок БД на 2026-08-17, до фиксов GS002/GS004. Перед каждой сессией
> переснимать: `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE category IN ('CRITICAL','HIGH') GROUP BY rule_id, category ORDER BY COUNT(*) DESC;"`.

---

## Заметки / уроки (копятся)

- `AuditContext.get_files()` **исключает все dotfiles** (`any(p.startswith('.') for p in f.parts)`) —
  GS002 через прямой `AuditContext` не видит `.env`; реальный CLI-скан находит (git-репо, другой
  механизм заполнения `files`). В smoke на `.env` использовать CLI-скан или не-dotfile.
- `Finding` — dict-like: `severity=` (канонично) или `category=` (backward-compat alias).
- `tests/test_regression.py` и `test_compliance_secrets.py` — standalone-скрипты, pytest их не
  собирает; запускать напрямую `python3 tests/...`.
- Секреты/токены в коммитах и заметках — не сохранять, только `[REDACTED]`.

---

## Следующая сессия

Стартовать с **GS017 (weak passwords)** — снять свежий срез FP из БД, оценить словарь и
path-exclusion. Параллельно можно дать GS014 саб-агенту по брифу `DETECTOR_IMPROVEMENT_BRIEF.md`.
