# Бриф: улучшение детекторов GSC

> Передаётся AI-агенту (Claude Code / Codex / саб-агенту). Самодостаточный: содержит контекст,
> контракт, метрику и формат ответа. **Не проси «улучшить всё» — давай по одному детектору.**
> Обновлён 23.08.2026 (recall-дыры закрыты, legacy-чистка, GS002 config-FP).

---

## 1. Что такое GSC

GSC (Git Security Checker) — self-learning AppSec-платформа, **47 детекторов (43 registry + 4 движка:
Secrets/SCA/IaC/Invariants)**, schema v33, v1.4.0, 169 модулей. Полный цикл
`detect → prove → fix → verify → heal → predict`.
Репозиторий: `~/gsc`. Детекторы: `gsc_core/gsc_detectors/gsXXX_*.py`.
SSOT чисел: `python3 gsc_meta.py`. Сверка: `python3 scripts/gsc_reconcile.py`.

**Текущая боль — precision, не recall.** Замер 3 (21.08, 100 реальных проектов): 64 831 находка,
4 302 CRITICAL, precision CRIT ~4–5% (48/90 чистых дают ложный CRITICAL), recall 8/10.
Главный CRITICAL-шум исторически — голый `eval`/`Function` в бандлерах (GS008, починен `ba4c2d0`);
теперь очередь — GS005 SQLi CRITICAL 4.2K.

## 2. Контракт детектора (что НЕЛЬЗЯ ломать)

Каждый registry-детектор — файл `gsXXX_name.py`. **Реальный контракт** (не legacy-сигнатура):

```python
from . import AuditContext, Finding

RULE_ID = "GS005"          # НЕ менять
ECHELON = 2
description = "..."

def detect(ctx: AuditContext) -> list[Finding]:
    if RULE_ID in ctx.skipped_detectors:
        return []
    findings = []
    for fp in ctx.get_source_files(extensions=(...)):   # или ctx.get_files()
        content = fp.read_text()
        ...   # regex-матчинг, фильтры
        findings.append(Finding(
            rule_id=RULE_ID, file_path=rel_path, line=..., severity="...",
            title="...", detail="...", fix_suggestion="...", noise_tier="...",
        ))
    return findings
```

**Инварианты (нарушение = откат):**
1. **`rule_id` не менять.** `finding_key = sha256(rule_id + file + snippet)[:12]` — стабилен, ломает
   существующие находки и self-learning.
2. **Ключи finding:** `file_path` / `line` / `detail` / `severity` (+ `noise_tier`). Собирать через
   `Finding(...)` или `make_finding()`, НЕ dict руками.
3. **Новый паттерн → `pattern_id` в metadata** (если детектор с per-pattern tracking), НЕ новый rule_id.
   **ВАЖНО:** добавляя новый паттерн в секцию `patterns=[...]`, ставь его **в конец секции** — иначе
   сдвинется нумерация `GS0XX-<TYPE>-<LANG>-<N>` и сломаются hardcoded pid-ссылки
   (напр. `_INTERPOLATION_REQUIRED = {"GS005-GEN-PY-008"}`). Реальный баг этой сессии.
4. **Skip/negative-паттерн обязан пересекать переносы строк** (`[\s\S]*` / `re.DOTALL`), если
   положительный паттерн использует `\s*` — иначе skip не сработает.
5. **Scoped case-sensitivity:** Python `re` не поддерживает голый `(?-i)`. Только `(?-i:...)`.

## 3. Метрика — что считаем «лучше»

- **Primary: precision** = TP/(TP+FP). Задача — убрать FP **без потери TP**.
- **Guard:** отключение/сужение паттерна допустимо только если TP-кейсы остаются (TPR drop ≤ 3%).
- **Recall (новые паттерны) — вторично.** Только после того, как precision устаканился; каждый
  новый паттерн обязан пройти clean-репозитории (не дать FP).

## 4. Три инструмента (в порядке предпочтения)

1. **Path exclusion** — `EXCLUDE_PATH_RE`/`EXCLUDE_FILE_RE`: тесты/samples/tutorials/vendor/mock
   не сканируются этим детектором. Дёшево, безопасно, снимает 30–60% FP разом.
2. **Regex-сужение** — требовать больше контекста: SQL-оператор перед `SELECT`, `%`-оператор после
   `%s` (интерполяция vs DBAPI-placeholder), слово целиком `\bkey\b` вместо подстроки `key`.
3. **Context analysis** — ±N строк вокруг матча: sanitizer (escape/htmlEscape/DOMPurify) → LOW,
   taint-source (request.args/input()) → HIGH, параметризованный запрос → skip.

## 5. Приоритетные детекторы (текущая очередь)

| Детектор | Файл | Шум (свежий срез БД) | Зацепка |
|---|---|---|---|
| GS005 SQLi | `gsc_core/gsc_detectors/gs005_sql_injection.py` | 4 258 CRITICAL | f-string (1813) + raw-concat (792) + CVE-55721 (786) — проверить на параметризованных/статичных запросах |
| GS018 payment abuse | `gsc_core/gsc_detectors/gs018_*.py` | 266 HIGH | price/amount манипуляции → FP на легитимных вычислениях |
| GS014 credential exposure | `gsc_core/gsc_detectors/gs014_*.py` | 73 HIGH | логи/дебаг с кредами → FP |

> Уже закрыто (не брать повторно): GS017 weak passwords (`6691959`), GS002 world-readable (`6820e32` +
> `e50afca`), GS029 secrets, GS022 redirect, GS020 XSS, GS001 secret, GS004 subprocess, legacy-чистка
> GS000-LEGACY (IP/admin-ID/CIDR → quality). Полная история — `docs/DETECTOR_TRAINING_STATUS.md`.

## 6. Что прочитать перед правкой

- `docs/DETECTOR_TRAINING_STATUS.md` — журнал фиксов + уроки + очередь.
- `benchmark/PRECISION_REPORT_100.md` — замер на 100 проектах (главный источник шума).
- `benchmark/FP_CLASSIFICATION.md` — классификация FP по детекторам (root-cause).
- `tests/test_regression.py` — регрессия (standalone, `python3 tests/test_regression.py`).
- `tests/test_compliance_secrets.py` — standalone compliance.
- Живой срез шума:
  `sqlite3 ~/.hermes/state/gsc_audit.db "SELECT rule_id, category, COUNT(*) FROM findings WHERE category IN ('CRITICAL','HIGH') GROUP BY rule_id, category ORDER BY COUNT(*) DESC;"`

## 7. Формат ответа (что вернуть)

Для **каждого** предложения — блок:

```
### GS-XXX: <название фильтра>
- **Тип:** path_exclusion | regex_сужение | context_analysis
- **Паттерн/код:** <конкретный regex или diff>
- **Обоснование:** почему это FP, откуда (пример файла/строки)
- **Пример FP, который убирает:** <реальная строка>
- **Влияние на TP:** какие TP-кейсы из ghsa_benchmark.py НЕ задевает
- **Предлагаемый regression-тест:** run_case(...) в tests/test_regression.py
```

Без этих 6 полей предложение не рассматривается (нельзя оценить risk/benefit).

## 8. Критерии приёмки (Definition of Done)

- [ ] Каждый фильтр подкреплён примером FP и проверкой TP (ghsa_benchmark).
- [ ] `rule_id` и `finding_key` не изменились.
- [ ] Regression-тест добавлен и зелёный (`python3 tests/test_regression.py`).
- [ ] Полный `python3 -m pytest -q` зелёный (+ `tests/test_compliance_secrets.py`).
- [ ] Re-scan целевого проекта: счётчик FP по rule_id снизился, TP не исчезли.
- [ ] `python3 scripts/gsc_reconcile.py` → ALL MATCH.

## 9. Что НЕ делать

- ❌ Не менять rule_id / finding_key / severity-шкалу.
- ❌ Не добавлять новый детектор (это отдельная задача, другой контракт).
- ❌ Не «чистить код» сверх задачи (scope discipline).
- ❌ Не отключать шумный детектор целиком — только фильтры (правило пользователя).
- ❌ Не редактировать regex-файлы через patch-tool вслепую (рвёт спецсимволы/`\s` → SyntaxError);
  для regex-правок — `write_file` или python `str.replace` (см. скилл `safe-code-editing`).

## 10. Уроки этой сессии (обязательно учесть)

- **Docstring-фильтр `gsc_cli/main.py:_line_is_comment_or_docstring`** ложно режет находки ниже
  строки, где закрывающая тройная кавычка в выражении (`''' % request.url`) принята за открытие
  docstring. При работе с «находки пропадают в CLI, но детектор их выдаёт» — проверяй этот фильтр.
- **Отладка recall/FP по трём слоям:** детектор напрямую → `check_plugin_detectors` →
  `run_audit_echelons`. Если детектор ловит, а CLI нет — пост-фильтры (docstring/inline-suppress).
- **Перезамер precision** — `python3 scripts/gsc_precision_measure.py` (13 calibration проектов,
  ~2.5 мин). Не гоняй 100-проектный benchmark без нужды — дорого.
