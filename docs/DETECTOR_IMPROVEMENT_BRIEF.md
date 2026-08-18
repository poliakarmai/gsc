# Бриф: улучшение детекторов GSC

> Передаётся AI-агенту (Claude Code / Codex / саб-агенту). Самодостаточный: содержит контекст,
> контракт, метрику и формат ответа. **Не проси «улучшить всё» — давай по одному детектору.**

---

## 1. Что такое GSC

GSC (Git Security Checker) — self-learning AppSec-платформа, 42 детектора (38 registry + 4 движка:
Secrets/SCA/IaC/Invariants). Полный цикл `detect → prove → fix → verify → heal`.
Репозиторий: `~/gsc`. Детекторы: `gsc_core/gsc_detectors/gsXXX_*.py`.

**Текущая боль — precision, не recall.** На 10 реальных проектах: 2695 находок, но precision
CRITICAL ~8–12%. Основной шум: GS001 на extractor/конфигах, тестовые секреты, широкие регэксы.

## 2. Контракт детектора (что НЕЛЬЗЯ ломать)

Каждый registry-детектор — файл `gsXXX_name.py`:

```python
RULE_ID = "GS005"          # НЕ менять
ECHELON = 2
description = "..."
detector = RegexDetector(rule_id=RULE_ID, name="...", patterns=[...], severity="...", ...)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
```

**Инварианты (нарушение = откат):**
1. **`rule_id` не менять.** `finding_key = sha256(rule_id + file + snippet)[:12]` — стабилен, ломает
   98K существующих находок и self-learning.
2. **Ключи finding:** `file_path` / `line_number` / `detail` (+ legacy `file`/`line`/`snippet`).
   Собирать через `make_finding()` или `Finding(...)`, НЕ dict руками с `file=`/`line=`.
3. **Новый паттерн → `pattern_id` в metadata** (если детектор с per-pattern tracking), НЕ новый rule_id.
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
3. **Context analysis** — ±3 строки вокруг матча: sanitizer (escape/htmlEscape/DOMPurify) → LOW,
   taint-source (request.args/input()) → HIGH, параметризованный запрос → skip.

## 5. Приоритетные детекторы (первая волна)

| Детектор | Файл | Известная проблема |
|---|---|---|
| GS001 | `gsc_core/gsc_detectors/gs001_*.py` | extractor/конфиги — 57% всех FP |
| GS005 | `gsc_core/gsc_detectors/gs005_sql_injection.py` | f-string/format SQL — FP на параметризованных запросах |
| GS029 | `gsc_core/gsc_detectors/gs029_*.py` (или `secrets_core`) | тестовые/примерочные секреты |
| GS020 | `gsc_core/gsc_detectors/gs020_*.py` | XSS — 0% TPR на Java, слабо на DOM/React |
| GS022 | `gsc_core/gsc_detectors/gs022_open_redirect.py` | ASP.NET `Redirect(Request)` vs Django `redirect(request.path)` |

## 6. Что прочитать перед правкой

- `benchmark/FP_CLASSIFICATION.md` — классификация FP по детекторам (root-cause).
- `benchmark/PRECISION_REPORT.md` — замер precision на 10 проектах.
- `benchmark/ghsa_benchmark.py` — 38 пар vulnerable→fixed (TP/FP ground truth).
- `tests/test_regression.py` — регрессия (standalone `run_case()`).
- `tests/test_corpus.py` — базовые кейсы.

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
- [ ] Полный `python3 -m pytest -q` зелёный.
- [ ] Re-scan целевого проекта: счётчик FP по rule_id снизился, TP не исчезли.

## 9. Что НЕ делать

- ❌ Не менять rule_id / finding_key / severity-шкалу.
- ❌ Не добавлять новый детектор (это отдельная задача, другой контракт).
- ❌ Не «чистить код» сверх задачи (scope discipline).
- ❌ Не отключать шумный детектор целиком — только фильтры (правило пользователя).
