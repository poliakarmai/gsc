# PoF-корпус — baseline замер GSC (13.08.2026)

Сертифицированный корпус standalone web-приложений (13 vuln + 2 clean) для честного
замера PoF-цикла GSC. Каждое приложение: `vulnerable/` + `patched/` + ground-truth PoC + `meta.json`.

## Валидация корпуса

`python3 validate_corpus.py` → **13/13 валидны** (каждый ground-truth PoC эксплуатирует
vulnerable/ и НЕ эксплуатирует patched/).

## Baseline: detect-фаза

`python3 measure_pof.py --detect-only` (скан GSC + детект, без LLM-PoC):

| Метрика | Значение |
|---|---|
| Найдено (TP + MISLABELED) | **8/13 (61.5%)** |
| Точный TP | 5/13 |
| MISLABELED (нашёл, не тот rule) | 3/13 |
| FN (не нашёл) | 5/13 |
| **FP на clean** | **0/2** ✅ |

## Per-класс breakdown

| Класс | rule_id (ожидаемый) | Результат | Факт |
|---|---|---|---|
| SQLi ×3 | GS005 | ✅ TP ×3 | f-string SQL конкатенация детектится |
| CMDI | GS004 | ✅ TP | os.popen детектится |
| IDOR | GS007 | ✅ TP | отсутствие ownership-проверки детектится |
| SSTI | GS037 | ⚠️ MISLABELED | нашёл (GS000-LEGACY), не GS037 |
| Deserialization | GS037 | ⚠️ MISLABELED | нашёл pickle.load (GS007), не GS037 |
| SSRF | GS021 | ⚠️ MISLABELED | SSRF не сработал; GS001 нашёл hardcoded secret |
| XSS ×2 | GS020 | ❌ FN ×2 | f-string HTML-инъекция не детектится |
| Path traversal | GS037 | ❌ FN | os.path.join + send_file не детектится |
| XXE | GS037 | ❌ FN | feature_external_ges=True не детектится |
| Open redirect | GS022 | ❌ FN | redirect(next_url) не детектится |

## Приоритет улучшения детекторов (по данным)

1. **XSS (GS020)** — добавить паттерн f-string HTML-инъекции (`f"...{var}..."` без escape). 2 приложения, 0/2.
2. **Path traversal (GS037)** — паттерн `os.path.join(dir, user_input)` + `send_file`/`open`.
3. **XXE (GS037)** — паттерн `feature_external_ges = True` / `resolve_entities`.
4. **Open redirect (GS022)** — паттерн `redirect(request.args.get(...))` без валидации.
5. **Rule_id remap** — SSTI/pickle из `GS000-LEGACY`/`GS007` → `GS037` (детект есть, классификация неверна).

## PoC-generation gap (важно для PoF)

Deterministic PoC (`gsc_poc_deterministic.DETERMINISTIC_RULES`) покрывает **только**
SSTI (GS020) и command-injection (GS025). SQLi/XSS/SSRF/IDOR/path/deser/XXE/redirect
требуют LLM-PoC (`gsc_poc_generator`). Для полного PoF-цикла нужно расширить
deterministic PoC на все классы корпуса.

## Как воспроизвести

```bash
cd benchmark/pof_corpus
python3 validate_corpus.py            # сертификация (13/13)
python3 measure_pof.py --detect-only  # detect baseline
python3 measure_pof.py                # + gsc pof generate (LLM-PoC, медленно)
```
