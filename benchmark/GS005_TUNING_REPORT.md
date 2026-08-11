# GS005 Tuning Report

Baseline: TPR=0.429, FPR=0.062
Final:    TPR=0.429, FPR=0.000

Target FPR ≤ 0.3: ✅
FPR improvement: +0.062 (+100%)
TPR change: +0.000

Hold-out FPR: 0.000
Отключено: 1 (limit: 10)
Защищено (полезных): 2

## Отключённые паттерны
| pattern_id | FPR | TPR | FP | TP | Score |
|---|---|---|---|---|---|
| GS005-ORM-PY-008 | 0.062 | 0.071 | 1 | 1 | +0.009 |