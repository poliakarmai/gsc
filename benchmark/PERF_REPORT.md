# GSC Performance Benchmarks

Synthetic Python repos (clean functions + sprinkled vulns: hardcoded secret +
SQL string concat). Baseline = static scan only (`gsc scan --ci --json`, no
`--deep` / LLM), so the numbers reflect the deterministic engine cost.

| LOC | Time (s) | Peak RSS (MB) | Findings |
|---|---|---|---|
| 13,335 | 7.51 | 38.2 | 43 |
| 133,335 | 38.1 | 47.8 | 403 |
| 1,333,320 | 335.82 | 139.0 | 3985 |

## Методика

- `python3 benchmark/benchmark_perf.py --sizes 10k,100k,1m`
- Синтетические `.py` модули по ~2000 строк, 1 уязвимая функция на ~500.
- Замер: wall-clock (`time.perf_counter`) + peak RSS (`resource.RUSAGE_CHILDREN`).
- Хост: Linux 6.8, Python 3.12, ripgrep.

## Выводы

- Пропускная способность ~4K LOC/s.
- Сублинейный скейлинг: 10× строк → ~8.8× времени (нагрев ~7s на запуск).
- <150 MB peak RSS на 1.33M LOC — лёгкий для CI-агентов.
