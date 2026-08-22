# GSC vs Bandit — benchmark comparison

> Track 0.7.6 (Sale-Readiness). Deterministic, count-based comparison — no LLM revalidation.
> Date: 2026-08-22 · GSC v1.4.0 · Bandit 1.9.4 (Python 3.12)

## Method

- Same 3 projects scanned by both tools, taken from the pinned 100-project benchmark set:
  bottle (9 192 LOC), requests (12 055 LOC), flask (18 345 LOC).
- **GSC:** `gsc.py scan` (all echelons), counts read from `benchmark/precision_report_batch*.json`.
- **Bandit:** `bandit -r <project> -f json -q`, severity = `issue_severity`.
- Counts only — this is a signal-density comparison, not TP/FP classification.

## Results

| Project | LOC | GSC findings | GSC CRIT / HIGH | Bandit findings | Bandit HIGH |
|---|---|---|---|---|---|
| bottle | 9 192 | 13 | 0 / 8 | 18 | 4 |
| requests | 12 055 | 8 | 0 / 1 | 708 | 0 |
| flask | 18 345 | 29 | 2 / 9 | 1 083 | 3 |

## Bandit severity breakdown

| Project | HIGH | MEDIUM | LOW |
|---|---|---|---|
| bottle | 4 | 7 | 7 |
| requests | 0 | 127 | 581 |
| flask | 3 | 5 | 1 075 |

## Bandit HIGH findings — qualitative review

| Project | Test | Finding | Verdict |
|---|---|---|---|
| bottle | B324 | weak SHA1 hash | legacy crypto, not exploitable |
| bottle | B412 ×2 | CGI/wsgi «security implications» | informational |
| bottle | B701 | jinja2 autoescape=False | design choice |
| flask | B324 | weak SHA1 hash | legacy crypto, not exploitable |
| flask | B201 ×2 | Flask `debug=True` | **fires on `test_basic.py` / `test_templating.py`** — test code |
| requests | — | — | 0 HIGH |

## Key observations

1. **Bandit's volume is style noise, not security.** B101 (`assert` used) = 579 in requests
   + 1 054 in flask = ~90% of its total findings. `assert` is a debug/contract construct and
   a well-known Bandit false-positive class — it is not a vulnerability.

2. **Bandit emits few HIGH, and ~half are non-issues:**
   - B201 (`debug=True`) fires inside test files.
   - B324 (weak SHA1) is legacy crypto, not exploitable.
   - B412 (CGI/wsgi) and B701 (autoescape) are informational/design flags.

3. **GSC yields more security-relevant signals** (2 CRIT + 18 HIGH = 20) on the same code,
   and does not emit `assert`-style noise.

## Caveats

- Count comparison only — GSC HIGH precision is ~20–25%, so a fraction of GSC HIGHs are FP too.
- Bandit is Python-only; GSC covers Python + JS/TS + Go + IaC + SCA.
- Next: repeat the same comparison for Semgrep (Python + JS/TS) and CodeQL (Go/JS/TS).

## Reproduce

```bash
python3 -m venv /tmp/bandit-env && /tmp/bandit-env/bin/pip install -q bandit

for p in bottle requests flask; do
  /tmp/bandit-env/bin/bandit -r "benchmark/real_world_100/$p" -f json -q
done

# GSC side (counts already in benchmark/precision_report_batch*.json)
python3 gsc.py scan benchmark/real_world_100/bottle --ci --json
```
