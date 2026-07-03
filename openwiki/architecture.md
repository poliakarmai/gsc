# Architecture

GSC architecture is inspired by [Deepsec](https://github.com/vercel-labs/deepsec) (Vercel Labs): scan → revalidate → export, per-file state, structured verdicts. The system is designed for **self-learning** — findings confirmed as true positives become patterns for future scans.

## High-Level Pipeline

```
         scan              revalidate            export
          │                    │                    │
          ▼                    ▼                    ▼
   candidates  →   findings    TP/FP/Fixed   →  JSON / Obsidian
   (regex+15       (LLM verify)  (structured      (markdown +
   detectors)                    verdicts)        SARIF)
        │                      │
        └── resume ────────────┘
      (per-file state, idempotent,
       можно продолжить с места падения)
```

## Scan Pipeline (3 Echelons)

When `gsc scan` runs, the code in `/gsc.py:run_audit_echelons()` executes checks in order:

### E1 — Source-driven (Precise Tier)
- **Components**: grep pattern matching + precise-tier plugin detectors
- **Detectors**: GS001, GS004, GS005, GS010, GS011, GS014
- **Cost**: Low (grep-based, fast I/O)
- **Noise**: Low (high signal-to-token ratio)

### E2 — Security (Normal Tier)
- **Components**: regex patterns + normal-tier plugin detectors
- **Detectors**: GS002, GS003, GS007, GS008, GS009, GS012, GS013
- **Cost**: Medium (regex + file I/O)
- **Noise**: Medium

### E3 — Adversarial (Noisy Tier)
- **Components**: semantic matching + noisy-tier detectors
- **Detectors**: GS015 (entry-point coverage)
- **Cost**: Medium
- **Noise**: Higher (intentionally broad)

### E4 — LLM Deep Analysis (Optional, `--deep`)
- **Components**: `/scripts/e4_llm.py` — sends findings to OpenRouter for validation
- **Default model**: `deepseek/deepseek-chat` (via OpenRouter)
- **Fallback models**: `google/gemini-2.5-flash`, `qwen/qwen-3-coder`
- **Cost guardrails**: max 800 tokens/finding, max $2/scan, circuit breaker at 20 findings
- **Cache**: SHA256(snippet + pattern_id) in SQLite cache DB (`gsc_e4_cache.db`)

E4 only escalates findings that meet criteria: E3 without clear pattern, 2+ findings clustered in same file, schema mismatch, explicit `--deep` flag, or `needs_review: true` patterns.

### Post-Filters (applied to all findings)

1. **Docstring/comment filter** (`/gsc.py:_is_in_docstring_or_comment()`) — removes findings inside comments, docstrings, type annotations
2. **Inline suppression** (`/gsc.py:_is_suppressed_inline()`) — respects `# gsc:ignore`, `// gsc:ignore`, `# nosec`
3. **Framework-aware filter** (`/scripts/framework_aware.py`) — understands imports to reduce FPs (e.g., `pickle.loads()` in ML projects, `print()` in CLI tools)
4. **Reachability analysis** (`/scripts/gsc_reachability.py`, opt-in via `--reachability`) — checks if vulnerable files are actually imported

## Plugin Detector System

Defined in `/gsc_detectors/__init__.py` and `/gsc_detectors/registry.py`.

### Core Types

```python
@dataclass
class AuditContext:
    project: str
    path: Path                  # Absolute project root
    files: list[Path]           # File inventory (lazy-loaded)
    file_contents: dict         # Cache
    diff_files: list[str] | None  # For diff-mode
    diff_ranges: dict | None
    known_patterns: list[dict]  # From DB
    skipped_detectors: set[str]

class Finding(dict):
    # Backward-compatible dict with keys: rule_id, severity, title,
    # file_path, line, detail, fix_suggestion, references, noise_tier
```

Each detector module exports:
- `RULE_ID` (string like `"GS001"`)
- `ECHELON` (1, 2, or 3)
- `NOISE_TIER` (`"precise"`, `"normal"`, `"noisy"`)
- `description` (human-readable)
- `detect(ctx: AuditContext) -> list[Finding]` (the detection function)

### Registration

In `/gsc_detectors/registry.py`, each detector is wrapped in a `DetectorEntry`:

```python
DetectorEntry(rule_id=..., echelon=..., detect_fn=..., description=...)
```

`ALL_DETECTORS` is a list of `DetectorEntry` objects. The registry also provides `run_detectors()` and `get_detectors(echelon=...)`.

## Resume Scanner

`/gsc_resume.py:FileStateManager` enables interrupted scans to continue:

- **Per-file state machine**: `pending → scanning → scanned → processed → skipped`
- **Atomic file locking**: via `locked_by_run_id` (supports parallel workers)
- **File hash tracking**: MD5 of file content for change detection
- **Analysis history**: append-only records
- **Usage**: `--resume` flag on `gsc scan`

The state is stored in the same SQLite DB (`file_state` table).

## Structured Revalidator

`/gsc_revalidate.py:Revalidator` re-checks findings with structured verdicts:

1. **Heuristic pre-checks**: test files, documentation, placeholder patterns
2. **Git history check**: was the vulnerability line modified? (detects fixed findings)
3. **LLM structured analysis**: sends context to LLM for TP/FP/Fixed/Uncertain verdict
4. **Verdict storage**: `revalidation_verdict`, `revalidation_reasoning`, `revalidation_checked_at`, `revalidation_git_fixed`

About 50%+ FP reduction achieved through revalidation.

## Pattern System

Patterns are the atomic rules that drive detection.

### Sources
- **Seed patterns**: JSON files in `/patterns/` (7 languages + Bug Hunter + SQL safety + systemd)
- **Learned patterns**: Automatically created from findings confirmed as TP (≥3 confirmations)

### Structure
```json
{
  "title": "SQL injection risk: f-string in query",
  "category": "CRITICAL",
  "echelon": 2,
  "pattern_type": "regex",
  "search_pattern": "f['\"].*SELECT",
  "description": "f-string in SQL query — parameterize the query",
  "language": "python"
}
```

### Lifecycle
- **Active**: patterns with effectiveness ≥ 30%
- **Auto-deactivated**: patterns with effectiveness < 30% AND ≥ 10 evaluations
- **Effectiveness**: `true_positive_count / (true_positive_count + false_positive_count)`

## Data Storage (SQLite)

Single SQLite database at `~/.hermes/state/gsc_audit.db`:

- **findings table**: all scan results with status (open, confirmed, false_positive, baseline, fixed)
- **patterns table**: active and historical patterns with TP/FP counters
- **file_state table**: per-file scan state for resume
- **e4 cache** (separate DB at `gsc_e4_cache.db`): LLM analysis cache

WAL mode enabled for concurrent CI/CD access.

## Key Source Files

| File | Purpose |
|------|---------|
| `/gsc.py` | CLI entry, 3-echelon audit engine, post-filters, dashboard server |
| `/gsc_detectors/__init__.py` | `AuditContext`, `Finding`, `Detector` protocol |
| `/gsc_detectors/registry.py` | `ALL_DETECTORS`, `run_detectors()` |
| `/gsc_resume.py` | `FileStateManager` — per-file resume state |
| `/gsc_revalidate.py` | `Revalidator` — structured TP/FP/Fixed verdicts |
| `/scripts/e4_llm.py` | LLM deep analysis with cost guardrails |
| `/scripts/framework_aware.py` | Framework-context FP reduction |
| `/scripts/gsc_reachability.py` | Import-graph reachability analysis |
| `/patterns/` | Seed pattern JSON files (seed data) |

## Change Guidance for Agents

- **Adding a new detector**: Create `gsc_detectors/gs0XX_*.py`, add import + entry in `registry.py`, add seed patterns, add corpus test in `tests/test_corpus.py`
- **Modifying scan flow**: Edit `/gsc.py:run_audit_echelons()` — be aware of post-filter ordering (docstring → suppression → framework → reachability)
- **Changing LLM integration**: Edit `/scripts/e4_llm.py` — respect cost guardrails (max_tokens, max_cost, circuit breaker)
- **Adding export format**: Add new format function in `/gsc.py` and register in the `cmd_scan()` output section
