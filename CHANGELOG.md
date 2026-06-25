# GSC v0.4.0 — Adaptive Audit Release

## Core
- 277 seed patterns across 7 languages (Python, Go, TS, Rust, Java, Docker, Terraform)
- 3 audit echelons: Source-driven → Security → Adversarial
- E4 LLM deep analysis via OpenRouter API (optional, `--deep`)
- 8/8 corpus tests passing
- 88% FP reduction: language filter + framework-aware AST filter

## Triage & Learning
- Interactive triage with pattern-skip and inline explain
- Bulk triage by pattern (`--group-by pattern`)
- Auto-deactivation: patterns with <30% effectiveness disabled automatically
- Precision/recall metrics dashboard

## CI/CD
- SARIF 2.1.0 export for GitHub Code Scanning
- Diff-only scan (`--diff`) for PRs
- Smart pre-commit hook (baseline-aware, only blocks NEW critical)
- Helm chart for Kubernetes (CronJob-based)

## DX
- `gsc fix` — AI-generated patch via OpenRouter
- `gsc issue` — create Jira/Linear tickets from findings
- `gsc report` — HTML/PDF export
- HTML report with styled cards, badges, severity indicators
- `gsc config` — user settings (vault path, API keys, excludes)
- VSCode extension (read-only diagnostic markers)
- `pyproject.toml` — `pip install -e .` → `gsc scan`

## Marketplace & Ecosystem
- Pattern marketplace: export/import patterns as YAML
- 217 Python patterns @ 91.9% average effectiveness
- DB encryption (Fernet AES-128)
- Obsidian vault integration

## Project Audit Results
- bybit-ws: 388 → 46 findings after filters
- pci-index: 62 findings audited, 0 critical remaining
- Total: 358 findings in database, 8 audit runs
