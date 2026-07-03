# Workflows

This page covers the key GSC workflows: the self-learning audit loop, collector pipeline, and how the system improves over time.

## Core Audit Workflow

The primary user workflow follows the **scan → triage → revalidate → fix → report** loop.

### 1. Initialize

```bash
gsc init           # Creates .gsc/config.yaml
```

### 2. Scan

```bash
gsc scan my-project                 # Full audit
gsc scan my-project --diff          # Only changed files (for PRs)
gsc scan my-project --deep          # With LLM analysis
gsc scan my-project --resume        # Continue interrupted scan
```

The scan runs 3 echelons sequentially (see [Architecture](architecture/)) and saves findings to SQLite + optionally exports to Obsidian.

### 3. Triage — Interactive or Bulk

After scanning, findings need labels:
```bash
gsc triage my-project                         # One by one
gsc triage my-project --group-by pattern       # By pattern batch
gsc triage my-project --bulk --auto-accept     # In CI
```

Each finding gets labeled: **confirmed** (TP), **false_positive** (FP), or left as **open**.

### 4. Revalidate (Deepsec-inspired)

For existing findings, revalidation produces structured verdicts:
```bash
gsc revalidate my-project                     # LLM + heuristics
gsc revalidate my-project --no-llm            # Heuristics only
gsc revalidate my-project --min-severity HIGH # Only HIGH+
```

Verdict: `true-positive`, `false-positive`, `fixed`, or `uncertain`.  
The git history check detects if a vulnerability was patched since the original finding.

### 5. Fix and Explain

```bash
gsc explain 42          # CVSS + threat analysis for finding #42
gsc fix 42              # AI-generated patch suggestion
gsc issue 42 --jira     # Create Jira ticket
gsc issue 42 --linear   # Create Linear ticket
```

### 6. Report

```bash
gsc dashboard                    # Web UI on :8080
gsc metrics                      # Precision/recall stats
gsc scan . --sarif > out.sarif   # SARIF for GitHub Code Scanning
```

## Self-Learning Loop

This is what makes GSC unique — the system gets smarter over time.

```
                    ┌─────────────────────┐
                    │  gsc scan <project>  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Findings generated  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  gsc triage          │  ← Human or AI labels
                    │  TP / FP marking     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Patterns updated    │
                    │  - TP count +1       │
                    │  - FP count +1       │
                    │  - effectiveness %   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Auto-deactivation   │
                    │  (effectiveness<30%  │
                    │   AND ≥10 eval)      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  New scan is better  │
                    │  - Bad patterns off  │
                    │  - Good patterns ↗   │
                    └─────────────────────┘
```

**Key files**: `/scripts/gsc_metrics.py` (precision calculation), `/gsc_detectors/registry.py` (pattern activation).

## Collector Pipeline

GSC has two collector systems that gather vulnerability patterns from external sources for self-learning.

### Lightweight Collector (`/gsc_collect_light.py`)

API-based collector using `requests` (no Scrapy overhead):

```bash
python3 gsc_collect_light.py nvd        # NVD CVE → patterns
python3 gsc_collect_light.py github     # GitHub code search → patterns
python3 gsc_collect_light.py hackerone  # HackerOne hacktivity → patterns
python3 gsc_collect_light.py all        # Everything
```

Sources feed into:
- GSC SQLite DB (patterns + findings tables)
- Obsidian vault (`~/obsidian-vault/hermes/gsc-collector/`)
- JSON export for downstream processing

State is tracked in `~/.hermes/state/gsc_collector_state.json` to avoid re-processing.

**Pattern extraction** (`/gsc_collect_light.py:CVE_PATTERN_MAP`): Maps CVE description regex patterns (e.g., "hardcoded password", "SQL injection") to GSC rule IDs, search patterns, and severity levels.

### Scrapy Collector (`/gsc_collector/`)

Full Scrapy spider for GitHub code search:

```bash
cd gsc_collector && scrapy crawl gsc_vuln
```

Defined in `/gsc_collector/gsc_collector/spiders/gsc_vuln_spider.py`.

**Search queries** map to GSC detector rules:
- `.env` files with secrets → GS001
- `os.system` with f-strings → GS004
- `f"SELECT"` in Python → GS005
- `jwt.decode(verify=False)` → GS011
- `**request.POST` → GS012
- `postgres://user:pass@` in code → GS014

Pipelines (`/gsc_collector/gsc_collector/pipelines.py`):
1. `GscDatabasePipeline` — inserts findings and patterns into SQLite
2. `ObsidianExportPipeline` — creates Markdown notes in Obsidian vault

## GitHub Dorks Scanner

`/gsc_github_dorks.py` searches public GitHub repositories for exposed secrets:

```bash
python3 gsc_github_dorks.py <org_or_company> [--limit 5] [--days 7]
python3 gsc_github_dorks.py --list-dorks
```

**12 dorks** covering: `.env` files, Docker configs, private keys, AWS keys, API keys, database URLs, JWT secrets, passwords, Firebase config, Slack tokens, npm `.npmrc` files, GCP service accounts.

Requires `GITHUB_TOKEN` or `gh auth` for GitHub Search API access.

## Typical Day-1 Workflow

```bash
# 1. Install and verify
brew install ripgrep
pip install -e .
gsc doctor

# 2. Initialize and scan
gsc init
gsc scan my-project --deep

# 3. Triage findings
gsc triage my-project

# 4. Check metrics
gsc metrics

# 5. Export results
gsc scan my-project --sarif > results.sarif
```

## Continuous Learning Setup

```bash
# Daily pattern collection (cron)
0 3 * * * cd ~/gsc && python3 gsc_collect_light.py all

# Daily audit of known projects
0 6 * * * cd ~/gsc && gsc scan pci-index --ci --json

# Weekly metrics report
0 8 * * 1 cd ~/gsc && python3 scripts/gsc_report.py
```

Or use the Helm CronJob for Kubernetes (see [Operations](operations/)).
