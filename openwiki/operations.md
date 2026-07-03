# Operations

Installation, configuration, CLI reference, CI/CD integration, and deployment.

## Prerequisites

- **Python 3.10+**
- **ripgrep 13+** (binary, not pip package)

```bash
# macOS
brew install ripgrep

# Linux
sudo apt install ripgrep
# or: sudo dnf install ripgrep / sudo pacman -S ripgrep

# Verify
rg --version
```

## Installation

```bash
git clone https://github.com/poliakarmai/gsc.git
cd gsc
pip install -e .

# Verify
gsc doctor
```

This registers the `gsc` CLI command via `pyproject.toml: [project.scripts] gsc = "gsc:main"`.

## CLI Commands

All commands are defined in `/gsc.py` as `cmd_*` functions and dispatched via `argparse`.

### Scanning

```bash
gsc scan <project>                     # Full 3-echelon audit
gsc scan <project> --resume            # Continue interrupted scan
gsc scan <project> --deep              # With LLM deep analysis
gsc scan <project> --diff              # Only changed files (for PRs)
gsc scan <project> --echelon 1         # Run only echelon 1
gsc scan <project> --json              # JSON output
gsc scan <project> --sarif             # SARIF 2.1.0 for GitHub Code Scanning
gsc scan <project> --ci                # CI mode (quiet + JSON)
gsc scan <project> --compliance pci    # Filter findings by compliance standard
gsc scan <project> --reachability      # Enable reachability analysis
```

### Revalidation

```bash
gsc revalidate <project>               # Recheck findings (LLM)
gsc revalidate <project> --no-llm      # Heuristics only
gsc revalidate <project> --min-severity HIGH
```

### Triage

```bash
gsc triage <project>                   # Interactive triage (y/n/i per finding)
gsc triage <project> --group-by pattern  # Accept/reject by pattern
gsc triage <project> --bulk --auto-accept  # Automatic in CI
```

### Analysis

```bash
gsc explain <id>                       # CVSS + threat analysis
gsc fix <id>                           # AI-generated patch (via OpenRouter)
gsc issue <id> --md                    # Create ticket (Markdown)
gsc issue <id> --jira                  # Create Jira ticket
gsc issue <id> --linear                # Create Linear ticket
```

### Management

```bash
gsc init                               # Initialize .gsc/ config
gsc dashboard                          # Web dashboard on :8080
gsc doctor                             # Environment diagnostics
gsc metrics                            # Precision/recall statistics
gsc patterns list                      # List all patterns with effectiveness
gsc patterns export patterns.yaml      # Export patterns
gsc patterns import patterns.yaml      # Import patterns
gsc config show                        # Show current configuration
gsc status <project>                   # Scan progress (resume-aware)
gsc db "SELECT count(*) FROM findings" # Direct SQL query
```

## Configuration

Configuration file: `.gsc/config.yaml`

```yaml
# Example: .gsc/config.yaml
ignore_patterns:
  - patterns/*.json
```

Additional configuration via environment variables:
- `GSC_LLM_PROVIDER` — LLM provider (default: `openrouter`)
- `GSC_LLM_MODEL` — LLM model (default: `deepseek/deepseek-chat`)
- `GSC_E4_MAX_TOKENS` — Max tokens per finding (default: `800`)
- `GSC_E4_MAX_COST_USD` — Max cost per scan (default: `2.0`)
- `GSC_E4_CB_MAX` — Circuit breaker max findings (default: `20`)
- `GSC_E4_CACHE` — Enable/disable E4 cache (default: `true`)

## CI/CD Integration

### GitHub Actions

`/action.yml` provides a composite action:

```yaml
- name: Run GSC Audit
  uses: poliakarmai/gsc@main
  with:
    project: my-project
    fail_on: 'true'
```

Outputs: `total` (total findings), `critical` (critical count). Fails the pipeline if critical findings exist.

### Pre-commit Hook

Copy the provided hook:
```bash
cp pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook blocks commits only on **new** CRITICAL findings (baseline-aware — existing findings are ignored).

### SARIF Upload

```yaml
- name: Run GSC
  run: gsc scan . --diff --sarif > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: results.sarif}
```

## Kubernetes Deployment

Helm chart at `/helm/` deploys:
- **CronJob**: scheduled GSC scans (`gsc scan --ci --json --diff`)
- **Dashboard**: GSC web dashboard with SSO via oauth2-proxy
- **Persistent Volume**: shared state across jobs

```bash
helm install gsc ./helm \
  --set gsc.projects[0].name=my-project \
  --set gsc.projects[0].url=https://github.com/user/repo.git \
  --set gsc.openrouter_key=sk-...
```

See `/helm/values.yaml` for full configuration.

## LLM Provider Setup

Default: **DeepSeek via OpenRouter** (chosen for 1000× lower cost than Claude Opus).

```bash
export OPENROUTER_API_KEY=sk-or-...
export GSC_LLM_MODEL=deepseek/deepseek-chat

# Or use Ollama for local inference
export GSC_LLM_PROVIDER=ollama
```

Cost guardrails are hard-coded in `/scripts/e4_llm.py:E4_CONFIG`:
- max_tokens_per_finding: 800
- max_cost_per_scan_usd: 2.0
- circuit_breaker_max: 20 findings per scan
- cache: SHA256-based dedup with 30-day TTL

## Export Formats

| Format | Command | Destination |
|--------|---------|-------------|
| JSON | `gsc scan . --json` | stdout |
| SARIF | `gsc scan . --sarif` | stdout (→ GitHub Code Scanning) |
| HTML | `gsc dashboard` | `~/.gsc/dashboard.html` |
| Obsidian | auto during scan | `~/obsidian-vault/hermes/gsc-collector/` |
| Jira ticket | `gsc issue <id> --jira` | API → Jira |
| Linear ticket | `gsc issue <id> --linear` | API → Linear |
| PDF | via `scripts/gsc_pdf.py` | File |
| Knowledge export | `scripts/gsc_export_knowledge.py` | JSONL (OpenAI fine-tuning format) |

## DB Management

- **Location**: `~/.hermes/state/gsc_audit.db`
- **Encryption**: `scripts/db_encrypt.py` (Fernet AES-128)
- **Baseline**: `scripts/gsc_baseline.py` — mark existing findings as baseline to suppress in future scans
- **Direct queries**: `gsc db "SELECT * FROM findings WHERE severity='CRITICAL'"`

## Key Source Files

| File | Purpose |
|------|---------|
| `/gsc.py` | CLI entry point, all command handlers |
| `/scripts/gsc_doctor.py` | Environment diagnostics |
| `/scripts/gsc_metrics.py` | Precision/recall calculation |
| `/scripts/gsc_config.py` | Config management |
| `/scripts/gsc_baseline.py` | Baseline saving/loading |
| `/scripts/db_encrypt.py` | Database encryption |
| `/scripts/gsc_issue.py` | Jira/Linear ticket integration |
| `/scripts/gsc_pr_comment.py` | PR comment generation |
| `/scripts/gsc_report.py` | HTML/PDF report generation |
| `/action.yml` | GitHub Actions composite action |
| `/helm/` | Kubernetes deployment manifests |
| `/pre-commit` | Git pre-commit hook |
| `/vscode/` | VSCode extension |
