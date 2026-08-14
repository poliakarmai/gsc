<div align="center">

# 🛡️ GSC — Git Security Checker

### Self-learning SAST that sees the **past, present, and future** of every vulnerability

Not just another scanner. GSC **proves** vulnerabilities with generated exploits,
**fixes** them with verified patches, and **heals** your codebase with automatic PRs.

[![Tests](https://img.shields.io/badge/tests-pytest-brightgreen)]()
[![Detectors](https://img.shields.io/badge/detectors-41-blue)]()
[![Version](https://img.shields.io/badge/version-v1.3.0-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commercial-blue)](LICENSE)
[![GSC Score](https://img.shields.io/badge/GSC-84%2F100-green?style=flat&logo=shield)]()
[![Hall of Fame](https://img.shields.io/badge/hall%20of%20fame-5%20finds-gold)](HALL_OF_FAME.md)

[Quick Start](#-quick-start) · [Features](#-what-makes-gsc-unique) ·
[GitHub Action](#-github-action) · [Architecture](#-architecture) · [Roadmap](#-roadmap)

</div>

---

## 🎯 Why GSC?

Every SAST tool shows you a **snapshot of "right now"** — a list of findings you
have to triage, verify, and fix manually.

**GSC is different.** It closes the entire security loop:

**detect → prove → fix → verify → heal → predict → learn**

| Stage | What GSC does | Who else does this? |
|---|---|---|
| **Detect** | 41 detectors + LLM revalidation | Semgrep, Snyk, CodeQL, Sonar |
| **Prove** | Auto-generates a working exploit (PoC) | 🟡 *partial* — PT Application Inspector (exploit confirmation), Checkmarx (exploitability) |
| **Fix** | Auto-generates a minimal patch via LLM | 🟡 Snyk DeepCode Fix, Sonar AI CodeFix, GitHub Copilot Autofix |
| **Verify** | Re-runs PoC in sandbox — exploit must *fail* | 🟢 *rare* — few close the full PoC→patch→re-verify loop (closest: PT Application Inspector) |
| **Heal** | Opens a PR with the verified fix | 🟡 Snyk/Semgrep/Mend auto-PR (without PoF verification) |
| **Predict** | Forecasts where the *next* vulnerability appears | 🟢 *no known equivalent* |
| **Learn** | Self-tunes: auto-deactivates noisy patterns | 🟢 *rare* — self-learning feedback loop |

> **Most scanners see a slice of "now." GSC's differentiator is the closed loop:**
> **a verified fix, not just another alert — detect → prove → fix → verify → heal.**

---

## ✨ What Makes GSC Unique

### 🥇 Proof-of-Fix — verified auto-remediation
GSC doesn't just tell you there's a bug. It:
1. Generates a **working exploit** (PoC) and runs it → proves the code is vulnerable
2. Generates a **minimal patch** via LLM
3. Applies the patch in an **isolated sandbox**
4. **Re-runs the exploit** → if the exploit now *fails*, the fix is **verified** ✅
5. Optionally **validates on staging** via nuclei DAST scan (v0.28)

```bash
gsc pof generate abc123 --report scan.json --project-root ./repo
```
```
Finding GS005 (SQL Injection) — app.py:42
  PoC before:  SQLi successful: admin@admin.com   (VULNERABLE)
  Patch:       query = "SELECT ... WHERE id=?" ; cursor.execute(query, (uid,))
  PoC after:   ERROR: no results                  (SAFE)
  DAST verify: nuclei staging scan → no findings ✅
  ✅ VERIFIED (sandbox + DAST)
```

> **Verification strength** (due-diligence, честный контракт): «verified» означает полный
> before/after exploit evidence. OS-изоляция PoC требует container runtime (Docker/Podman);
> без него GSC деградирует в rlimit (CPU/mem limits без filesystem/network namespace) и
> помечает результат **NOT verified** (fail-closed) — не «verified». PoF-пайплайн
> **Python-first** (JS/TS — roadmap). Для **hostile/repository code** обязателен
> container/VM backend — см. threat model в `docs/DUE_DILIGENCE_v2.md`.

### 🥈 Self-Healing CI — automatic remediation PRs
Wire GSC into CI. On every `CRITICAL`/`HIGH` finding, GSC runs Proof-of-Fix
and — if the patch is verified — **opens a pull request with the fix**.

```bash
gsc pof batch scan.json --create-pr --max-fixes 3
```
→ Opens PR #142: `[GSC Auto-Fix] 2 verified fixes`

### 🥉 Security Archaeology — vulnerability time-travel
Trace the **full lifespan** of any vulnerability: who introduced it, when,
who fixed it, and how long it lived.

```bash
gsc archaeology trace abc123 --repo ./project
```
```
GS003 SQLi in auth.py:42
  Introduced by:  commit abc123 (alice) on 2026-06-15
  Fixed by:       commit def456 (bob)   on 2026-08-01
  Lived:          47 days
  Module auth — average lifespan: 23.4 days
```

### 🔮 Predictive Forecasting — risk heatmaps
GSC scores every file by **likelihood of future vulnerabilities** using past
density, code churn, author count, file size, and module clustering.

```bash
gsc forecast heatmap --repo ./project
```
```
 Score  Level      C  H  Churn  File
    55  critical   3  2    42   🔴 payments/checkout.py
    38  high       1  4    18   🟠 auth/login.py
    22  medium     0  2    12   🟡 api/handler.go
     8  low        0  0     2   🟢 utils/helpers.py
```

### 🗣️ NL Policy — security rules in plain language
Write a policy in English (or Russian). GSC compiles it to a deterministic
regex rule and enforces it across the repo.

```bash
gsc policy add "secrets must never appear in log statements"
→ Policy nlp-abc12345 (CRITICAL) compiled
  Pattern: (?i)(?:log\.(?:info|error|debug|warn)\(.*(?:password|secret|token|key).*)
```

### 🔗 Exploit Chain Composer
GSC composes individual findings into **real attack chains**, showing how a
low-severity leak chains into a critical breach (e.g., Info Leak → IDOR → SQLi → RCE).

### 🔐 Cross-Repo Secret Correlation (v0.27)
Scans multiple repos, fingerprints secrets (stores **hashes only, never values**),
correlates the same secret across codebases, and detects **rotation**.

### 🧠 Self-Learning Engine
- Nightly LLM revalidation of findings (DeepSeek)
- Developer feedback loop: `gsc feedback <key> --verdict tp|fp`
- **Auto-deactivation** of patterns with < 30% TP rate at ≥ 10 verdicts
- Blocking Engine only blocks with detectors of **proven accuracy**

### 🔬 DAST Validation (v0.28)
SAST findings exported as nuclei YAML templates. Validate on staging:
```bash
gsc export-nuclei scan.json -o templates/
gsc scan-dast https://staging.example.com --severity critical
```

### 🤖 MCP Server — your AI agent becomes a security scanner
GSC speaks **Model Context Protocol** — Claude Code, Cursor, Cline, Windsurf and
Copilot can run scans, read findings and verify exploits **inside their own
context**, then fix the code in the same session:

```json
{ "mcpServers": { "gsc": {
    "command": "python3", "args": ["gsc_mcp_server.py"], "cwd": "/path/to/gsc"
} } }
```

```text
User: scan ~/my-project and fix CRITICALs
Agent: scan_repo() → 3 CRITICAL → verify_finding() → exploit confirmed
       → patches the code → re-scan → scan-diff shows "fixed: 1"
```

Read-only tools (`scan_repo`, `list_findings`, `verify_finding`); PoCs run in an
isolated sandbox. Full guide: **[docs/MCP_SERVER.md](docs/MCP_SERVER.md)**.

---

## 🏗️ Architecture

```
GSC SAST+DAST Hybrid Platform
├── 41 detectors (37 registry + 4 engines: Secrets/SCA/IaC/Invariants)
├── LLM revalidator (DeepSeek) — confidence scoring
├── PoC Auto-Generator — working exploits (Python/curl)
├── Proof-of-Fix — sandbox + staging verification
├── Self-Healing CI — auto-PR with verified patches
├── Security Archaeology — vulnerability lifespan tracing
├── Predictive Forecasting — risk heatmaps
├── NL Policy — human-language security rules
├── Exploit Chain Composer — cross-file attack paths
├── Cross-Repo Secret Correlation — fingerprint + rotation
├── Blocking Engine — auto-policy with community verdicts
├── GitHub Adapter — PR comments, checks, SARIF, /gsc commands
├── Nuclei Integration — DAST export/import/validate (v0.28)
└── SQLite DB — schema 31, WAL, 403K fingerprints
```

**Scan modes:** `quick` (CI, ~5s, regex-only) · `standard` (daily, LLM) · `deep` (full audit with chains)

---

## ⚡ Quick Start

```bash
# Full scan of a repository
gsc external-scan https://github.com/user/repo --profile audit

# PR diff scan (CI gate)
gsc external-scan ./repo --profile pr-gate \
    --mode diff --base main --head HEAD --fail-on-blocking

# Scan + auto-generate verified fixes
gsc external-scan ./repo --profile audit --with-poc --with-chains

# Predict risk hotspots
gsc forecast heatmap --repo ./repo

# Trace a vulnerability's history
gsc archaeology trace <finding_key> --repo ./repo

# Export to nuclei for DAST validation
gsc export-nuclei scan.json -o nuclei-templates/
nuclei -t nuclei-templates/ -u https://staging.example.com
```

**Profiles:** `developer-review` · `pr-gate` · `audit` · `candidate-review`

---

## 📊 Comparison

| Capability | GSC | Semgrep | Snyk | CodeQL | Sn1per |
|---|:---:|:---:|:---:|:---:|:---:|
| SAST detection | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Auto PoC generation** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Auto verified fix** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Self-healing PRs** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Self-learning / auto-tune** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Vulnerability archaeology** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Predictive forecasting** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Exploit chain composition** | ✅ | ❌ | ❌ | ❌ | ❌ |
| NL security policies | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Cross-repo secret correlation | ✅ | ❌ | ⚠️ | ❌ | ❌ |
| DAST validation | ✅ | ❌ | ❌ | ❌ | ✅ |
| PR integration | ✅ | ✅ | ✅ | ✅ | ❌ |

---

## 🧪 Quality

- **Test suite** — `pip install -e '.[test]' && pytest` (corpus + nuclei + schema integrity)
- **17/17 calibration projects** (11 clean + 6 vulnerable)
- Hard chain assertion with retry (2-of-3, temperature 0)
- Production rollout Phase 0–5 complete (blocking-standard)
- Schema 25, WAL, auto-backup migrations

---

## 🗺️ Roadmap

| Phase | Status |
|---|---|
| Core pipeline v0.11–v0.16 | ✅ |
| Unique features v0.17–v0.21 | ✅ |
| Production rollout Phase 0–5 | ✅ |
| Exclusive features v0.27 (PoF, Archaeology, Forecast…) | ✅ |
| SAST+DAST hybrid v0.28 (nuclei integration) | ✅ |
| VSCode extension / Marketplace | 🔜 |
| Enterprise (Helm, SSO) | 📋 |

---

## 📄 License

**Dual-licensed:** [Apache License 2.0](LICENSE) for open use + [Commercial License](COMMERCIAL.md)
for operating a competing hosted/managed SAST service. See [COMMERCIAL.md](COMMERCIAL.md) for details.

---

## 🚀 GitHub Action

One line to add GSC to any repo:

```yaml
- uses: poliakarmai/gsc@master
  with:
    deep_scan: true
    with_poc: true
    with_chains: true
```

The action will:
- 🔍 Scan your code on every PR and push
- 💬 Post findings as a PR comment (upserts on new commits)
- 📊 Show a security score badge on your README
- 🚫 Optionally block merge on CRITICAL findings

**Template:** Copy [`.github/workflows/gsc-audit-template.yml`](.github/workflows/gsc-audit-template.yml) to your repo.

<div align="center">

**GSC doesn't just find vulnerabilities. It proves them, fixes them, and learns from them.**

</div>
