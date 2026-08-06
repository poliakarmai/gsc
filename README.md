# 🔒 GSC — Git Security Checker

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](./LICENSE)
[![Detectors](https://img.shields.io/badge/detectors-25-green)](./gsc_detectors/)
[![Tests](https://img.shields.io/badge/tests-46%2F46-brightgreen)](./tests/)
[![Calibration](https://img.shields.io/badge/calibration-17%2F17-brightgreen)](./calibration/)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)

> AI-powered SAST with self-learning, PoC auto-generation, exploit chains, and mutation tracking.
> **v1.0 — Cloud-ready: multi-tenant SaaS with billing, SSO, audit log, and Enterprise agent.**

## What is GSC

GSC scans source code for security vulnerabilities using 25 regex detectors + LLM revalidation (DeepSeek).
Unlike traditional SAST tools, GSC learns from every scan: true positives strengthen detectors, false positives
are auto-deactivated, and confirmed findings generate new patterns.

**Core capabilities:**
- **25 plugin detectors** — secrets, injection, auth, crypto, supply chain, priv esc
- **LLM revalidation** — CRITICAL/HIGH findings verified by DeepSeek (~$0.05/day)
- **PoC Auto-Generation** — curl exploits for confirmed findings
- **Exploit Chain Composer** — cross-file attack chains (SQLi → RCE, SSRF → IDOR)
- **Temporal Mutation Tracker** — detects reintroduced "fixed" vulnerabilities
- **Security Invariant Engine** — policy-as-code with AST taint tracking
- **Blocking Engine** — CRITICAL ≥ 0.90, HIGH ≥ 0.85 with auto-policy from community verdicts
- **Self-learning** — 400K+ findings database, closed-loop pattern optimization

## Quick Start

```bash
# Requirements: Python 3.10+, ripgrep (binary, not pip)
brew install ripgrep       # macOS
sudo apt install ripgrep   # Linux

git clone https://github.com/poliakarmai/gsc.git
cd gsc && pip install .
gsc doctor && gsc scan .
```

## GSC Cloud (SaaS)

GSC is also available as a fully managed multi-tenant SaaS platform:

| Feature | Description |
|---|---|
| **GitHub App** | PR gate, /gsc commands, verdicts, auto-comment |
| **Web Dashboard** | Next.js dashboard: repos, findings, chains, mutations, usage |
| **SSO (OIDC)** | Okta, Azure AD, Google Workspace (Business+) |
| **Stripe Billing** | Seat-based subscriptions (Free / Team / Business) |
| **Audit Log** | Append-only hash chain, SOC 2 ready, exportable |
| **GitHub Marketplace** | Plan sync via signed webhook |
| **DPA / GDPR** | 30-day grace deletion, data classification |

## Enterprise Agent

For organizations that require code to **never leave their perimeter:**

```bash
# Self-hosted agent in your infrastructure
docker run gsc-agent:0.31 \
  --tenant-key <ACTIVATION_KEY> \
  --repos /mnt/repos --interval 3600

# Air-gap mode (fully isolated, SARIF export)
gsc-agent --air-gap --once --repos /mnt/repos
```

Findings are sent to GSC Cloud. Your source code stays on-premises.

## VSCode Extension

Install from VSIX or build from source: [gsc-vscode](./../gsc-vscode)

- Diagnostics in Problems panel
- CodeLens: TP / FP / Fixed verdicts
- Attack Chains Webview
- SARIF import for CI results

## Architecture

```
external-scan(target, profile)
  ├── 25 regex detectors → raw findings
  ├── LLM revalidate (DeepSeek) → confirmed / likely / uncertain
  ├── PoC Generator → curl exploit
  ├── Chain Composer → cross-file attack chains
  ├── Mutation Tracker → reintroduced vulns
  ├── Invariant Engine → policy-as-code, AST taint
  └── Blocking Engine → auto-policy from verdicts
```

**Confidence V3:** ≥ 0.80 confirmed | 0.55–0.79 likely | 0.35–0.54 uncertain | < 0.35 suppressed

## Detectors

| Rule | Severity | Category |
|------|:--------:|----------|
| GS001 | CRITICAL | Hardcoded secrets (API keys, tokens, PAN/CVV) |
| GS002 | HIGH | World-readable sensitive files |
| GS003 | LOW | Debug prints in production |
| GS004 | HIGH | Dangerous subprocess (shell=True, eval) |
| GS005 | CRITICAL | SQL injection (87+ patterns) |
| GS007 | HIGH | BAC/IDOR (35 patterns) |
| GS008 | LOW | Dead code |
| GS009 | HIGH | Supply chain (npm/PyPI/Go) |
| GS010 | CRITICAL | Weak SSH config |
| GS011 | CRITICAL | JWT vulnerabilities |
| GS012 | HIGH | Mass Assignment |
| GS013 | HIGH | GraphQL security |
| GS014 | HIGH | Credential exposure |
| GS015 | INFO | Entry-point coverage |
| GS016 | CRITICAL | Linux privilege escalation |
| GS017 | CRITICAL | Weak/default passwords |
| GS018 | CRITICAL | Payment logic abuse |
| GS019 | HIGH | Auth/session weaknesses |
| GS020 | CRITICAL | XSS/HTML/SSTI injection |
| GS021 | CRITICAL | CSRF/SSRF |
| GS022 | HIGH | Open Redirect |
| GS023 | HIGH | Race Conditions (TOCTOU) |
| GS024 | CRITICAL | LLM-based SQLi (pilot) |
| GS025 | HIGH | AI-Code Provenance |
| GS028 | HIGH | Security Invariant Engine |

## Commands

```bash
# Scan
gsc scan <project>                   # full audit
gsc scan <project> --diff            # changed files only
gsc scan <project> --with-poc        # generate PoC
gsc scan <project> --with-chains     # compose attack chains
gsc scan <project> --json --sarif    # export formats

# Revalidate
gsc revalidate <project>             # LLM re-check
gsc revalidate <project> --no-llm    # heuristics only (free)

# Verdicts
gsc feedback <finding_key> --verdict tp|fp|fixed

# Metrics
gsc metrics                          # precision/recall per detector
gsc rollout report                   # production rollout status

# Management
gsc doctor                           # diagnostics
gsc api --port 8766                  # REST API + Swagger
```

## CI/CD (GitHub Actions)

```yaml
- run: pip install git+https://github.com/poliakarmai/gsc.git
- run: gsc scan . --diff --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
```

## Quality

| Suite | Tests |
|---|---|
| Core scanner | 8/8 |
| Cloud (S1–S4) | 30/30 |
| Enterprise agent | 8/8 |
| Calibration | 17/17 projects |
| **Total** | **46 + 17** |

## Roadmap

| Phase | Status |
|---|---|
| v0.11–v0.26 Production rollout (CI, feedback, blocking engine) | ✅ |
| S1 Multi-tenant (PG + RLS + API keys) | ✅ |
| S2 GitHub App (webhooks, /gsc commands, deep subsystems) | ✅ |
| S3 Dashboard + Stripe (Next.js, billing) | ✅ |
| S4 Trust & Growth (audit, SSO, DPA, SOC 2, marketplace) | ✅ |
| Enterprise Agent v0.31 | ✅ |
| VSCode Extension v0.32 | ✅ |
| Cloud 1.0 GA | 🔜 |
| First pilots | 🔜 |

## License

**Business Source License 1.1 (BSL 1.1).**

✅ Allowed: viewing, modifying, forks, internal production use (scanning your own repos, including self-hosted), non-commercial use.

⛔ Not allowed without a commercial license: offering GSC as a commercial SaaS/managed security-scanning service to third parties.

🔓 Each version converts to **Apache 2.0** after 4 years (Change Date: 2030-08-06).

Commercial licensing: armyanao@gmail.com

© 2026 Алексей Поляков