<div align="center">

# 🛡️ GSC — Git Security Checker

<!-- GSC-META-START -->
**Version:** v1.4.0 · **Detectors:** 50 · **Modules:** 213 · **Schema:** v33
<!-- GSC-META-END -->

### Find it. Prove it. Fix it. Verify it.

GSC is a self-learning AppSec platform that doesn't stop at detection — it
**proves** vulnerabilities with generated exploits, **fixes** them with verified
patches, and **heals** your codebase with automated pull requests.

[![Tests](https://img.shields.io/badge/tests-pytest-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

[Getting Started](#-getting-started) · [Capabilities](#-capabilities) ·
[GitHub Action](#-github-action) · [Documentation](docs/README.md)

</div>

---

## Why GSC?

Most static-analysis tools show you a snapshot of *right now* — a list of
findings you then triage, verify and fix by hand. GSC closes the loop:

**detect → prove → fix → verify → heal → learn**

- **Prove** — generates a working exploit so a finding is evidence, not a guess.
- **Fix** — produces a minimal patch instead of another ticket.
- **Verify** — re-runs the exploit against the patch in a sandbox; only a fix
  that defeats its own exploit counts as verified.
- **Heal** — opens a pull request with that verified fix.
- **Learn** — tunes itself from your TP/FP feedback to cut false positives over time.

GSC is **Vulnerability Management**, not just a scanner: it ranks findings by
exploitability (EPSS + CISA KEV + ExploitDB, not raw CVSS), suppresses false
positives deterministically (CSP/CDN-aware filters), and cross-references the
Russian FSTEC BDU — closing the loop most scanners leave open.

---

## 🚀 Getting Started

```bash
git clone https://github.com/poliakarmai/gsc.git && cd gsc
pip install -e .
```

```bash
# Scan a repository
gsc external-scan https://github.com/user/repo --profile audit

# CI gate: scan a PR diff, block merge on new CRITICAL/HIGH
gsc external-scan ./repo --profile pr-gate \
    --mode diff --base main --head HEAD --fail-on-blocking

# Scan + generate verified fixes
gsc external-scan ./repo --profile audit --with-poc --with-chains
```

Profiles: `developer-review` · `pr-gate` · `audit` · `candidate-review`

---

## ✨ Capabilities

### Detection
- **SAST** — 50 detectors across Python, JS/TS, Go, Java, Rust and more, backed
  by LLM revalidation for confidence scoring.
- **SCA** — dependency vulnerabilities via OSV.dev, with precise lock-file
  resolution (`package-lock.json`, `yarn.lock`, `go.sum`).
- **Secrets** — fingerprinting with cross-repo correlation and rotation
  detection (stores hashes only, never values).
- **IaC** — Terraform, Kubernetes and Dockerfile misconfigurations.
- **Supply chain** — SBOM (CycloneDX / SPDX), VEX, and signature verification.

### Verification & Remediation
- **Proof-of-Fix** — generate an exploit, patch the code, re-run the exploit in
  an isolated sandbox. A fix that defeats its own exploit is the definition of
  "verified".
- **Self-Healing CI** — automatically open pull requests with verified fixes.
- **DAST validation** — export findings as nuclei templates and validate them
  against staging.

### Intelligence
- **Security Archaeology** — who introduced a vulnerability, when, and how long
  it lived before it was found.
- **Predictive Forecasting** — risk heatmaps of where the *next* vulnerability
  is likely to appear.
- **NL Policy** — write security rules in plain language, compiled to
  deterministic patterns.
- **Exploit chains** — compose individual findings into real attack paths.
- **Threat intel** — export findings as STIX 2.1 / TAXII 2.1 (MISP, OpenCTI).

### Integrations
- **GitHub** — Action, PR comments, checks, SARIF, `/gsc` slash commands.
- **GitLab** — post scan results as merge-request notes (self-hosted friendly).
- **VSCode** — inline diagnostics and CodeLens.
- **MCP server** — let your AI agent scan and fix code inside its own context.

---

## 🏗️ Architecture

Three packages over a SQLite store:

- `gsc_core/` — detection engine
- `gsc_cli/` — CLI and scanners
- `gsc_cloud/` — SaaS API (multi-tenant, SSO, workers)

Scan modes: `quick` (CI, regex-only) · `standard` (daily, LLM) · `deep` (full
audit with exploit chains).

---

## 🚀 GitHub Action

```yaml
- uses: poliakarmai/gsc@master
  with:
    deep_scan: true
    with_poc: true
```

Scans every PR and push, posts findings as a PR comment, shows a security score
badge, and can block merge on CRITICAL findings. See
[`.github/workflows/gsc-audit-template.yml`](.github/workflows/gsc-audit-template.yml).

---

## 📚 Documentation

Install, detectors, architecture, enterprise and roadmap — see the
[documentation index](docs/README.md).

---

## 📄 License

Dual-licensed: [Apache License 2.0](LICENSE) for open use, plus a
[Commercial License](COMMERCIAL.md) for operating a competing hosted/managed
SAST service. See [COMMERCIAL.md](COMMERCIAL.md).

---

<div align="center">

**GSC doesn't just find vulnerabilities. It proves them, fixes them, and learns from them.**

</div>
