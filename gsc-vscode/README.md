# GSC — Git Security Checker for VS Code

<p align="center">
  <img src="media/icon.png" width="128" alt="GSC icon"/>
</p>

**Self-learning AppSec scanner. Finds vulnerabilities, proves them with PoC, auto-fixes with verified PRs — right in your IDE.**

---

## 🚀 Why GSC

Traditional scanners (Snyk, Semgrep, SonarQube) give you a list of findings. You spend hours triaging false positives.

**GSC is different:** it only shows proven vulnerabilities.

```
Snyk:    "439 findings, 71 false — triage yourself"
GSC:     "4 proven vulnerabilities, auto-PR with fix attached"
```

## ✨ Features

- **🔍 Scan** — 50 detectors: SAST + SCA + Secrets + IaC + DAST + LLM
- **💥 PoC** — Auto-generated proof-of-concept for each vulnerability
- **🔗 Exploit Chains** — Multi-step attack paths
- **🔧 Auto-Fix** — One-click fix suggestions
- **✅ Verdict** — TP/FP feedback → self-learning improves over time

## 📦 Quick Start

1. Install from VS Code Marketplace
2. Open any project
3. Click `GSC: Scan` in the sidebar or command palette
4. See only proven findings with PoC

## ⚙️ Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `gsc.apiUrl` | `http://localhost:8766` | GSC API endpoint |
| `gsc.profile` | `developer-review` | Scan profile (audit, pr-gate, etc.) |
| `gsc.scanOnSave` | `false` | Auto-scan on file save |

## 🛡️ Scan Profiles

- **developer-review** — fast, low noise (default)
- **pr-gate** — blocks merge if CRITICAL found
- **audit** — full echelon scan
- **candidate-review** — balanced for code review

## 🔗 Links

- [GitHub](https://github.com/poliakarmai/gsc)
- [Full Documentation](https://github.com/poliakarmai/gsc/blob/master/GSC_AUDIT_GUIDE.md)
- [Demo Script](https://github.com/poliakarmai/gsc/tree/master/demo)

## 📄 License

BUSL-1.1 — free for evaluation and non-production use.
