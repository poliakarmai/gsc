# GSC VSCode Extension v0.37

Self-learning AppSec platform in your IDE. See findings, exploit chains, and PoCs without leaving VSCode.

## Features

- **Diagnostics** — findings as squiggly lines in Problems panel
- **CodeLens** — PoC / TP / FP actions above affected lines
- **Findings Explorer** — tree view grouped by severity
- **Webview** — full PoC and exploit chain details
- **Verdicts** — submit TP/FP/fixed from IDE
- **Overrides** — emergency bypass with audit trail

## Setup

```bash
cd gsc-vscode && npm install && npm run compile
```

Then press F5 in VSCode, or install from .vsix:
```bash
vsce package && code --install-extension gsc-security-0.37.0.vsix
```

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `gsc.apiUrl` | `http://localhost:8766` | GSC API URL |
| `gsc.apiKey` | — | API key (x-api-key) |
| `gsc.profile` | `developer-review` | Scan profile |
| `gsc.minSeverity` | `LOW` | Minimum severity to display |
| `gsc.scanOnSave` | `false` | Auto-scan on save |

## Requirements

- GSC API running (`gsc api --port 8766`)
- VSCode 1.85+
