# GSC Compliance Mapping

> Маппинг паттернов GSC на стандарты: PCI DSS 4.0, SOC2, ISO 27001

## Coverage Summary

| Standard | Mapped Patterns | Coverage |
|----------|----------------|----------|
| PCI DSS 4.0 | 32 | Requirements 3,4,6,7,8,10,11 |
| SOC2 | 28 | CC6.1-CC6.8, CC7.1-CC7.5 |
| ISO 27001 | 35 | A.8-A.18 |

## PCI DSS 4.0

| Requirement | GSC Pattern | Category |
|------------|------------|----------|
| **Req 3** — Protect stored cardholder data | Hardcoded encryption key, Hardcoded secret, Hardcoded API key | CRITICAL |
| **Req 4** — Encrypt transmission | Insecure TLS, crypto/md5, crypto/sha1, math/rand for crypto | CRITICAL |
| **Req 6** — Develop securely | SQL injection, eval(), pickle.load(), Bare except | CRITICAL/HIGH |
| **Req 6.5** — Address common vulnerabilities | XSS (innerHTML), Command injection, Path traversal | CRITICAL |
| **Req 7** — Restrict access | World-readable files (.env, .key, .pem), chmod: 644 | HIGH |
| **Req 8** — Identify/authenticate | Hardcoded password, Token in /proc/environ | HIGH |
| **Req 10** — Log and monitor | print() instead of logging, console.log in production | MEDIUM |
| **Req 11** — Test regularly | — (GSC itself is the testing tool) | — |

## SOC2

| Trust Service Criteria | GSC Pattern | Category |
|-----------------------|------------|----------|
| **CC6.1** — Logical access | World-readable files, chmod issues | HIGH |
| **CC6.3** — Security incident response | Bare except (swallowed exceptions hide incidents) | HIGH |
| **CC6.6** — External threats | SQL injection, XSS, Command injection | CRITICAL |
| **CC6.7** — Data transmission | Insecure TLS, crypto weaknesses | CRITICAL |
| **CC6.8** — Malicious software | eval(), pickle.load(), dangerous functions | HIGH |
| **CC7.1** — Change detection | — (GSC itself detects changes) | — |
| **CC7.2** — System monitoring | print() vs logging, missing HEALTHCHECK | MEDIUM |
| **CC7.3** — Incident reporting | Swallowed exceptions, silent failures | HIGH |
| **CC7.5** — Recovery testing | Race conditions (TOCTOU), resource leaks | HIGH |

## ISO 27001 (Annex A)

| Control | GSC Pattern | Category |
|---------|------------|----------|
| **A.8** — Asset management | World-readable sensitive files | HIGH |
| **A.9** — Access control | Hardcoded credentials, token leaks | CRITICAL |
| **A.10** — Cryptography | Weak hash (MD5/SHA1), insecure random, insecure TLS | CRITICAL |
| **A.12** — Operations security | Bare except, resource leaks, missing logging | MEDIUM |
| **A.14** — System acquisition | SQL injection, XSS, supply chain (typosquatting) | CRITICAL |
| **A.16** — Incident management | Swallowed exceptions, missing error boundaries | HIGH |
| **A.17** — Business continuity | Race conditions, state corruption | HIGH |
| **A.18** — Compliance | Hardcoded secrets in code (GDPR/PCI impact) | CRITICAL |

## How to Use

```bash
# Show compliance status for a project
gsc scan my-project --compliance pci-dss     # PCI DSS report
gsc scan my-project --compliance soc2         # SOC2 report
gsc scan my-project --compliance iso27001     # ISO 27001 report

# All standards at once
gsc scan my-project --compliance all
```

## Evidence Collection for Auditors

GSC findings serve as audit evidence:
- `.gsc/baseline.json` — timestamped snapshot of known issues
- `gsc report --format pdf` — PDF for auditor submission
- SQLite DB — queryable history of all findings with timestamps
- `gsc metrics` — precision/recall stats prove tool effectiveness

Each finding record includes:
- `created_at` — when first detected
- `reviewed_at` — when triaged
- `status` — confirmed/false_positive/baseline
- `file_path:line_number` — precise location
- CVSS score (for E4-analyzed findings)
