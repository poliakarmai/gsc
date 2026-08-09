# 🏆 GSC Hall of Fame — Real Vulnerabilities Found

> These are real vulnerabilities discovered by GSC in production open-source projects.
> Each finding includes the CWE, project stars, fix PR, and GSC detector that caught it.

| # | Project | ⭐ | Vulnerability | CWE | Detector | PR |
|---|---------|-----|---------------|-----|----------|----|
| 1 | **aio-libs/aiohttp-security** | 147 | Session Fixation in demo login handlers — `remember()` without `forget()` allows attacker to hijack authenticated session | CWE-384 | GS019 (session handling) | [#1005](https://github.com/aio-libs/aiohttp-security/pull/1005) |
| 2 | **mathiasertl/django-ca** | 158 | SSRF in ACME HTTP-01 validation — `validate_http_01()` makes HTTP request to attacker-controlled domain without checking for internal IPs | CWE-918 | GS025 (CVE/SSRF patterns) | [#202](https://github.com/mathiasertl/django-ca/pull/202) |
| 3 | **deep-learning-indaba/Baobab** | 60 | Hardcoded API key `sk_Lex...` in `api/app/invoice/generator.py` — visible to 533 contributors | CWE-798 | GS029 (Secrets) | [#1401](https://github.com/deep-learning-indaba/Baobab/pull/1401) |

## How It Works

GSC scans open-source projects daily using its precision-hunt profile:
- **7 high-noise detectors disabled** (GS000, GS001, GS003, GS008, GS015, GS023, GS029)
- **High-precision rules only:** GS005 (SQLi with taint tracking), GS020 (XSS with sanitizer context), GS025 (CVE patterns), YAML-based detectors (SSTI, reverse shell)
- **Manual verification** before PR submission — every finding is reviewed by a human
- **Fix-ready PRs** with minimal, targeted code changes

## Submit a Finding

Found a vulnerability with GSC? [Open an issue](https://github.com/poliakarmai/gsc/issues/new?title=Hall+of+Fame:+[project]+[CWE]) to get it added!

---
*GSC — Git Security Checker. Not just another scanner.*
