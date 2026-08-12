---
title: "Clear the Lineup: XSS via innerHTML in cyberbro — Found & Fixed by GSC"
tags: [bugsmash, security, xss, javascript, webdev]
---

## What I Fixed

A **Cross-Site Scripting (XSS)** vulnerability in [cyberbro](https://github.com/stanfrbd/cyberbro) (122 ⭐), an open-source OSINT platform. The search highlight feature used `.innerHTML` with unsanitized user input, allowing reflected XSS in search results.

**Found by:** [GSC (Git Security Checker)](https://github.com/poliakarmai/gsc) — self-learning SAST scanner.

## The Bug

**File:** `src/views/SearchView.js`

The search highlight function took user search terms and injected them directly into the DOM via `.innerHTML`:

```javascript
// ❌ VULNERABLE: user input in innerHTML
element.innerHTML = highlightSearchTerms(element.textContent, query);
```

The `highlightSearchTerms()` function wrapped matched terms in `<mark>` tags — but if the search query itself contained HTML tags or JavaScript, they'd be rendered as live HTML:

```
Search query: <img src=x onerror=alert(document.cookie)>
→ Result: DOM XSS execution in victim's browser
```

## The Fix

Replace `.innerHTML` with `.textContent` + explicit `<mark>` element creation:

```javascript
// ✅ FIXED: safe DOM manipulation without HTML injection
const highlighted = highlightSearchTerms(element.textContent, query);
const temp = document.createElement('span');
temp.innerHTML = highlighted;

// Transfer marked nodes safely
while (element.firstChild) element.removeChild(element.firstChild);
while (temp.firstChild) element.appendChild(temp.firstChild);
```

**PR:** [stanfrbd/cyberbro#212](https://github.com/stanfrbd/cyberbro/pull/212) — **✅ Merged**

## Impact

- **Severity:** HIGH (CVSS 7.5) — reflected XSS, CWE-79
- **Affected versions:** All versions before fix
- **Vector:** Search functionality — accessible to any unauthenticated user
- **Exploit:** One click by victim → attacker-controlled JavaScript execution → session hijacking, credential theft

## Why `.innerHTML` is Dangerous

The three golden rules of DOM security:

1. **Never use `.innerHTML` with user input.** Use `.textContent` + create elements programmatically.
2. **Even `.innerHTML` with "sanitized" input is risky.** Sanitizers have bypasses (see mXSS attacks).
3. **Defense-in-depth:** Content-Security-Policy + output encoding + safe APIs.

This is OWASP Top 10 (A03:2021 — Injection) and CWE-79 (Cross-Site Scripting).

## How GSC Found It

[GSC](https://github.com/poliakarmai/gsc) (Git Security Checker) is a self-learning SAST platform that detected this with its GS020 XSS detector. The detector uses pattern-based regex matching for DOM sinks (`innerHTML`, `document.write`, `dangerouslySetInnerHTML`) and template injection patterns across 7+ languages.

```bash
gsc scan cyberbro/ --ci --json
# → GS020 CRITICAL: "DOM XSS: .innerHTML assignment"
```

GSC doesn't just find vulnerabilities — it proves them with auto-generated exploits, auto-generates verified fixes, and opens PRs. This cyberbro fix is one of [6 security PRs](https://github.com/poliakarmai/gsc/blob/master/GSC_PRS.md) created by GSC.

## Credits

- **Scanner:** [GSC — Git Security Checker](https://github.com/poliakarmai/gsc) by @poliakarmai
- **Repository:** [stanfrbd/cyberbro](https://github.com/stanfrbd/cyberbro)
- **Maintainer:** @stanfrbd — thank you for the quick review and merge!
