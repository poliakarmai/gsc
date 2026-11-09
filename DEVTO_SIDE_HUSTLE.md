---
title: "The Same Bug, Three Times: Hardcoded Secrets Keep Shipping to Production"
published: false
tags: security, opensource, showdev, ai
---

A security scanner that publishes its own false positive — and found the same class of bug in three unrelated projects.

It's called GSC. It found a debugger exposed on a public interface in a 3,552-star project, an XSS in a 693-star OSINT platform, four hardcoded secrets in a Flask deployment tool, a default-admin-credentials bug in a file host, and an OS command injection in a server panel. Six fixes landed in production repos. One report was wrong — and one ended up as something more interesting than the fix I proposed. I'm going to show you both.

**Who pays for this?** Anyone with a repo they can't afford to be wrong about — and, importantly for what follows, anyone who has already tried a noisy scanner and turned it off.

## The Finding That Made Me Write This

Three projects, three unrelated maintainers, no shared code. Same mistake:

| Project | What was committed | CWE |
|---|---|---|
| `cabotage/cabotage-app` | `SECRET_KEY="my_precious"`, `SECURITY_PASSWORD_SALT`, `SECURITY_TOTP_SECRETS`, `REGISTRY_AUTH_SECRET` | CWE-798 |
| `django-files/django-files` | `SECRET=JYGTKLzt…` in `docker-compose-prod.yaml`, plus `testuser`/`demopassword` admin creds | CWE-798, CWE-521 |
| `manjurulhoque/doccure` | Django `SECRET_KEY` inline in `settings.py` | CWE-798 |

This is not three mistakes. It's **one broken template, copied three times.** Framework scaffolding generates `SECRET_KEY = 'django-insecure-...'` as a *convenience*, and the path from "it runs locally" to "it's on the internet" has no gate that says *this literal must not ship*. Project one had 38 stars, project two had 12, project three had 81. Star count doesn't predict it.

For cabotage it was four secrets in one file — a 7-file, +168/−1 patch, because rotating a `SECRET_KEY` isn't a one-line change: it invalidates every session, CSRF token, and TOTP secret already issued. That's the part people don't do by hand.

Why it matters concretely: a leaked `SECRET_KEY` means forged sessions, bypassed CSRF, and forged password-reset tokens. A leaked `SECURITY_TOTP_SECRETS` means your 2FA is decorative. And `testuser`/`demopassword` shipped in a *prod* compose file means the front door was open with a sign on it.

## The Biggest Finding: A Debugger on a 3,552-Star Project

`yoheinakajima/instagraph` had the Werkzeug debugger exposed when the app bound to `0.0.0.0`. That's an interactive Python console on a public interface — request `/console` and, on an unprotected deployment, you get code execution. Merged as [#94](https://github.com/yoheinakajima/instagraph/pull/94), +6/−2.

3,552 stars, and the diff is six lines. That ratio is the whole argument for automated scanning: the severity of a finding has nothing to do with how hard it is to fix, so a human reviewer's attention is wasted looking for it and well spent on the fix.

## The XSS in a 693-Star Project

`stanfrbd/cyberbro` (693 ⭐ at scan time) had its search-highlight feature building DOM with `.innerHTML` and unsanitized query input:

```javascript
// before — the query string is attacker-controlled
element.innerHTML = highlightSearchTerms(element.textContent, query);
```

Search `"><img src=x onerror=…>` and it executes. Merged as [#212](https://github.com/stanfrbd/cyberbro/pull/212), +8/−1 — the kind of patch a maintainer will actually take, because it's small and obviously correct.

## The One Where the Maintainer Fixed It Themselves

`BrowserlessAPI/VortexPanel` had OS command injection in its file manager: `subprocess.run(..., shell=True)` interpolating unsanitized user input, with `safe_path()` that normalises paths but doesn't escape shell metacharacters.

I opened [PR #19](https://github.com/BrowserlessAPI/VortexPanel/pull/19). The owner closed it — and wrote back: *"all the Vulnerability closed now."*

That's the part I had to verify rather than take on faith. It checks out: **v3.5.0**, released a week later, documents *"Domain names are validated before reaching shell commands or filesystem paths."* The fix landed. My patch didn't get merged; the vulnerability did get fixed. Counting that as a win is fair — but only because I went and checked, which is the whole point of this section.

## The Report I Got Wrong

Here is a map that most scanner vendors would leave out.

I filed session-fixation (CWE-384) bugs against two projects. A maintainer of `liquidguru/docker-updater` pushed back, carefully, and was right:

> *"this app uses Flask's default client-side sessions... Session fixation needs a persistent identifier that survives login, and there isn't one... I tested the actual attack rather than reasoning about it."*

He'd actually run the attack. My finding was wrong. But he added:

> *"reviewing this did turn up something real, so thank you — it wasn't wasted."*

Reviewing it surfaced a genuine issue: sessions are signed with `FLASK_SECRET_KEY`, not derived from the password, so **changing `AUTH_PASSWORD` does not invalidate existing sessions** — a leaked session outlives the password change by up to 7 days. He documented rotating the signing key alongside it ([`e855972`](https://github.com/liquidguru/docker-updater/commit/e855972)).

The same thing happened in `aiohttp-security`: the maintainer asked *"can you walk me through what is happening here?"* twice, and each time the honest answer was that my claimed attack didn't apply to the demo's client-side cookie storage. I conceded it in-thread and reframed the PR as defence-in-depth (rotating the session on login, OWASP ASVS V3.2.1) rather than a live vulnerability.

And one report was flatly wrong. A maintainer of `wine-cellar` pointed out that the "insecure" settings I flagged are a deliberate **development** config, with `docker_settings.py` and `prod.py` for real deployments:

> *"Please instruct your ai next time to research the deployment a bit better ;-)"*

Fair. The scanner sees `DEBUG = True` and a `django-insecure-` prefix; it does not see that this file is never loaded in production. That's a real limit of pattern-based analysis, and the honest response is to write it down instead of quietly deleting the row.

## Why Open Innovation Matters

Two reasons, and the second is the one people underestimate.

**First: the data problem.** Scanning someone's code with a hosted API means shipping their source — including the secrets you're looking for — to a third party. That's a non-starter for a large chunk of the market. The answer is open-weight models running locally: the code never leaves the machine, and there's no per-scan bill that makes continuous scanning a budget conversation. GSC supports Ollama and vLLM endpoints directly, so the LLM-based revalidation step can run entirely on your own hardware.

**Second: auditability.** This is the part I care about most. I can tell you my scanner found five real fixes *because I can also tell you it produced one false positive and I published it.* A closed tool's accuracy claims are unfalsifiable — you get a percentage with no denominator and no list of what it missed. With an open codebase you can re-run it, read the detector, and check my scorecard against the actual PRs.

That matters commercially, not just philosophically. The scanner you pay for isn't the one that finds the most — it's the one you don't turn off after a week of noise. A tool whose misses are on the record is a tool you can calibrate. That's the difference between a subscription and a nuisance.

## Show Me the Numbers

Every row below is verifiable against the GitHub API. Reproduce it yourself.

**Merged — the fix is my patch:**

| Project | PR | CWE | Diff |
|---|---|---|---|
| yoheinakajima/instagraph ⭐3552 | #94 | Werkzeug debugger exposed | +6/−2 |
| stanfrbd/cyberbro ⭐693 | #212 | CWE-79 | +8/−1 |
| cabotage/cabotage-app ⭐38 | #388 | CWE-798 | +168/−1, 7 files |
| django-files ⭐12 | #428 | CWE-798, CWE-521 | +6/−1 |

**Accepted — maintainer fixed it themselves:**

| Project | PR | Verified by |
|---|---|---|
| BrowserlessAPI/VortexPanel ⭐28 | #19 | v3.5.0 release notes (shell-command validation) |
| GoyGram/GoyGram ⭐20 | #4 | applied by hand in commit `4cc0778`, Co-authored-by preserved |
| boaz-ke/duty-calculator | #1 | vulnerability confirmed; maintainer fixed it their own way |

**Partial — PR declined, review surfaced a different real issue:**

| Project | PR | Result |
|---|---|---|
| liquidguru/docker-updater ⭐80 | #21 | My CWE-384 claim was wrong (maintainer tested it). The review found that changing `AUTH_PASSWORD` doesn't invalidate sessions; maintainer documented the fix in `e855972`. Docs, not code. |

**Open:** aiohttp-security #1005 (⭐240, reframed), django-ca #202 (⭐158, rebased), and four more awaiting maintainer review.

**Rejected:** 1 — and it's in the table above, not hidden.

Six fixes in production — 4 merged patches, 2 fixed upstream by the maintainers — across 4,343 combined stars; one partial (a real finding, different from the one I claimed). One report wrong, labelled wrong.

## How I Built It

GSC ("Git Security Checker") is an open-source SAST platform — 73 detectors across SAST, secrets, SCA and IaC, with a full `detect → prove → fix → verify` loop. The parts that matter for this post:

- **Precision-hunt profile.** The legacy catch-all detector is off, and the six noisiest ones are review-only — they flag but never block. A finding that opens a PR needs to be *right*, so the profile optimises for precision over recall — and every finding gets a human review before it becomes a PR. That review is what caught the wine-cellar false positive before it cost a maintainer time.
- **Fix generation, not just detection.** Detecting a hardcoded secret is easy; the `+168/−1` cabotage patch is the actual work, and it's the reason these PRs get merged instead of closed.
- **Local inference for revalidation.** Optional LLM-based revalidation runs against Ollama or vLLM, so it works without sending your code anywhere.

```bash
gsc external-scan <repo> --profile audit --with-poc --with-chains
```

## What's Next

`cabotage` was the interesting one — four secrets, seven files, and a blast radius most people don't think through before "just rotating the key." I want the scanner to explain that blast radius up front: *changing this invalidates these sessions, these tokens, these TOTP secrets.*

If you maintain a project and want yours scanned, open an issue. And if a finding looks wrong, tell me — the maintainer who tested the attack and explained why I was wrong made the tool better than any true positive did.

---

**Code:** [github.com/poliakarmai/gsc](https://github.com/poliakarmai/gsc) · **Scorecard:** [HALL_OF_FAME.md](https://github.com/poliakarmai/gsc/blob/master/HALL_OF_FAME.md)
