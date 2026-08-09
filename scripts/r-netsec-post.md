# I built an AI vulnerability hunter that found 3 real bugs in open-source projects this weekend

Over the weekend I ran GSC (Git Security Checker) — my self-learning SAST tool — against random Python projects on GitHub. It autonomously:

1. **Scans repos** (10-100★, active)
2. **Detects vulnerabilities** (38 SAST detectors)
3. **Verifies findings** (LLM-powered TP/FP classification)
4. **Creates PRs with educational fixes** (what/why/when/how + analogy)

**Results (3 PRs in 2 days):**

| Project | Stars | Vulnerability | CWE | PR |
|---------|-------|---------------|-----|-----|
| aio-libs/aiohttp-security | 147 | Session Fixation in demo login | CWE-384 | [#1005](https://github.com/aio-libs/aiohttp-security/pull/1005) |
| mathiasertl/django-ca | 158 | SSRF in ACME HTTP validation | CWE-918 | [#202](https://github.com/mathiasertl/django-ca/pull/202) |
| deep-learning-indaba/Baobab | 60 | Hardcoded API key (533 contributors!) | CWE-798 | [#1401](https://github.com/deep-learning-indaba/Baobab/pull/1401) |

**Technical details:**

- **Detectors:** 38 SAST rules (SQLi, XSS, SSRF, secrets, session fixation, auth, race conditions + language-specific)
- **Precision-hunt mode:** auto-disables noisy detectors (FP < 50%) for external scanning. Currently 1 disabled, 6 review-only, 32 active.
- **Self-learning:** nightly batch revalidation (50 findings/night), auto-deactivates rules with <30% TP rate
- **Federated learning:** DP-noised global weights (ε=1.0) for cross-project pattern quality
- **Educational PRs:** each fix includes What/Why/When/How breakdown + intuitive analogy (AntiVibe-inspired)

**The approach:** Instead of generating spam PRs (99% FP), I focused on precision: quality over quantity. Each finding is LLM-verified before submission. The hunter runs daily at 07:00 MSK, scanning 5-10 projects.

**Lessons learned:**
- Web frameworks and auth libraries are goldmines
- Small projects (10-100★) have more vulns than mature ones (100-500★)
- f-string SQLi detector needs context (parameterized `?` placeholders)
- 3rd-party JS in static/ folders is a major FP source

**Open source:** https://github.com/poliakarmai/gsc (BUSL-1.1)

**Feedback welcome:** What vulnerability classes should I add detectors for? Prototype pollution? SSTI? Deserialization gadgets?
