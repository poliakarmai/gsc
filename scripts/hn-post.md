Show HN: GSC — AI vulnerability hunter that found 3 real bugs in production code

https://github.com/poliakarmai/gsc

I built a self-learning SAST tool that autonomously scans GitHub repos, finds vulnerabilities, and creates educational PRs. This weekend it found 3 real bugs:

- Session Fixation in aiohttp-security (147★, official aiohttp auth lib) — CWE-384
- SSRF in django-ca (158★, CA management tool) — CWE-918  
- Hardcoded API key in Baobab (60★, 533 contributors can see it) — CWE-798

What makes it different from other scanners:

1. **Precision-first.** 32 active detectors, auto-disables rules with <30% TP rate. No spam PRs.
2. **Educational fixes.** Each PR explains WHAT the vuln is, WHY it matters, WHEN it triggers, HOW to fix — with analogies. Example: "Session fixation is like a cloakroom ticket — if you can hand ticket #42 to a VIP and later claim their coat..."
3. **Self-learning.** Nightly batch revalidation (50 findings via LLM), federated DP-noised weights across projects.
4. **Daily hunter.** Cron job finds small projects (10-100★), scans with precision profile, opens PRs.

Stack: Python 3.12, SQLite, an LLM for verification, 38 SAST detectors.

Looking for feedback on detector coverage — what should I add next? SSTI? Prototype pollution? Deserialization?
