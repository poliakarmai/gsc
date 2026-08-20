#!/usr/bin/env python3
"""Generate a self-contained precision brief for an external agent."""
import re
from pathlib import Path

GSC = Path(__file__).resolve().parent.parent
DET = GSC / "gsc_core" / "gsc_detectors"
OUT = GSC / "docs" / "GSC_DETECTOR_PRECISION_BRIEF.md"

DETECTORS = [
    "gs001_hardcoded_secret", "gs002_world_readable", "gs003_debug_prints",
    "gs004_dangerous_subprocess", "gs005_sql_injection", "gs007_idor",
    "gs008_dead_code", "gs009_supply_chain", "gs010_ssh_hardening",
    "gs011_jwt_vulnerabilities", "gs012_mass_assignment", "gs013_graphql_security",
    "gs014_credential_exposure", "gs015_entry_points", "gs016_linux_priv_esc",
    "gs017_weak_passwords", "gs018_payment_abuse", "gs019_auth_session",
    "gs020_xss_injection", "gs021_csrf_ssrf", "gs022_open_redirect",
    "gs023_race_conditions", "gs024_llm_sqli", "gs025_ai_provenance",
    "gs028_invariants", "gs029_secrets", "gs030_sca", "gs031_iac",
    "gs032_prompt_injection", "gs033_cicd", "gs034_supply_chain", "gs035_php",
    "gs036_nodejs", "gs037_python", "gs038_go", "gs039_ruby", "gs040_pii_disclosure",
]

YAML_RULES = ["ssti_injection", "reverse_shell", "no_print_secrets",
              "no_eval_exec", "no_debug_true"]


def meta(name: str):
    code = (DET / f"{name}.py").read_text()
    rule = re.search(r'(?:RULE_ID|rule_id)\s*=\s*["\']([^"\']+)', code)
    ech = re.search(r'ECHELON\s*=\s*(\d+)', code)
    noise = re.search(r'NOISE_TIER\s*=\s*["\']([^"\']+)', code)
    return {
        "rule": rule.group(1) if rule else "?",
        "echelon": ech.group(1) if ech else "?",
        "noise": noise.group(1) if noise else "normal",
        "code": code,
        "lines": code.count("\n"),
    }


def section_detectors():
    out = []
    out.append("## 3. Detectors — full embedded source\n")
    out.append("Each detector is a single module exporting `RULE_ID`, `ECHELON`, "
               "`NOISE_TIER`, `description`, and `detect(ctx) -> list[Finding]`.\n")
    out.append("**The code below is the ONLY source of truth. Do not invent "
               "signatures, DB columns, or helper functions not shown here.**\n")
    for name in DETECTORS:
        m = meta(name)
        out.append(f"\n---\n\n### {m['rule']} — `{name}.py` "
                   f"(echelon {m['echelon']}, noise_tier `{m['noise']}`, {m['lines']} lines)\n")
        out.append(f"```python\n{m['code']}\n```\n")
    # YAML rules
    out.append("\n---\n\n### YAML custom rules\n")
    for name in YAML_RULES:
        p = DET / "yaml_rules" / f"{name}.py"
        if not p.exists():
            continue
        code = p.read_text()
        out.append(f"\n#### yaml_rules/{name}.py\n")
        out.append(f"```python\n{code}\n```\n")
    return "".join(out)


HEADER = """# GSC Detector Precision Brief — self-contained (no repo access required)

> **Goal:** find and fix false-positive (FP) noise in GSC detectors. You must
> return precise, reviewable edits (diff blocks) that reduce FP **without losing
> true positives (recall)**. This brief embeds the full source of every detector,
> the exact `Finding`/`AuditContext` contract, the FP evidence already measured,
> and hard anti-hallucination rules.

---

## 0. What you must deliver

For each noisy detector, produce a self-contained edit proposal with:

- **Which file** and **which pattern/loop** is producing the FP (trace it, don't guess).
- **Before / After** code (exact diff).
- **Rationale** — why the match is NOT a vulnerability.
- **FP-removed** — expected delta on the clean projects (concrete numbers).
- **TP-impact** — proof the real vulnerability cases still match.
- **Verification** — the exact scan command and the expected result.

**You do NOT have repo access.** Everything you need is in this file. If you need
a symbol or file that is not in §3, write `UNKNOWN:<name>` and ask for it — do not
invent it.

---

## 1. Context — precision already measured

Fresh scan (2026-08-20) of 10 real open-source projects, `--ci` (regex-only):

| Metric | Value |
|---|---|
| Total findings | 506 |
| CRITICAL | ~27 |
| HIGH | ~218 |

Manual verification of every CRITICAL found **~0 real vulnerabilities** — nearly
all are FP. The measured FP causes (your hunting map):

| # | FP cause | Example (project / file:line) |
|---|---|---|
| 1 | **Docstring example** matched as code | loguru `_logger.py:1607` `>>> record = pickle.loads(pipe.read())` |
| 2 | **Public test keys** flagged as secrets | piccolo-api `captcha.py:57` hCaptcha `0x0000…` / `10000000-…` |
| 3 | **Parameterized query** seen as SQLi | piccolo-api `crud/endpoints.py:491` `.raw(sql, f"%{search_term}%")` |
| 4 | **Fixed subprocess args** as cmd-injection | youtube-dl `YoutubeDL.py:429` `['bidiv'] + width_args` |
| 5 | **JS operator** as SQL keyword | youtube-dl `openload.py:86` `delete window._phantom` |
| 6 | **Bare word `key`** as crypto secret | pendulum `formatter.py:351` `key = "translations.day_periods"` |
| 7 | **Abstract method / aggregate marker** | piccolo-api `mfa/provider.py:40` `@abstractmethod send_code` |
| 8 | **Fake CVE / extractor API token** | httpie `man_pages.py:21` `os.system == 'nt'` (comparison) |

Some of these are already patched (see §5 "already fixed"). Your job is to find
the **remaining** noise, including patterns not yet listed here, across all
detectors and all severity levels (CRITICAL / HIGH / MEDIUM / LOW / INFO).

**Critical rule:** a finding that is real code matching an insecure-API name
(e.g. `pickle.loads`, `os.system`, `.execute(`) is **NOT** automatically a
vulnerability. It is only a vulnerability when **user-controlled / untrusted
input** reaches the sink. Regex detectors that match the sink without a taint
source are the #1 FP generator — treat "no taint ⇒ downgrade or suppress" as the
default fix, not "keep the pattern".

---

## 2. Contract (verbatim)

### Finding

```python
class Finding(dict):
    def __init__(self, rule_id, severity="MEDIUM", title="", file_path="",
                 line=0, detail="", fix_suggestion="", references=None,
                 noise_tier="normal", **kwargs):
        sev = kwargs.pop("category", severity)
        line_no = kwargs.pop("line_number", line)
        super().__init__(
            rule_id=rule_id, severity=sev, category=sev, title=title,
            file_path=file_path, line=line_no, line_number=line_no,
            detail=detail, fix_suggestion=fix_suggestion,
            references=references or [], noise_tier=noise_tier or "normal",
            **kwargs)
```

Supported extra keys (via `**kwargs`): `confidence`, `cwe`, `cvss`, `metadata`,
`snippet`, `secret_value`, `pattern_ids`, `finding_key`.

### AuditContext (key fields/methods detectors use)

```python
@dataclass
class AuditContext:
    project: str
    path: Path                       # absolute project root
    files: list[Path]
    file_contents: dict[str, str]
    skipped_detectors: set[str]
    MAX_SCAN_FILE_SIZE: int = 1_000_000
    def get_files(self, extensions=None) -> list[Path]
    def get_source_files(self, extensions=None) -> list[Path]  # excludes tests/non-code
    def read_file(self, filepath: Path) -> str
    def get_disabled_patterns(self, rule_id: str) -> set[str]
    def is_test_file(self, filepath: Path) -> bool
```

Most detectors iterate `ctx.get_source_files(...)` and call `ctx.read_file(fp)`.
A detector returns `list[Finding]`; returning `None` elements is allowed and the
registry filters them out.

---

"""

CONSTRAINTS = """

---

## 5. Constraints — what you may / may not change

### MAY change
- `*_PATTERNS` / `*_RULES` lists and their regexes.
- Local helper functions (`_has_sanitizer`, `_is_placeholder`, `_mask_*`, ...).
- Add **new** local skip/downgrade filters inside `detect()`.

### MUST NOT change
- `RULE_ID`, `ECHELON`, `NOISE_TIER` (unless explicitly argued + approved).
- The `Finding` / `AuditContext` contract.
- `description` strings (cosmetic only).
- The module's public signature `detect(ctx)`.

### Recall is non-negotiable
- Before suppressing a pattern, prove the real-vulnerability cases still match.
- Downgrade (`CRITICAL`→`HIGH`/`MEDIUM`) is preferred over deletion when the
  pattern is ambiguous. Only **delete** a pattern when it has **zero TP value**
  (name-only matches, fake CVEs, aggregate markers).

### Already fixed (do NOT re-propose)
- GS037: docstring masking + aggregate `GS037-high_risk` demoted to INFO.
- GS019: placeholder/test-secret markers (`0x0000…`, `10000000-…`, `6LeI…`).
- GS005: removed `execute with <collection>[idx]` unpacking patterns.
- DB seed `Hardcoded encryption key`: narrowed (bare `key` removed).
- DB pattern `pickle.load()`: deactivated (duplicate of GS037).

---

## 6. ANTI-HALLUCINATION guardrails (from past agent failures)

1. **Do not invent signatures.** A past agent rewrote `load_patterns()` with a
   non-existent `cursor.execute(...)` + `ORDER BY priority`. → Only diff code
   that appears verbatim in §3.
2. **Do not invent a DB layer.** If a detector is a plain regex module (no
   `sqlite3`, no `load_patterns`, no `rule_id` column), say so — do not add one.
3. **Trace the FP to its exact pattern.** A past agent "fixed" the OWASP `chmod`
   pattern while the FP actually came from `_perm_finding()`. → For every FP you
   cite, give `file:line` and the exact pattern/loop that produced it.
4. **Check for mirrors.** Some rules live in more than one file (e.g. a regex in
   a detector AND in the DB `patterns` table). State whether the file is unique
   or list every mirror.

Additional rules:
- If you need a symbol not in §3 → `UNKNOWN:<name>` and ask. Never fabricate.
- No vague "add a filter" answers — give the exact regex and insertion point.
- Never claim a "TP" on a vulnerable benchmark project without showing the
  snippet and arguing why it is genuinely exploitable (a `HOST="localhost"`
  default or a `!= '127.0.0.1'` comparison is NOT an SSRF TP).

---

## 7. Response format

For each detector you touch, emit a block:

```
## <GS0xx> <detector-name>
Type: <suppress | downgrade | narrow-regex | delete-pattern | add-taint-check>
File: <path.py>
Pattern/loop: <the exact _PATTERNS entry or loop that produces the FP>
FP evidence: <project file:line → snippet → why not a vuln>
Before:
    <current code>
After:
    <proposed code>
Rationale: <1-2 sentences>
FP-removed: <clean-project: N → 0>
TP-impact: <vuln-project: still N/N detected — with snippet proof>
Verification: <exact scan command + expected result>
```

Rank proposals by FP volume (biggest noise first). End with a summary table:

```
| Detector | Change | FP-removed | TP-impact |
```

---

## 8. Verification commands

```bash
cd ~/gsc
# Full test suite (must stay green — 461 passed, 5 skipped)
python3 -m pytest -q

# Clean projects (FP should drop)
python3 gsc.py scan benchmark/real_world/loguru --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/pendulum --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/piccolo-api --ci --json | grep -c CRITICAL

# Vulnerable projects (TP must NOT drop)
python3 gsc.py scan /tmp/gsc-calibration/pygoat --ci --json | grep -c CRITICAL
python3 gsc.py scan /tmp/gsc-calibration/dvpwa --ci --json | grep -c CRITICAL
```

Expected after a correct fix: clean-project CRITICAL drops toward 0 while
vuln-project CRITICAL stays ≥ its current baseline. Always report the exact
before/after numbers.
"""


def main():
    body = HEADER + section_detectors() + CONSTRAINTS
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(body)
    print(f"Written {OUT} ({len(body.splitlines())} lines, {len(body)} chars)")


if __name__ == "__main__":
    main()
