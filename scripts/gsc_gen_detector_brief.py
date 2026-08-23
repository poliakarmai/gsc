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
    "gs041_crypto_secrets", "gs042_solidity", "gs043_honeypot",
    "gs044_trading_bots", "gs045_github_actions",
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
    out.append("Line numbers are shown as `N|` at the start of each line and "
               "match the real source files — cite them as `file:line` in your "
               "proposals (no `UNKNOWN` needed).\n")
    for name in DETECTORS:
        m = meta(name)
        out.append(f"\n---\n\n### {m['rule']} — `{name}.py` "
                   f"(echelon {m['echelon']}, noise_tier `{m['noise']}`, {m['lines']} lines)\n")
        numbered = "\n".join(f"{i+1:4d}| {line}"
                             for i, line in enumerate(m['code'].splitlines()))
        out.append(f"```\n{numbered}\n```\n")
    # YAML rules
    out.append("\n---\n\n### YAML custom rules\n")
    for name in YAML_RULES:
        p = DET / "yaml_rules" / f"{name}.py"
        if not p.exists():
            continue
        code = p.read_text()
        out.append(f"\n#### yaml_rules/{name}.py\n")
        numbered = "\n".join(f"{i+1:4d}| {line}"
                             for i, line in enumerate(code.splitlines()))
        out.append(f"```\n{numbered}\n```\n")
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

Three benchmarks on real projects (`--ci` regex-only). Latest: **Замер 3**
(2026-08-21, 100 real GitHub projects — 90 clean + 10 known-vulnerable).

| Metric | Value |
|---|---|
| Total findings | 64 831 |
| CRITICAL | 4 302 |
| HIGH | 37 246 |
| Recall | 8/10 vulnerable caught |
| Clean projects with CRIT (FP noise) | 48/90 |
| Precision CRITICAL | ~4–5% |

Top CRITICAL generators (FP-noise source):

| Rule | CRIT | Diagnosis |
|---|---|---|
| GS008 (eval/exec) | 2 508 | eval legit in bundlers/minifiers → **FIXED** (`ba4c2d0`) |
| GS000-LEGACY | 505 | no-rule_id data-quality debt → **FIXED** (remap to quality) |
| GS005 (SQLi) | 211 → now 4 258 | f-string/raw-concat → **OPEN, top priority** |

**Recall already closed (do NOT re-open):** hardcoded_secret 0/1→1/1,
idor 0/1→1/1, sql_injection 1/3→3/3 (`eec5d42`); legacy attribution GS000-LEGACY
remapped (IP/admin-ID/CIDR → quality, `dd6e6a3`).

**Your job:** hunt the remaining noise. Priority order from the live findings DB
(`sqlite3 ~/.hermes/state/gsc_audit.db`, snapshot 2026-08-23):

| Priority | Rule | Noise | Clue |
|---|---|---|---|
| 1 | GS005 SQLi | 4 258 CRITICAL | f-string (1813) + raw-concat (792) + CVE-55721 (786) |
| 2 | GS018 payment | 266 HIGH | FLOAT_MONEY regex → FP on legit money math |
| 3 | GS014 credential exposure | 73 HIGH | logs/debug with creds |

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
- GS005: removed `execute with <collection>[idx]` unpacking; skip DB migrations; `SLEEP` no longer matches `time.sleep()`.
- GS001: exclude `tests.py`/`testing.py`; `input()`/`getpass()` prompt is not a secret; removed `sqlite://`; internal dev hosts (localhost/cache/db, even `@user:pass`) → config.
- GS019: abstractmethod lookbehind (`\\b` not `\\s*$`); stub body (`pass`/`...`/`raise NotImplementedError`); `contrib.auth|cycle_key` (Django login rotation); test/`e2e`/`__tests__`/example path exclude.
- GS025: vendor test-secret markers (`0x0000`, `ffff-ffff`, …).
- GS016: skip provision/migrate/setup/install scripts.
- GS017: test/`e2e` path exclude; enum-member role filter (`ADMIN="admin"` — UPPER lhs only).
- GS032: skip tutorial/docs/example/readme.
- `main.py` `_pattern_search`: migration/provision exclude for the DB-pattern layer.
- DB seed `Hardcoded encryption key`: narrowed (bare `key` removed).
- DB pattern `pickle.load()`: deactivated (duplicate of GS037).
- GS001 (recall): `app.config['SECRET_KEY']` / `JWT_SECRET_KEY` covered; 0/1→1/1 (`eec5d42`).
- GS005 (recall): two-step SQLi (%-formatting + concat query building) with taint window 150 lines; 1/3→3/3 (`eec5d42`).
- GS007 (recall): `.objects.get/filter(key=request.GET/POST/COOKIES/...)`; 0/1→1/1 (`eec5d42`).
- GS017: `_is_weak_value` — long mixed-case (≥13) → not weak; KEY/mixed-case gates (`6691959`).
- GS002: config/data files (.yaml/.yml/.json/.log) → not sensitive, narrowed suffix list (`e50afca`).
- `gsc_rule_attribution`: hardcoded IP/admin-ID/CIDR → quality, not GS029 (`dd6e6a3`).
- `main.py` docstring filter: closing triple-quote in expression (`''' % request.url`) not a docstring opener (`eec5d42`).

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
# Full test suite (must stay green — 668 passed, 6 skipped)
python3 -m pytest -q

# Clean projects (FP should drop)
python3 gsc.py scan benchmark/real_world/piccolo-api --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/cyberbro --ci --json | grep -c CRITICAL
python3 gsc.py scan benchmark/real_world/python-sdk --ci --json | grep -c CRITICAL

# Vulnerable projects (TP must NOT drop)
python3 gsc.py scan /tmp/gsc-calibration/pygoat --ci --json | grep -c CRITICAL
python3 gsc.py scan /tmp/gsc-calibration/dvpwa --ci --json | grep -c CRITICAL

# 100-project benchmark (track 0.14.2)
python3 scripts/gsc_benchmark_100.py --scan && python3 scripts/gsc_benchmark_100.py --report
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
