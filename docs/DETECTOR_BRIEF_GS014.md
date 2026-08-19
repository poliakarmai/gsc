# Brief: Improve GS014 (Credential Exposure) precision in GSC

> For an external AI agent (Claude Code / Codex / ChatGPT). **Self-contained** — the full
> detector source is embedded below, no repo access needed. Return only proposals in the
> format from §6.

---

## 1. Context

GSC is a self-learning SAST platform (Python, 42 detectors). Detectors are regex patterns +
context filters. **The current pain is precision, not recall**: on 10 real-world projects
(160–132K ⭐) the scan yields 2695 findings, precision CRITICAL ~8–12%. The goal is to remove
false positives (FP) **without losing** true positives (TP).

Detector **GS014 — Credential Exposure** (Echelon 2, SECURITY) flags exposed credentials:
SAM/SYSTEM backups, DPAPI master keys, stored credential files (`.rdp`, `credentials.xml`),
private keys (`id_rsa`, `*.pem`, `*.key`), env/credential files (`.env`, `.credentials`),
unattended-install files (`autounattend.xml`, kickstart), shell-history files, plus
content-based patterns: base64 admin password in unattend, WireGuard `PrivateKey`,
**PostgreSQL connection strings with embedded password**, and sudoers `NOPASSWD:ALL`.

**Current state in the findings DB** (`~/.hermes/state/gsc_audit.db`): `rule_id LIKE 'GS014%'`
has ~1350 rows, of which **~92% (1243 MEDIUM) is one pattern** — the private-key glob. A
**fresh** self-scan of the GSC repo itself now yields **14 findings** (the private-key noise
is already fixed by the current filters — the 1243 is cumulative history):

```
gsc (self-scan):  14 findings
    11  HIGH  PostgreSQL connection string with embedded password
     3  LOW   Environment/credential file — check for hardcoded secrets
bybit-ws:          0 findings
```

Historical DB top titles (cumulative, some already fixed):

| title | count | severity |
|---|---|---|
| Private key file — verify proper permissions | 1243 | MEDIUM |
| PostgreSQL connection string with embedded password | 78 | HIGH |
| Environment/credential file — check for hardcoded secrets | 26 | LOW |

## 2. Current detector code (change only patterns/filters, not the contract)

```python
# gs014_credential_exposure.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS014 — Credential Exposure Detector
Echelon: 2 (SECURITY)
Category: HIGH

Detects credential exposure patterns from Redteam Kit:
- Unquoted service paths (Windows)
- Stored credentials in config files
- SAM/SYSTEM backup files
- Credential files in home directories
- AlwaysInstallElevated registry equivalent (Linux sudoers)
- DPAPI/Credential Manager files
- MacAfee SiteList.xml passwords
- Unattended installation files (autounattend.xml, kickstart)

Sources: Window Privilege Escalation, SSH Hardening & Offensive Mastery,
2025 Playbooks (Credential Stuffing)
"""
from . import AuditContext, Finding
import re
from pathlib import Path

RULE_ID = "GS014"
ECHELON = 2
description = "Credential exposure — stored credentials, backup auth files, weak sudoers"


# Files that indicate credential exposure.
# Entry shape: (patterns, title, severity, detail, fixture_sensitive).
# `fixture_sensitive=True` → skip test/fixture paths (vectors/, test/, tests/,
# fixtures/, dummyserver/, *.example/*.sample/*.template/*.test) — those are
# test fixtures / public materials, not real committed credentials.
CREDENTIAL_FILE_PATTERNS = [
    # Windows-like credential files
    (["*.sam", "*.sam.bak", "SYSTEM", "SYSTEM.bak", "ntds.dit"],
     "Potential SAM/SYSTEM backup — Windows credential database",
     "CRITICAL", "SAM/SYSTEM backups allow offline credential extraction.", False),

    # DPAPI master keys
    (["*/DPAPI/*", "*/Microsoft/Protect/*"],
     "DPAPI master key file — encrypted credential storage",
     "MEDIUM", "DPAPI keys may contain decryptable credentials if user password is known.", False),

    # Credential manager files
    (["*.rdp", "*.rdg", "credentials.xml", "SiteList.xml"],
     "Stored credential file (RDP/MacAfee/credential manager)",
     "HIGH", "RDP and credential manager files may contain saved passwords.", False),

    # SSH keys with weak paths
    (["id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key"],
     "Private key file — verify proper permissions and no passphrase",
     "MEDIUM", "Private keys should have 600 permissions and passphrase protection.", True),

    # Config files with potential credentials
    (["*.env", ".env.*", "*.envrc", ".credentials", "credentials.yml",
      "credentials.json", "credentials.ini", ".netrc"],
     "Environment/credential file — check for hardcoded secrets",
     "LOW", "These files should be gitignored. Verify no secrets are committed.", True),

    # Unattended installation files
    (["autounattend.xml", "unattend.xml", "Unattend.xml",
      "*.kickstart", "preseed.cfg", "answerfile*"],
     "Unattended installation file — may contain encoded passwords",
     "CRITICAL", "Unattended files often contain base64-encoded admin passwords.", False),

    # Shell history files (shouldn't be in repo)
    ([".bash_history", ".zsh_history", ".fish_history", ".psql_history", ".mysql_history"],
     "Shell history file in repo — may contain credentials in command lines",
     "MEDIUM", "Shell history files may contain passwords passed as command arguments.", False),
]

# Placeholder/example passwords used in docstrings and examples. A connection
# string carrying one of these is documentation, not an exposed credential.
POSTGRES_PLACEHOLDER = (
    r"(?:\*\*\*|pass|password|secret|changeme|example|your|xxx|pwd|scott|tiger|user|test|admin)"
)

# Content-based patterns
CONTENT_PATTERNS = [
    # Base64-encoded admin password in autounattend
    (re.compile(r'<AdministratorPassword>.*?<Value>([^<]{20,})</Value>', re.I | re.DOTALL),
     "Base64-encoded admin password in unattend file", "CRITICAL",
     "Windows autounattend.xml contains encoded Administrator password. "
     "This is trivially decodable (base64)."),

    # WireGuard/OpenVPN keys in config
    (re.compile(r'PrivateKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}', re.I),
     "WireGuard private key in config", "HIGH",
     "WireGuard PrivateKey exposed in configuration file. "
     "Use external key storage or environment variable."),

    # PostgreSQL connection strings with password (skip placeholder/example passwords)
    (re.compile(r'postgres(?:ql)?://[^:@]+:(?!' + POSTGRES_PLACEHOLDER + r'@)[^@]+@', re.I),
     "PostgreSQL connection string with embedded password", "HIGH",
     "Database URL contains password in plaintext. Use environment variable."),

    # sudoers: NOPASSWD for ALL commands
    (re.compile(r'^\s*\S+\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*NOPASSWD\s*:\s*ALL', re.I | re.MULTILINE),
     "sudoers NOPASSWD:ALL — unrestricted sudo without password", "HIGH",
     "NOPASSWD on ALL commands allows privilege escalation without re-authentication. "
     "Restrict to specific commands with NOPASSWD."),

    # sudoers: user with ALL=(ALL) ALL
    (re.compile(r'^\s*(\S+)\s+ALL\s*=\s*\(\s*(?:ALL|root)\s*\)\s*ALL', re.I | re.MULTILINE),
     "sudoers: full sudo access — verify it's intentional", "LOW",
     "Full sudo access detected. Verify user requires full privileges."),
]

# Public cert/key PEM headers — these are NOT private keys and must not be flagged.
PUBLIC_KEY_MARKERS = (
    "BEGIN CERTIFICATE", "BEGIN PUBLIC KEY", "BEGIN X509",
    "BEGIN TRUSTED CERTIFICATE", "BEGIN RSA PUBLIC KEY",
    "BEGIN EC PUBLIC KEY", "BEGIN DSA PUBLIC KEY",
)

# Directory components that mark a test/fixture path (not real credentials).
TEST_FIXTURE_COMPONENTS = {
    "vectors", "testdata", "fixtures", "__fixtures__", "tests", "test", "dummyserver",
}


def _match_glob(path: Path, pattern: str) -> bool:
    """Simple glob matching for credential file patterns."""
    import fnmatch
    # Handle path patterns like */DPAPI/*
    if "/" in pattern or "\\" in pattern:
        return fnmatch.fnmatch(str(path).replace("\\", "/"), pattern)
    return fnmatch.fnmatch(path.name, pattern)


def _is_test_fixture_path(rel_path: str) -> bool:
    """True if rel_path is a test vector / fixture / example file, not a real credential."""
    p = rel_path.replace("\\", "/").lower()
    parts = p.split("/")
    for comp in parts[:-1]:                     # directory components only
        if comp in TEST_FIXTURE_COMPONENTS:
            return True
    name = parts[-1]
    if name == "test.env":
        return True
    return name.endswith((".example", ".sample", ".template", ".test"))


def _is_public_key_material(fp: Path) -> bool:
    """True if a .pem/.key file's head is a public certificate/key (not a private key)."""
    try:
        head = fp.read_bytes()[:2048].decode("utf-8", errors="ignore")
    except Exception:
        return False
    return any(m in head for m in PUBLIC_KEY_MARKERS)


def detect(ctx: AuditContext) -> list[Finding]:
    if "GS014" in ctx.skipped_detectors:
        return []
    findings = []

    # Get ALL files (not just source — credential files may be in any location)
    all_files = ctx.get_files()

    for fp in all_files:
        rel_path = str(fp.relative_to(ctx.path))

        # 1. Check filename patterns
        for patterns, title, severity, detail, fixture_sensitive in CREDENTIAL_FILE_PATTERNS:
            if not any(_match_glob(fp, pat) for pat in patterns):
                continue

            # Don't flag SSH keys in .ssh/ directories (user home)
            if (fp.suffix in (".pem", ".key") or fp.name.startswith("id_")) and ".ssh/" in str(fp):
                continue

            # Skip test vectors / fixtures / examples (not real credentials)
            if fixture_sensitive and _is_test_fixture_path(rel_path):
                continue

            # .pem/.key that are public certs/keys — not private keys
            if fp.suffix in (".pem", ".key") and _is_public_key_material(fp):
                continue

            findings.append(Finding(
                rule_id=RULE_ID,
                file_path=rel_path,
                line=1,
                severity=severity,
                title=title,
                detail=detail,
                fix_suggestion="Remove from repository. Add to .gitignore. "
                               "Rotate any exposed credentials.",
                references=["Window Privilege Escalation Guide",
                            "SSH Hardening & Offensive Mastery"]
            ))

        # 2. Check content-based patterns (only for text files)
        if fp.suffix in (".xml", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json",
                         ".txt", ".md", ".sh", ".bash", ".py", ".rb", ""):
            try:
                content = fp.read_text()
            except Exception:
                continue

            for pattern, title, severity, detail in CONTENT_PATTERNS:
                for match in pattern.finditer(content):
                    lineno = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        rule_id=RULE_ID,
                        file_path=rel_path,
                        line=lineno,
                        severity=severity,
                        title=title,
                        detail=detail,
                        fix_suggestion="Remove hardcoded credential. Use environment variables "
                                       "or secrets manager. Rotate exposed secrets.",
                        references=["Redteam Kit", "2025 Playbooks - Credential Stuffing"]
                    ))

    return findings
```

## 3. Metric — what counts as "better"

- **Primary: precision** = TP/(TP+FP). Remove FP **without losing TP**.
- **Guard:** any narrowing/disabling of a pattern is acceptable only if TP cases still fire.
- Recall (new patterns) is secondary, and only after precision is stable.

## 4. Known FP candidates (leads — verify and confirm/refute each)

### Lead 1 (main remaining bug) — PostgreSQL: flags documentation + its own brief

`postgres(?:ql)?://[^:@]+:(?!placeholder@)[^@]+@` fires on **any** `postgres://user:pass@host`
whose password is not in `POSTGRES_PLACEHOLDER`, regardless of whether it lives in
documentation, a docstring, or a real config. The current placeholder list
(`***|pass|password|secret|changeme|example|your|xxx|pwd|scott|tiger|user|test|admin`) does
not cover everything. A fresh self-scan of the GSC repo yields **11 HIGH, and the detector
flags its own documentation**:

| file | why FP |
|---|---|
| `docs/DETECTOR_BRIEF_GS014.md` (×4) | **the brief itself** — example URLs in the doc |
| `docs/DETECTOR_BRIEF_GS021.md` | example URL in another detector's brief |
| `benchmark/real_world/sanic/guide/content/en/guide/how-to/orm.md` | documentation (Markdown) |
| `gsc_core/gsc_detectors/gs040_pii_disclosure.py` | docstring example |
| `gsc_core/gsc_collector/spiders/gsc_vuln_spider.py` | docstring example |
| `docker-compose.yml`, `k8s/base/00-namespace-config.yaml` | deploy config (borderline — verify) |

**Fix direction (two-step):**
1. **Placeholder widening** — treat any password that equals its own username (self-
   reference `user:user@`, `postgres:postgres@`, `remnawave:remnawave@`) or a doc/example
   token as a placeholder, OR
2. **Context filter** — skip matches whose line is inside a docstring (`"""`/`'''` block)
   or a Markdown file, OR drop `.md`/`.txt`/`.rst` from the content-scan extensions for the
   postgres pattern specifically.

> ⚠️ **Do NOT over-filter:** `docker-compose.yml`, `k8s/*.yaml`, and `.env` with real
> credentials are **TP** — keep them firing. The FP is documentation/docstring/self-reference,
> not "any non-Python file".

### Lead 2 — Private-key glob (1243 historical) — ALREADY fixed, verify

The current code already has `fixture_sensitive=True` + `_is_test_fixture_path` +
`_is_public_key_material`, so a fresh self-scan of gsc/bybit-ws yields **0** private-key
findings. The 1243 rows in the DB are cumulative history (mostly `cryptography`'s
`vectors/cryptography_vectors/**/*.pem` public test keys). **Your job is only to confirm**
the existing filters hold on external projects — i.e. verify `_is_public_key_material`
covers binary/DER `.pem` (no ASCII `BEGIN …` marker) and that `*.key` public keys are not
misflagged. Do not weaken these filters.

### Lead 3 — env/credential glob (3 on self-scan) — these are TP, do NOT cut

The 3 self-scan hits are `cloud/.env`, `cloud/.env.bak-20260816_1215`,
`cloud/.env.bak-20260816_212334` — real `.env` files committed to the repo (an actual
credential exposure). These are **true positives**. The glob is already narrowed (no more
`*credentials*` wildcard; explicit `credentials.yml/json/ini`, `.netrc`, `.credentials`).
Only check: on *external* projects, does `*.env` still catch test fixtures that
`_is_test_fixture_path` should have filtered (e.g. `test.env`, `*.env.example`)?

### Lead 4 (data, NOT the detector) — split `rule_id` in the DB

Some rows carry `rule_id = "GS014 (Credential exposure — stored credentials, backup auth
files,)"` (the `description` leaked into `rule_id` in an old version). The current code is
correct (`rule_id=RULE_ID`). This is a DB-migration concern (`UPDATE findings SET
rule_id='GS014' …`), **not** a detector change. Ignore for precision work; just query with
`LIKE 'GS014%'`.

## 5. Your task

Analyze the code above. For each candidate in §4 (and any OTHER FP you notice) propose a
concrete fix. Three allowed tools (in order of preference):

1. **Path exclusion** — add to a path/glob exclusion (tests, samples, benchmark, vendor).
2. **Regex narrowing** — require more context in the pattern itself.
3. **Context analysis** — extend a `_is_false_positive`-style filter (±3 lines / key capture).

## 6. Response format (strict)

For each proposal, one block:

```
### GS014: <name>
- Type: path_exclusion | regex_narrowing | context_analysis
- Pattern/code: <concrete regex or diff>
- Rationale: why it's an FP (file/line example)
- FP it removes: <real code line>
- TP impact: which TP cases are NOT affected
```

## 7. Do NOT do

- ❌ Do not change `RULE_ID`, the severity scale, the `detect()` signature, or `Finding` keys.
- ❌ Do not disable the detector wholesale — only filters.
- ❌ Do not weaken `_is_test_fixture_path` / `_is_public_key_material` — they already fix the
  private-key noise (Lead 2).
- ❌ Do not "clean up" code beyond the task (scope discipline).
- ❌ Do not propose without FP examples (can't assess risk/benefit).
- ❌ Do not add new credential *detection* (recall) — this is a precision pass only.

## 8. Verification procedure (run before claiming a fix)

```bash
cd ~/gsc
# Fresh FP slice — do NOT trust the historical DB for "is it still firing"
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from pathlib import Path
from gsc_detectors import AuditContext
from gsc_detectors import gs014_credential_exposure as g14
for root in ('.', str(Path.home()/'bybit-ws')):
    ctx = AuditContext(project='x', path=Path(root)); ctx.files = ctx.get_files()
    fs = g14.detect(ctx)
    print(root, '->', len(fs), 'findings')
    for f in fs[:20]:
        print('  ', f.get('severity'), f.get('file_path'), f.get('title'))
PY

# full suite + standalone regression/compliance
python3 -m pytest -q
python3 tests/test_regression.py
python3 tests/test_compliance_secrets.py
```

Pitfalls:
- `Finding` is dict-like: `severity=`/`category=` (same), `file_path`/`line_number`/`detail`
  (NOT `file=`/`message=`). Emit both where a bridge expects one.
- This detector scans **ALL** files via `ctx.get_files()` (not `get_source_files()`) — do not
  narrow it to source-only; credential files may be in any location.
- `test_regression.py` / `test_compliance_secrets.py` are standalone — run with
  `python3 tests/…`, not `pytest`.
- **Commit only on explicit instruction** — the repo owner gates all commits.
