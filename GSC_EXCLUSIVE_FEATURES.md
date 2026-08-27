# GSC Exclusive Features — Code Review

> **Дата:** 2026-08-06  
> **Версия:** v1.4.0  
> **Файлов:** 9 новых, 3 изменённых  
> **Строк:** ~3500 (новых)  
> **Коммиты:** bb0a2c4 → 963af71

---

## 🥇 1. Proof-of-Fix (`gsc_proofoffix.py`, 340 строк)

**Цикл:** finding → patch → sandbox → re-PoC → verify → evidence

```bash
gsc pof generate abc123 --report scan.json --project-root ./repo
```

### Ключевая логика

```python
def generate_fix(finding_key, report_path, project_root):
    # Step 1: Run PoC BEFORE fix — prove it's vulnerable
    evidence.poc_before, evidence.poc_before_exit = _run_poc(finding, source, root)

    # Step 2: LLM generates minimal patch
    llm_output = _generate_patch(finding, source)
    evidence.patch = _parse_patch(llm_output)

    # Step 3: Apply patch in sandbox
    patched_source = _apply_patch(source, evidence.patch)

    # Step 4: Re-run PoC AFTER fix
    evidence.poc_after, evidence.poc_after_exit = _run_poc(finding, patched_source, root)

    # Step 5: Verify — PoC should FAIL on fixed code
    evidence.verified = (
        evidence.poc_before_exit != 0           # was vulnerable
        and evidence.poc_after_exit == 0        # now safe
    )
```

**Формат evidence:**

```json
{
  "finding_key": "abc123",
  "rule_id": "GS005",
  "verified": true,
  "patch": "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n-query = f\"SELECT * FROM users WHERE id={user_input}\"\n+query = \"SELECT * FROM users WHERE id=?\"\n+cursor.execute(query, (user_input,))",
  "poc_before": "SQLi successful: admin@admin.com",
  "poc_before_exit": 1,
  "poc_after": "ERROR: no results",
  "poc_after_exit": 0
}
```

---

## 🥈 2. Self-Healing CI (`gsc_selfhealing.py`, 220 строк)

**Цикл:** scan → CRITICAL/HIGH → Proof-of-Fix → verified patch → auto-PR

```bash
gsc pof batch scan.json --create-pr --max-fixes 3
```

> ⚠️ **Draft-only by design.** Auto-fix PRs are opened as **drafts** with a
> least-privilege token (contents:write on the single repo — no secrets, no
> admin). A human must review and approve before merge; GSC never self-merges.
> Every auto-fix writes an audit trail (finding_key → patch → evidence) so the
> change is traceable end-to-end.

### Eligibility rules

```python
def _eligible_for_autofix(finding):
    return (
        sev in ("CRITICAL", "HIGH")
        and conf >= 0.80
        and verdict not in ("fp", "fixed")
        and rule_id in {"GS001", "GS004", "GS005", "GS017", "GS020", "GS021"}
    )
```

### Auto-PR body

```markdown
## 🛡️ GSC Self-Healing CI: Auto-Fix
**3 verified fixes** applied automatically.

| # | Rule | Key | File |
|---|------|-----|------|
| 1 | GS005 | abc123 | app.py |

## Evidence
- abc123 — [evidence](fixes/abc123.evidence.json)

### How GSC Verified These Fixes
1. Generated PoC exploit → reproduced vulnerability ✅
2. Generated minimal patch via LLM
3. Applied patch in sandbox
4. Re-ran PoC → exploit FAILED → fix VERIFIED ✅
```

---

## 🥉 3. Security Archaeology (`gsc_archaeology.py`, 280 строк)

```bash
gsc archaeology trace abc123 --repo ./project
gsc archaeology report --repo ./project
```

### Fingerprint matching

```python
def _content_fingerprint(snippet):
    """Normalized fingerprint — survives whitespace/indent changes."""
    norm = "".join(snippet.lower().split())[:120]
    return hashlib.sha256(norm.encode()).hexdigest()[:16]

def trace_lifespan(finding, repo_path):
    # git blame → who introduced it
    blame = _git_blame(file_path, line, repo)
    # DB check → when was it resolved
    rows = db.execute("SELECT resolved_at FROM findings WHERE finding_key=?", (key,))
    # Lifespan = resolved_at - introduced_at
```

**Output:**
```
GS003 SQLi in auth.py:42
  Introduced by: commit abc123 (alice) on 2026-06-15
  Fixed by: commit def456 (bob) on 2026-08-01
  Lived: 47 days
  Module: auth — avg lifespan: 23.4 days
```

---

## 4. Predictive Forecasting (`gsc_forecast.py`, 270 строк)

```bash
gsc forecast predict --repo ./project --limit 10
gsc forecast heatmap --repo ./project
```

### Scoring formula (no training needed)

```python
def _calc_risk_score(file_path, per_file_counts):
    score = 0.0

    # Past density (strongest predictor)
    if past_critical > 0:
        score += min(past_critical * 15, 50)
    if past_high > 0:
        score += min(past_high * 8, 30)

    # Churn factor (high churn = more bugs)
    if churn_90d > 20:    score += 15
    elif churn_90d > 10:  score += 8

    # Multi-author = more inconsistency
    if authors_90d > 3:   score += 5

    # Large files = more surface area
    if lines > 1000:      score += 8
    elif lines > 500:     score += 4

    # New files — less history, more risk
    if 0 < age_days < 30: score += 5

    # Module clustering
    if module_critical_count > 5: score += 10

    # Risk levels
    return "critical" if score >= 50 else "high" if score >= 30 else "medium" if score >= 15 else "low"
```

**Output:**
```
 Score  Level      C   H  Churn  File
    55  critical   3   2     42  🔴 payments/checkout.py
    38  high       1   4     18  🟠 auth/login.py
    22  medium     0   2     12  🟡 api/handler.go
     8  low        0   0      2  🟢 utils/helpers.py
```

---

## 5. NL Policy (`gsc_nlpolicy.py`, 310 строк)

```bash
gsc policy add "секреты не должны попадать в логи"
gsc policy list
gsc policy test nlp-abc12345 --repo ./project
```

### LLM compilation

```python
def _compile_policy(natural_text):
    system = "Convert natural-language policy into regex pattern. Output ONLY JSON."
    user = f"POLICY: {natural_text}"
    raw = call_deepseek(system, user)
    compiled = json.loads(raw)
    # → {"rule_id": "GS028-custom", "pattern": "log\.(info|error...)...", ...}
```

### Deterministic enforcement

```python
def policy_test(policy_name, repo):
    pat = re.compile(policy.pattern)
    for f in repo.rglob("*"):
        for line_no, line in enumerate(f.read_text().split("\n"), 1):
            if pat.search(line):
                matches.append({"file": f, "line": line_no})
```

**Output:**
```
Policy nlp-abc12345 (CRITICAL): Log statements must not contain secrets
Pattern: (?i)(?:log\.(?:info|error|debug|warn)\(.*(?:password|secret|token|key|api).*\))
Matches: 8
  payments/paypal.py:142 — log.info(f"Processing with key={api_key}")
  auth/oauth.py:89 — logger.debug(f"secret={client_secret}")
```

---

## 6. Cross-Repo Secrets (`gsc_crossrepo_secrets.py`, 350 строк)

```bash
gsc secrets correlate --repos ./repo1 ./repo2 ./repo3
gsc secrets status --key 5c8d81b3109b...
gsc secrets report
```

### Architecture

```
extract → fingerprint (SHA256[:32]) → correlate → rotation-detect
   ↑                                                                 
   └── NEVER stores secret values, only hashes
```

### Extraction patterns (7 types)

```python
patterns = [
    (r'[A-Za-z0-9+/=]{40,}',              'api_key'),
    (r'AKIA[0-9A-Z]{16}',                  'aws_access_key'),
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH)',   'private_key'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'jwt_token'),
    (r'(?:password|passwd|pwd|secret|token)\s*[:=]\s*[\'"]?([^\s\'"]{8,})', 'config_secret'),
    (r'(?:mongodb|mysql|postgresql|redis)://[^\s]{10,}', 'db_url'),
    (r'\b[0-9a-fA-F]{32,64}\b',           'hex_key'),
]
```

### Rotation detection

```sql
SELECT a.fingerprint, b.fingerprint
FROM secret_sightings a
JOIN secret_sightings b
  ON a.repo_path = b.repo_path
 AND a.file_path = b.file_path
 AND a.line_number = b.line_number
 AND a.fingerprint != b.fingerprint
 AND a.seen_at < b.seen_at
```

### DB Schema (SQLite, WAL)

```sql
-- Fingerprints: one row per unique secret hash
secret_fingerprints(fingerprint TEXT PK, repo_count, total_sightings,
                    rotated INT, status TEXT)

-- Sightings: each occurrence across repos/files/lines  
secret_sightings(id PK, fingerprint FK, repo_path, file_path, line_number,
                 prev_fingerprint, next_fingerprint, seen_at)
```

---

## 7–9. Platform Hygiene (ранее)

### Scan Modes (`gsc_scan_modes.py`, 100 строк)

```python
SCAN_MODES = {
    "quick":    {"llm_enabled": False, "llm_max_calls": 0, ...},   # CI, 5 сек
    "standard": {"llm_enabled": True,  "llm_max_calls": 20, ...},  # повседневная
    "deep":     {"llm_enabled": True,  "llm_max_calls": 50, ...},  # полный аудит
}
```

### Workspace (`gsc_workspace.py`, 260 строк)

```
gsc workspace create "Pentest ACME"
gsc workspace add "Pentest ACME" https://github.com/user/repo
gsc workspace scan "Pentest ACME" --scan-mode deep
gsc workspace report "Pentest ACME"
```

### API v1 (`gsc_api.py`, +6 endpoint)

```
POST   /api/v1/workspaces              create workspace
GET    /api/v1/workspaces              list
POST   /api/v1/workspaces/{n}/repos    add repo
POST   /api/v1/workspaces/{n}/scan     scan all repos
GET    /api/v1/workspaces/{n}/report   aggregate report
DELETE /api/v1/workspaces/{n}          cleanup
```

---

## Итоговая таблица

| # | Модуль | CLI | Эксклюзив | Строк |
|:--:|--------|-----|:---------:|:-----:|
| 1 | `gsc_proofoffix.py` | `gsc pof generate` | 🔴 абсолютный | 340 |
| 2 | `gsc_selfhealing.py` | `gsc pof batch` | 🔴 абсолютный | 220 |
| 3 | `gsc_archaeology.py` | `gsc archaeology` | 🟠 высокий | 280 |
| 4 | `gsc_forecast.py` | `gsc forecast` | 🟠 высокий | 270 |
| 5 | `gsc_nlpolicy.py` | `gsc policy add` | 🟡 средний | 310 |
| 6 | `gsc_crossrepo_secrets.py` | `gsc secrets correlate` | 🟠 SaaS | 350 |
| 7 | `gsc_scan_modes.py` | `--scan-mode quick` | — | 100 |
| 8 | `gsc_workspace.py` | `gsc workspace` | — | 260 |
| 9 | `gsc_api.py` | REST API | — | +80 |

### Полный цикл GSC

```
detect (42 детектора, ~480K находок)
  ├── prove (PoC v0.17)              [эксклюзив]
  ├── fix (Proof-of-Fix)             [эксклюзив]
  ├── verify (sandbox re-PoC)        [эксклюзив]
  ├── PR (Self-Healing CI)           [эксклюзив]
  ├── predict (Forecasting)          [эксклюзив]
  ├── archaeology (blame/history)    [эксклюзив]
  ├── policy (human-language rules)  [эксклюзив]
  └── correlate (cross-repo secrets) [эксклюзив]
```

**Ни у кого такого нет.** Semgrep, Snyk, CodeQL, Sn1per — все видят срез «сейчас». GSC видит **прошлое, настоящее и будущее** каждой уязвимости.
