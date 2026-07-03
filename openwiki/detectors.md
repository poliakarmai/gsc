# Detectors (GS001–GS016)

GSC has 15 plugin detectors. Each detector is a self-contained module in `/gsc_detectors/` that exports `detect(ctx) -> list[Finding]`. Detectors are organized by **noise tier** (precise/normal/noisy) and assigned to an **echelon** (1/2/3) which determines when they run in the scan pipeline.

## Detector Quick Reference

| Rule | Source | Echelon | Tier | Severity | Category |
|------|--------|---------|------|----------|----------|
| GS001 | `/gsc_detectors/gs001_hardcoded_secret.py` | 1 | precise | CRITICAL | Hardcoded secrets |
| GS002 | `/gsc_detectors/gs002_world_readable.py` | 2 | normal | HIGH | File permissions |
| GS003 | `/gsc_detectors/gs003_debug_prints.py` | 2 | normal | LOW | Debug code |
| GS004 | `/gsc_detectors/gs004_dangerous_subprocess.py` | 1 | precise | HIGH | Dangerous subprocess |
| GS005 | `/gsc_detectors/gs005_sql_injection.py` | 2 | precise | CRITICAL | SQL/NoSQL injection |
| GS007 | `/gsc_detectors/gs007_idor.py` | 2 | normal | HIGH | IDOR |
| GS008 | `/gsc_detectors/gs008_dead_code.py` | 2 | normal | LOW | Dead code |
| GS009 | `/gsc_detectors/gs009_supply_chain.py` | 2 | normal | HIGH | Supply chain |
| GS010 | `/gsc_detectors/gs010_ssh_hardening.py` | 1 | precise | CRITICAL | SSH config |
| GS011 | `/gsc_detectors/gs011_jwt_vulnerabilities.py` | 1 | precise | CRITICAL | JWT |
| GS012 | `/gsc_detectors/gs012_mass_assignment.py` | 2 | normal | HIGH | Mass Assignment |
| GS013 | `/gsc_detectors/gs013_graphql_security.py` | 2 | normal | HIGH | GraphQL |
| GS014 | `/gsc_detectors/gs014_credential_exposure.py` | 1 | precise | HIGH | Credential exposure |
| GS015 | `/gsc_detectors/gs015_entry_points.py` | 3 | noisy | INFO | Entry-point coverage |
| GS016 | `/gsc_detectors/gs016_linux_priv_esc.py` | 2 | normal | HIGH | Linux priv esc |

## Detector Details

### GS001 — Hardcoded Secrets (precise, CRITICAL)

Detects API keys, passwords, tokens, JWT, and connection strings in source code. Uses regex patterns targeting common secret formats:

- API keys (`api_key`, `api_secret`, `API_KEY`)
- AWS Access Key IDs (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- JWT tokens (`eyJ...`)
- Connection strings (`mongodb://`, `mysql://`, `postgresql://`)
- Generic password assignments

**Influenced by**: OWASP CVE Lite OA001-orphaned-target pattern.  
**FP handling**: framework-aware filter skips key generation utilities.

### GS002 — World-Readable Files (normal, HIGH)

Checks file permissions on sensitive files (`.pem`, `.key`, `.env`, credentials files). Flags files that are world-readable when they contain secrets.

**Detection method**: `os.stat()` permission check.

### GS003 — Debug Prints (normal, LOW)

Flags `print()`/`console.log()` statements in files that are likely production code (not test files, not CLI tools using `click`/`typer`/`fire`).

**FP handling**: framework-aware filter skips CLI tools.

### GS004 — Dangerous Subprocess (precise, HIGH)

Flags dangerous code execution patterns:
- `os.system()`, `subprocess.run(..., shell=True)`
- `eval()`, `exec()`, `compile()` with untrusted input
- `pickle.loads()`, `yaml.load()` (unsafe deserialization)
- `__import__()`, `importlib.import_module()`

### GS005 — SQL/NoSQL Injection (precise, CRITICAL)

The most complex detector (19KB). Multi-language coverage for **Python, Ruby, JS/TS, PHP, Java, Go, C#, Rust**.

Detection categories:
- **String interpolation in SQL** (f-strings, `%`, `.format`, `+` concat)
- **UNION-based injection** (`SELECT ... UNION SELECT`)
- **Boolean-based blind** (`OR '1'='1`, `AND 1=1`)
- **Time-based blind** (`SLEEP`, `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK`)
- **Stacked queries** (multiple `;`-separated statements)
- **Second-order injection** (DB fetch → unsanitized query)
- **NoSQL injection** (MongoDB `$where`/`$regex`, DynamoDB filter expressions)
- **ORM anti-patterns** (Django `raw`/`extra`/`RawSQL`, SQLAlchemy `text`/`literal`, Sequelize)

Corpus tests exist for JS, PHP, Python, and Ruby variants.

### GS007 — IDOR / Missing Auth (normal, HIGH)

Finds missing authorization and ownership checks in Django, Rails, FastAPI, and other web frameworks. Experimental — looks for patterns like creating/updating objects without verifying user ownership.

### GS008 — Dead Code (normal, LOW)

Detects constants and feature flags that are declared but never referenced anywhere in the codebase.

### GS009 — Supply Chain (normal, HIGH)

"Bumblebee" scanner — checks for malicious or risky packages in:
- **npm** (`package.json`)
- **PyPI** (`requirements.txt`, `Pipfile`, `pyproject.toml`)
- **Go** (`go.mod`)
- **MCP** (Model Context Protocol extensions)
- **Editor extensions** (VSCode, JetBrains)

### GS010 — SSH Hardening (precise, CRITICAL)

Checks `sshd_config` for weak settings:
- `PermitRootLogin yes`
- `PasswordAuthentication yes`
- `LD_PRELOAD` abuse potential
- `X11Forwarding yes`
- Weak ciphers, MACs, and key exchange algorithms

**Trained on**: Redteam Kit (22 sources including SSH Hardening guide).

### GS011 — JWT Vulnerabilities (precise, CRITICAL)

Detects:
- `alg: none` or `alg: None` in JWT configuration
- `jwt.decode(..., verify=False)` 
- Hardcoded JWT secrets (`"my_secret"`, `"secret123"`)
- Weak or predictable signing keys

### GS012 — Mass Assignment (normal, HIGH)

Detects mass assignment vulnerabilities in:
- **Django**: `**request.POST`, `**request.data`
- **FastAPI**: `**body`, `**request`
- **Rails**: `params` (without strong params)
- **GraphQL**: mutations with unrestricted arguments

### GS013 — GraphQL Security (normal, HIGH)

Detects:
- Introspection queries enabled in production
- Depth limiting not configured
- Error disclosure (stack traces in errors)
- GraphiQL IDE enabled in production

### GS014 — Credential Exposure (precise, HIGH)

Finds:
- SAM (Security Account Manager) references
- DPAPI (Data Protection API) misuse
- `unattend.xml` files with passwords
- `sudoers` entries with `NOPASSWD`
- Windows credential manager access

**Trained on**: Redteam Kit (22 sources).

### GS015 — Entry Points (noisy, INFO)

Broad matcher — finds all HTTP handler registrations across web frameworks (FastAPI, Flask, Django, Sanic, Tornado, aiohttp). Useful for attack surface mapping rather than vulnerability detection.

**Not a security finding by itself** — used for coverage analysis.

### GS016 — Linux Privilege Escalation (normal, HIGH)

Detects patterns commonly used in Linux privilege escalation:
- SUID/SGID binaries
- Writable cron jobs
- Writable systemd service files
- `PATH` hijacking opportunities
- Sudo rule bypasses
- Kernel module loading

**Added**: Latest in the detector family, inspired by GTFO bins and LinPEAS.

## LLM Verify

`/gsc_detectors/llm_verify.py` is not a regular detector but a post-processing step. It takes CRITICAL/HIGH findings and sends them to an LLM for second-opinion validation. If the LLM says the finding is not exploitable in context, the finding is marked as `llm_verified: false`.

## Inline Suppression

Findings can be suppressed per-line with:
```python
risky_code()  # gsc:ignore
risky_code()  # nosec
```

Supports `# gsc:ignore`, `// gsc:ignore`, `-- gsc:ignore` for multiple languages.

## Adding a New Detector

1. Create `/gsc_detectors/gs0XX_your_detector.py` with required exports (`RULE_ID`, `ECHELON`, `NOISE_TIER`, `description`, `detect()`)
2. Add import + `DetectorEntry` in `/gsc_detectors/registry.py`
3. Add seed patterns in `/patterns/` JSON
4. Add corpus test in `/tests/test_corpus.py`
5. Run tests: `python3 tests/test_corpus.py`
