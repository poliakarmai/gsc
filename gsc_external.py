#!/usr/bin/env python3
"""
GSC External Scanner — проверка внешних проектов с минимальным шумом.

Pipeline:
  clone → inventory → exclude → scan → LLM revalidate → score → report

Usage:
  gsc-external scan https://github.com/org/repo
  gsc-external scan ./local-project
  gsc-external scan-pr https://github.com/org/repo/pull/42
  gsc-external report scan-result.json --format markdown
  gsc-external feedback <finding-id> --verdict fp

Modes:
  --mode full    полный аудит репозитория
  --mode pr      только изменённые файлы (PR)
  --mode diff    новые находки относительно baseline
"""

import os, sys, json, subprocess, tempfile, shutil, re, hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict

# ── Paths ────────────────────────────────────────────────────────────────────

GSC = os.path.expanduser("~/gsc/gsc.py")
STATE_DIR = Path(os.path.expanduser("~/.hermes/state"))
DB = STATE_DIR / "gsc_audit.db"
EXTERNAL_DIR = Path(os.path.expanduser("~/.gsc/external"))
EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
CLONE_ROOT = Path("/tmp/gsc-external")

# ── Exclude policy ───────────────────────────────────────────────────────────

EXCLUDE_DIRS = {
    "tests", "test", "testing", "fixtures", "fixture",
    "examples", "example", "demo", "demos",
    "docs", "doc", "documentation",
    "migrations", "node_modules", "vendor",
    "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "env", ".tox", ".eggs",
}

EXCLUDE_FILES = {
    ".DS_Store", "Thumbs.db",
}

EXCLUDE_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

PLACEHOLDER_PATTERNS = [
    r"changeme", r"example", r"placeholder", r"your.key", r"your[-_]?token",
    r"dummy", r"fake", r"test[-_]?(key|token|secret|password)",
    r"xxx+", r"<[A-Z_]+>", r"\$\{[A-Z_]+\}", r"\{\{[A-Z_]+\}\}",
    r"__TODO__", r"FIXME", r"REPLACE_ME",
]

# ── Redaction patterns for LLM ───────────────────────────────────────────────

REDACTION_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]"),
    (r"AKIA[A-Z0-9]{16}", "[REDACTED_AWS_KEY]"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", re.DOTALL),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),
    (r'(?:password|passwd|pwd|secret|token|key|api_key)\s*[=:]\s*["\']?[^\s"\']+["\']?', "[REDACTED_CREDENTIAL]", re.IGNORECASE),
]


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    repo: str
    commit: str = ""
    branch: str = "main"
    languages: list[str] = field(default_factory=list)
    files_total: int = 0
    files_scanned: int = 0
    excluded_dirs: list[str] = field(default_factory=list)
    scan_mode: str = "full"
    started_at: str = ""
    finished_at: str = ""
    findings_total: int = 0
    findings_confirmed: int = 0
    findings_likely: int = 0
    findings_uncertain: int = 0
    findings_fp: int = 0
    llm_calls: int = 0
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = self.findings
        return d


# ── Scoring engine ───────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

def is_placeholder(text: str) -> bool:
    """Check if text contains placeholder values."""
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False

def compute_confidence(finding: dict, is_test_file: bool = False, is_config_file: bool = False) -> float:
    """
    Compute confidence score based on multiple signals.
    V2: Cross-checks LLM reasoning vs verdict — if reasoning contradicts
    'true-positive', confidence is downgraded.
    Returns 0.0–1.0.
    """
    confidence = 0.5  # Start neutral

    # LLM verdict
    verdict = finding.get("revalidation_verdict", "")
    if verdict == "true-positive":
        confidence = 0.95
    elif verdict == "false-positive":
        confidence = 0.05
    elif verdict == "fixed":
        confidence = 0.10
    elif finding.get("llm_verified") is False:
        confidence = 0.15
    elif finding.get("llm_confidence"):
        confidence = float(finding["llm_confidence"])

    # ── V2: Reasoning-verdict consistency check ──
    # KEY INSIGHT from calibration: LLM reasoning is usually correct,
    # but verdict label is often wrong. Trust reasoning over verdict.
    reasoning = (finding.get("revalidation_reasoning") or "").lower()
    
    # If no LLM revalidation was done → automatic downgrade
    if not finding.get("revalidation_verdict") and not finding.get("llm_verified"):
        confidence = 0.35  # Max "uncertain" — never "confirmed" without LLM
    
    fp_signals = [
        "safe default", "not a vulnerability", "not a security",
        "not a secret", "not a credential", "development default",
        "standard default", "localhost", "loopback", "127.0.0.1",
        "test code", "test file", "documentation", "example",
        "false positive", "not exploitable", "intended behavior",
        "correctly", "properly", "safely", "not production",
        "not real", "mislabeled", "incorrectly identifies",
        "non-issue", "by design", "expected behavior",
        "not a file upload", "not a path traversal",
        "configuration file", "not a secret", "build script",
    ]
    fp_hits = sum(1 for s in fp_signals if s in reasoning)
    
    if fp_hits >= 2:
        confidence = 0.08  # Reasoning clearly describes a FP → override
    elif fp_hits == 1 and finding.get("revalidation_verdict") == "true-positive":
        confidence *= 0.4
    elif fp_hits == 1:
        confidence = 0.15

    # Config files without secrets → downgrade
    fp = finding.get("file_path", "")
    if fp.endswith((".yaml", ".yml", ".toml", ".cfg", ".ini", ".json")):
        title = (finding.get("title") or "").lower()
        if not any(kw in title for kw in ["secret", "token", "password", "key", "credential"]):
            confidence *= 0.5

    # Downgrades
    if is_test_file:
        confidence *= 0.3
    if is_config_file:
        confidence *= 0.6

    # Placeholder signal
    detail = (finding.get("detail") or "") + (finding.get("title") or "")
    evidence = finding.get("evidence", detail)
    if is_placeholder(evidence):
        confidence *= 0.4

    # Noise tier
    if finding.get("noise_tier") == "noisy":
        confidence *= 0.7
    elif finding.get("noise_tier") == "precise":
        confidence *= 1.1

    # Extension-based downgrade
    fp = finding.get("file_path", "")
    if fp.endswith((".md", ".rst", ".txt", ".cfg", ".ini", ".toml")):
        if finding.get("category") != "CRITICAL":
            confidence *= 0.5

    return min(1.0, max(0.0, confidence))


def compute_risk_score(severity: str, confidence: float,
                       exploitability: str = "unknown",
                       reachability: str = "unknown") -> float:
    """Composite risk score 0–100."""
    sev = SEVERITY_WEIGHTS.get(severity, 1)
    exp = {"remote": 1.0, "local": 0.6, "theoretical": 0.3, "unknown": 0.5}.get(exploitability, 0.5)
    reach = {"reachable": 1.0, "unknown": 0.6, "dead": 0.2}.get(reachability, 0.6)

    raw = sev * confidence * exp * reach
    return round(min(100, raw * 10), 1)


def classify_confidence(score: float) -> str:
    """Map confidence score to verdict category."""
    if score >= 0.85:
        return "confirmed"
    elif score >= 0.65:
        return "likely"
    elif score >= 0.35:
        return "uncertain"
    return "likely-false-positive"


def risk_status(risk_score: float) -> str:
    """Human-readable risk level."""
    if risk_score >= 90:
        return "🚨 CRITICAL — confirmed"
    elif risk_score >= 70:
        return "🔴 HIGH — high priority"
    elif risk_score >= 40:
        return "🟡 MEDIUM — review needed"
    return "⚪ LOW — informational"


# ── Repository intake ────────────────────────────────────────────────────────

def detect_languages(project_path: Path) -> list[str]:
    """Detect programming languages in project."""
    exts = set()
    for f in project_path.rglob("*"):
        if f.is_file() and f.suffix:
            exts.add(f.suffix)
    mapping = {
        ".py": "python", ".go": "go", ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript", ".rs": "rust",
        ".java": "java", ".rb": "ruby", ".php": "php",
        ".c": "c", ".cpp": "cpp", ".h": "c",
        ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
    }
    langs = set()
    for ext in exts:
        if ext in mapping:
            langs.add(mapping[ext])
    return sorted(langs)


def should_exclude(file_path: Path, relative_to: Path) -> bool:
    """Check if file/dir should be excluded."""
    try:
        rel = file_path.relative_to(relative_to)
    except ValueError:
        return True

    parts = rel.parts

    # Exclude hidden dirs
    if any(p.startswith(".") for p in parts[:-1]):
        return True

    # Exclude known dirs
    if any(p in EXCLUDE_DIRS for p in parts):
        return True

    # Exclude by extension
    if file_path.suffix in EXCLUDE_EXTENSIONS:
        return True

    # Exclude by filename
    if file_path.name in EXCLUDE_FILES:
        return True

    # Exclude minified
    if ".min." in file_path.name:
        return True

    return False


def inventory_project(project_path: Path) -> tuple[int, int, list[str]]:
    """Count files: total, scanned, excluded dirs."""
    total = 0
    scanned = 0
    excluded_dirs = set()

    for f in project_path.rglob("*"):
        if not f.is_file():
            continue
        total += 1
        if should_exclude(f, project_path):
            try:
                excluded_dirs.add(str(f.relative_to(project_path).parts[0]))
            except ValueError:
                pass
        else:
            scanned += 1

    return total, scanned, sorted(excluded_dirs)


def clone_repo(url: str, ref: str = "main") -> tuple[Path, str] | None:
    """Clone a GitHub repo, return (path, commit_sha) or None."""
    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    if "/" in url:
        # Extract org/repo from URL
        parts = url.rstrip("/").split("/")
        name = parts[-1].replace(".git", "")

    target = CLONE_ROOT / name
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref,
             "--filter=blob:none", url, str(target)],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode != 0:
            print(f"Clone failed: {r.stderr[:200]}", file=sys.stderr)
            return None

        # Get commit SHA
        sha_r = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10
        )
        sha = sha_r.stdout.strip()[:12] if sha_r.returncode == 0 else "unknown"

        return target, sha
    except Exception as e:
        print(f"Clone error: {e}", file=sys.stderr)
        return None


def redact_for_llm(text: str) -> str:
    """Redact secrets before sending to LLM."""
    for pattern, replacement, *flags in REDACTION_PATTERNS:
        flag = flags[0] if flags else 0
        text = re.sub(pattern, replacement, text, flags=flag)
    return text


# ── Revalidation (LLM) ──────────────────────────────────────────────────────

def revalidate_finding(finding: dict, project_path: Path) -> dict:
    """LLM-based revalidation of a single finding. Returns updated finding."""
    result = dict(finding)

    # Only revalidate CRITICAL/HIGH
    if finding.get("category") not in ("CRITICAL", "HIGH"):
        result["revalidation_verdict"] = "uncertain"
        result["revalidation_reasoning"] = "Severity too low for LLM revalidation"
        return result

    file_path = finding.get("file_path", "")
    line = finding.get("line_number", finding.get("line", 1))
    abs_path = project_path / file_path if not file_path.startswith("/") else Path(file_path)

    if not abs_path.exists():
        result["revalidation_verdict"] = "fixed"
        result["revalidation_reasoning"] = "File no longer exists"
        return result

    # Read context
    try:
        lines = abs_path.read_text(errors="replace").split("\n")
        start = max(0, line - 10)
        end = min(len(lines), line + 10)
        snippet = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start))
    except Exception:
        snippet = ""

    # Quick heuristic checks
    fp_lower = file_path.lower()
    if any(kw in fp_lower for kw in ["/test_", "/tests/", "_test.", "/test/", "/fixtures/", "/mocks/"]):
        result["revalidation_verdict"] = "false-positive"
        result["revalidation_reasoning"] = "Test/fixture file"
        return result

    detail = (finding.get("detail") or "")
    if is_placeholder(detail):
        result["revalidation_verdict"] = "false-positive"
        result["revalidation_reasoning"] = "Placeholder value detected"
        return result

    # LLM call
    if not snippet:
        result["revalidation_verdict"] = "uncertain"
        result["revalidation_reasoning"] = "No code context available"
        return result

    try:
        import requests

        api_key = _get_api_key()
        if not api_key:
            result["revalidation_verdict"] = "uncertain"
            result["revalidation_reasoning"] = "No API key for LLM"
            return result

        safe_snippet = redact_for_llm(snippet[:2000])
        safe_detail = redact_for_llm(detail[:500])

        prompt = f"""You are a security auditor. Analyze this finding.

FINDING:
  Severity: {finding.get('category')}
  Title: {finding.get('title')}
  Detail: {safe_detail}
  File: {file_path}:{line}

CODE:
```
{safe_snippet}
```

Determine if this is a real vulnerability. Reply with JSON:
{{"verdict": "true-positive"|"false-positive"|"uncertain", "confidence": 0.0-1.0, "reasoning": "2-3 sentences"}}

RULES:
- Hardcoded localhost IP (127.0.0.1, ::1) as default → false-positive (safe default)
- Test files, examples, documentation → false-positive
- Placeholder values (changeme, example, your_key) → false-positive
- Parameterized/guarded patterns → false-positive
- CLI defaults, Click options, argparse defaults → false-positive
- Real injection, real hardcoded secrets in production code → true-positive"""

        resp = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "You are a security auditor. Reply with JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1, "max_tokens": 300,
            },
            timeout=20
        )

        if resp.status_code == 200:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            start_j = content.find("{")
            end_j = content.rfind("}") + 1
            if start_j >= 0 and end_j > start_j:
                parsed = json.loads(content[start_j:end_j])
                result["revalidation_verdict"] = parsed.get("verdict", "uncertain")
                result["llm_confidence"] = parsed.get("confidence", 0.5)
                result["revalidation_reasoning"] = parsed.get("reasoning", "")
                result["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
                return result

        result["revalidation_verdict"] = "uncertain"
        result["revalidation_reasoning"] = f"LLM HTTP {resp.status_code}"
    except Exception as e:
        result["revalidation_verdict"] = "uncertain"
        result["revalidation_reasoning"] = f"LLM error: {str(e)[:100]}"

    return result


def _get_api_key() -> str | None:
    """Get DeepSeek API key."""
    key = os.environ.get("DEEPSEEK_API_KEY")
    if key:
        return key
    for env_path in [os.path.expanduser("~/.hermes/.env"), os.path.expanduser("~/.hermes/env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path) as f:
                    for line in f:
                        if line.strip().startswith("DEEPSEEK_API_KEY="):
                            return line.split("=", 1)[1].strip().strip('"').strip("'")
            except Exception:
                pass
    return None


# ── Report generators ────────────────────────────────────────────────────────

def generate_markdown_report(result: ScanResult) -> str:
    """Generate human-readable Markdown report."""
    lines = [
        f"# 🔒 GSC Security Audit: {result.repo}",
        "",
        f"**Commit:** `{result.commit}`  ",
        f"**Branch:** `{result.branch}`  ",
        f"**Languages:** {', '.join(result.languages) or 'unknown'}  ",
        f"**Files scanned:** {result.files_scanned} / {result.files_total}  ",
        f"**Mode:** {result.scan_mode}  ",
        f"**LLM calls:** {result.llm_calls}  ",
        "",
        f"## 📊 Summary",
        "",
        f"| Category | Count |",
        f"|----------|------:|",
        f"| 🚨 Confirmed | **{result.findings_confirmed}** |",
        f"| 🔴 Likely | {result.findings_likely} |",
        f"| 🟡 Uncertain | {result.findings_uncertain} |",
        f"| ⚪ FP / Noise | {result.findings_fp} |",
        f"| **Total** | **{result.findings_total}** |",
        "",
    ]

    # Only show confirmed + likely as top risks
    top = [f for f in result.findings if f.get("confidence_score", 0) >= 0.65]
    top.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

    if top:
        lines.append("## 🔴 Top Risks")
        lines.append("")
        for i, f in enumerate(top[:15], 1):
            risk = f.get("risk_score", 0)
            status = risk_status(risk)
            lines.extend([
                f"### {i}. {f.get('title', 'Unknown')}",
                "",
                f"**{status}** — Risk Score: {risk}/100",
                "",
                f"| Property | Value |",
                f"|----------|-------|",
                f"| Severity | {f.get('category', '?')} |",
                f"| Confidence | {f.get('confidence_score', 0):.0%} |",
                f"| Rule | {f.get('rule_id', f.get('pattern_title', '?'))} |",
                f"| File | `{f.get('file_path', '?')}:{f.get('line_number', '?')}` |",
            ])
            if f.get("revalidation_reasoning"):
                lines.append(f"| Verdict | {f['revalidation_reasoning'][:200]} |")
            lines.append("")

            # Evidence
            evidence = f.get("evidence", f.get("detail", ""))
            if evidence:
                lines.extend([
                    "**Evidence:**",
                    "```python",
                    evidence[:500],
                    "```",
                    "",
                ])

    # Append uncertain findings as appendix
    uncertain = [f for f in result.findings if 0.35 <= f.get("confidence_score", 0) < 0.65]
    if uncertain:
        lines.append("---")
        lines.append("## 🟡 Appendix: Uncertain Findings")
        lines.append("")
        lines.append("These findings need manual review:")
        lines.append("")
        for f in uncertain[:20]:
            fp = f.get("file_path", "?")
            ln = f.get("line_number", "?")
            lines.append(f"- **[{f.get('category')}]** `{fp}:{ln}` — {f.get('title')}")

    lines.extend([
        "",
        "---",
        f"*Scanned by GSC External Scanner v0.1 · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
    ])
    return "\n".join(lines)


def generate_sarif(result: ScanResult) -> dict:
    """Generate SARIF 2.1.0 JSON."""
    severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

    results = []
    for f in result.findings:
        if f.get("confidence_score", 0) < 0.65:
            continue  # Only confirmed + likely
        results.append({
            "ruleId": f.get("rule_id", f.get("pattern_title", "GSC")),
            "level": severity_map.get(f.get("category", "LOW"), "warning"),
            "message": {
                "text": f"{f.get('title')}: {f.get('detail', '')}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file_path", "")},
                    "region": {"startLine": f.get("line_number", 1)}
                }
            }],
            "properties": {
                "confidence": f.get("confidence_score", 0),
                "risk_score": f.get("risk_score", 0),
                "verdict": f.get("revalidation_verdict", "unknown"),
            }
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GSC External Scanner",
                    "informationUri": "https://github.com/poliakarmai/gsc",
                    "version": "0.1.0",
                    "rules": [],
                }
            },
            "results": results,
        }]
    }


def generate_pr_comment(result: ScanResult) -> str:
    """Generate short PR comment (only high-confidence findings)."""
    confirmed = [f for f in result.findings if f.get("confidence_score", 0) >= 0.85]
    likely = [f for f in result.findings if 0.65 <= f.get("confidence_score", 0) < 0.85]

    if not confirmed and not likely:
        return "## 🔒 GSC Security Scan\n\n✅ No high-confidence security issues found."

    lines = [
        "## 🔒 GSC Security Scan",
        "",
        f"Found **{len(confirmed)} confirmed** and **{len(likely)} likely** security issues.",
        "",
    ]

    if confirmed:
        lines.append("### 🚨 Confirmed")
        lines.append("")
        lines.append("| Severity | Rule | File | Risk |")
        lines.append("|----------|------|------|------|")
        for f in confirmed[:10]:
            risk = f.get("risk_score", 0)
            lines.append(
                f"| {f.get('category', '?')} | {f.get('rule_id', '?')} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | {risk}/100 |"
            )
        lines.append("")

    if likely:
        lines.append("### ⚠️ Likely")
        lines.append("")
        lines.append("| Severity | Rule | File | Risk |")
        lines.append("|----------|------|------|------|")
        for f in likely[:5]:
            risk = f.get("risk_score", 0)
            lines.append(
                f"| {f.get('category', '?')} | {f.get('rule_id', '?')} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | {risk}/100 |"
            )

    lines.extend([
        "",
        "---",
        "*Only findings with confidence ≥ 65% are shown. Full report available via `gsc-external report`.*",
    ])
    return "\n".join(lines)


# ── Main scan pipeline ──────────────────────────────────────────────────────

def run_external_scan(target: str, mode: str = "full",
                      ref: str = "main", max_llm_calls: int = 50) -> ScanResult:
    """
    Full external scan pipeline:
    1. Clone/intake
    2. Inventory + exclude
    3. GSC scan
    4. Filter + enrich
    5. LLM revalidate (CRITICAL/HIGH only)
    6. Score
    7. Classify
    """
    result = ScanResult(
        repo=target,
        branch=ref,
        scan_mode=mode,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    # Step 1: Intake
    if target.startswith("http://") or target.startswith("https://"):
        intake = clone_repo(target, ref)
        if not intake:
            print(f"❌ Failed to clone: {target}")
            return result
        project_path, sha = intake
        result.commit = sha
    else:
        project_path = Path(target).resolve()
        if not project_path.exists():
            print(f"❌ Path not found: {target}")
            return result
        result.commit = "local"

    # Step 2: Inventory
    total, scanned, excluded = inventory_project(project_path)
    result.files_total = total
    result.files_scanned = scanned
    result.excluded_dirs = excluded
    result.languages = detect_languages(project_path)

    print(f"📁 {scanned}/{total} files ({len(excluded)} dirs excluded)")
    print(f"🔤 Languages: {', '.join(result.languages) or 'unknown'}")

    # Step 3: GSC scan
    print(f"🔍 Scanning...")
    try:
        r = subprocess.run(
            [sys.executable, GSC, "scan", str(project_path), "--json", "--ci"],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode != 0 or not r.stdout.strip():
            print(f"⚠️ Scan produced no output")
            raw_findings = []
        else:
            output = r.stdout.strip()
            start = output.find("[")
            end = output.rfind("]") + 1
            raw_findings = json.loads(output[start:end]) if start >= 0 and end > start else []
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        raw_findings = []

    print(f"   Raw findings: {len(raw_findings)}")

    # Step 4: Filter + enrich
    enriched = []
    for f in raw_findings:
        fp = f.get("file_path", "")
        # Resolve to absolute for exclude check
        fp_abs = project_path / fp if not fp.startswith("/") else Path(fp)
        if should_exclude(fp_abs, project_path):
            continue

        is_test = any(kw in fp.lower() for kw in
                      ["/test_", "/tests/", "_test.", "/test/", "/fixtures/", "/mocks/"])
        is_config = fp.lower().endswith((".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env"))

        # Skip non-code findings that are clearly noise
        if is_test and f.get("category") not in ("CRITICAL",):
            continue

        f["_is_test"] = is_test
        f["_is_config"] = is_config
        enriched.append(f)

    # Step 5: LLM revalidate (CRITICAL/HIGH only, budget-limited)
    llm_calls = 0
    for f in enriched:
        if llm_calls >= max_llm_calls:
            break
        if f.get("category") in ("CRITICAL", "HIGH"):
            updated = revalidate_finding(f, project_path)
            f.update(updated)
            llm_calls += 1

    result.llm_calls = llm_calls
    print(f"   LLM revalidated: {llm_calls} CRITICAL/HIGH findings")

    # Step 6: Score + classify
    for f in enriched:
        conf = compute_confidence(f, f.get("_is_test", False), f.get("_is_config", False))

        # Use LLM confidence if available
        if f.get("llm_confidence"):
            conf = f["llm_confidence"]

        f["confidence_score"] = round(conf, 3)

        exploitability = "remote" if "remote" in str(f.get("detail", "")).lower() else "unknown"
        f["risk_score"] = compute_risk_score(
            f.get("category", "LOW"), conf, exploitability
        )
        f["verdict"] = classify_confidence(conf)

    # Step 7: Classify counts
    result.findings = enriched
    result.findings_total = len(enriched)
    result.findings_confirmed = sum(1 for f in enriched if f.get("verdict") == "confirmed")
    result.findings_likely = sum(1 for f in enriched if f.get("verdict") == "likely")
    result.findings_uncertain = sum(1 for f in enriched if f.get("verdict") == "uncertain")
    result.findings_fp = sum(1 for f in enriched if f.get("verdict") == "likely-false-positive")
    result.finished_at = datetime.now(timezone.utc).isoformat()

    print(f"   Results: {result.findings_confirmed} confirmed, "
          f"{result.findings_likely} likely, {result.findings_uncertain} uncertain")

    # Clean up clone
    if target.startswith("http"):
        shutil.rmtree(project_path, ignore_errors=True)

    return result


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="GSC External Scanner — security audit for external projects")
    sub = p.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="Scan a repository")
    scan_p.add_argument("target", help="GitHub URL or local path")
    scan_p.add_argument("--mode", choices=["full", "pr", "diff"], default="full")
    scan_p.add_argument("--ref", default="main", help="Branch/tag")
    scan_p.add_argument("--max-llm", type=int, default=50, help="Max LLM calls")
    scan_p.add_argument("--output", "-o", help="Output JSON file")
    scan_p.add_argument("--format", choices=["json", "markdown", "sarif"], default="json",
                        help="Output format")

    # report
    report_p = sub.add_parser("report", help="Generate report from scan result")
    report_p.add_argument("input_file", help="JSON scan result")
    report_p.add_argument("--format", choices=["json", "markdown", "sarif"], required=True)
    report_p.add_argument("--output", "-o", help="Output file")

    # feedback
    fb_p = sub.add_parser("feedback", help="Record feedback on finding")
    fb_p.add_argument("finding_id", help="Finding ID")
    fb_p.add_argument("--verdict", choices=["tp", "fp", "ignore", "fixed"], required=True)
    fb_p.add_argument("--reason", help="Why")

    args = p.parse_args()

    if args.command == "scan":
        result = run_external_scan(args.target, args.mode, args.ref, args.max_llm)

        if args.format == "markdown":
            output = generate_markdown_report(result)
            ext = ".md"
        elif args.format == "sarif":
            output = json.dumps(generate_sarif(result), indent=2)
            ext = ".sarif.json"
        else:
            output = json.dumps(result.to_dict(), indent=2, default=str)
            ext = ".json"

        if args.output:
            Path(args.output).write_text(output)
            print(f"📄 Report saved: {args.output}")
        else:
            # Auto-save
            name = args.target.rstrip("/").split("/")[-1].replace(".git", "")
            out_path = EXTERNAL_DIR / f"{name}-{datetime.now().strftime('%Y%m%d-%H%M')}{ext}"
            out_path.write_text(output)
            print(f"📄 Report saved: {out_path}")

        # Quick summary
        print()
        print(generate_pr_comment(result))

    elif args.command == "report":
        data = json.loads(Path(args.input_file).read_text())
        result = ScanResult(**{k: v for k, v in data.items() if k != "findings"})
        result.findings = data.get("findings", [])

        if args.format == "markdown":
            output = generate_markdown_report(result)
        elif args.format == "sarif":
            output = json.dumps(generate_sarif(result), indent=2)
        else:
            output = json.dumps(data, indent=2)

        if args.output:
            Path(args.output).write_text(output)
            print(f"Saved: {args.output}")
        else:
            print(output)

    elif args.command == "feedback":
        # Save feedback to DB for self-learning
        db_path = str(DB)
        if os.path.exists(db_path):
            conn = __import__("sqlite3").connect(db_path)
            conn.execute("""
                UPDATE findings SET
                    status = ?,
                    detail = detail || ' [feedback: ' || ? || ']'
                WHERE id = ?
            """, (args.verdict, args.reason or "", args.finding_id))
            conn.commit()
            conn.close()
            print(f"✅ Feedback recorded: {args.finding_id} → {args.verdict}")
        else:
            # Save to external feedback file
            fb_file = EXTERNAL_DIR / "feedback.jsonl"
            fb_file.parent.mkdir(parents=True, exist_ok=True)
            with open(fb_file, "a") as f:
                f.write(json.dumps({
                    "finding_id": args.finding_id,
                    "verdict": args.verdict,
                    "reason": args.reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }) + "\n")
            print(f"✅ Feedback saved: {args.finding_id} → {args.verdict}")


if __name__ == "__main__":
    main()
