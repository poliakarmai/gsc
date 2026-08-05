#!/usr/bin/env python3
"""
GSC External Scanner v0.12 — Developer Project Reviewer.

Pipeline:
  clone → inventory → exclude → scan → LLM revalidate → V3 score → report

Profiles:
  --profile developer-review   проверка проекта разработчика
  --profile pr-gate             проверка PR (diff-only, blocking)
  --profile audit               полный аудит (deep)
  --profile candidate-review    проверка тестового задания

Usage:
  gsc external-scan https://github.com/org/repo --profile developer-review
  gsc external-scan ./project --profile pr-gate --mode diff
  gsc report scan.json --format markdown
  gsc feedback <id> --verdict fp --reason "..."
"""

import os, sys, json, subprocess, tempfile, shutil, re, hashlib
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Paths ────────────────────────────────────────────────────────────────────
GSC = os.path.expanduser("~/gsc/gsc.py")
STATE_DIR = Path(os.path.expanduser("~/.hermes/state"))
DB = STATE_DIR / "gsc_audit.db"
EXTERNAL_DIR = Path(os.path.expanduser("~/.gsc/external"))
EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)
CLONE_ROOT = Path("/tmp/gsc-external")

# ═══════════════════════════════════════════════════════════════════════════════
# PROFILES
# ═══════════════════════════════════════════════════════════════════════════════

PROFILES = {
    "developer-review": {
        "description": "Проверка проекта разработчика",
        "mode": "full",
        "llm_enabled": True,
        "llm_max_calls": 20,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.60,
        "report_formats": ["json", "markdown", "sarif"],
        "show_uncertain": False,
        "disabled_rules": ["GS003", "GS008", "GS015"],
        "review_only_rules": ["GS007", "GS012", "GS013", "GS018", "GS019", "GS023"],
    },
    "pr-gate": {
        "description": "PR проверка — только изменения, только блокирующее",
        "mode": "diff",
        "llm_enabled": True,
        "llm_max_calls": 10,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "HIGH",
        "warn_min_confidence": 0.65,
        "report_formats": ["json", "sarif", "pr_comment"],
        "show_uncertain": False,
        "disabled_rules": ["GS003", "GS008", "GS015", "GS023"],
        "review_only_rules": ["GS007", "GS012", "GS013", "GS018", "GS019"],
    },
    "audit": {
        "description": "Полный аудит — глубокий, все правила",
        "mode": "full",
        "llm_enabled": True,
        "llm_max_calls": 50,
        "llm_severities": ["CRITICAL", "HIGH", "MEDIUM"],
        "block_min_severity": "HIGH",
        "block_min_confidence": 0.80,
        "warn_min_severity": "MEDIUM",
        "warn_min_confidence": 0.55,
        "report_formats": ["json", "markdown", "sarif"],
        "show_uncertain": True,
        "disabled_rules": [],
        "review_only_rules": [],
    },
    "candidate-review": {
        "description": "Проверка тестового задания — мягкий режим",
        "mode": "full",
        "llm_enabled": True,
        "llm_max_calls": 15,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "CRITICAL",
        "block_min_confidence": 0.85,
        "warn_min_severity": "HIGH",
        "warn_min_confidence": 0.70,
        "report_formats": ["markdown", "json"],
        "show_uncertain": False,
        "disabled_rules": ["GS003", "GS008", "GS015", "GS023"],
        "review_only_rules": ["GS007", "GS012", "GS013", "GS018", "GS019", "GS021", "GS022"],
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXCLUDE POLICY
# ═══════════════════════════════════════════════════════════════════════════════

EXCLUDE_DIRS = {
    "tests", "test", "testing", "fixtures", "fixture",
    "examples", "example", "demo", "demos",
    "docs", "doc", "documentation",
    "migrations", "node_modules", "vendor",
    "dist", "build", ".git", "__pycache__",
    ".venv", "venv", "env", ".tox", ".eggs",
    "coverage", "media",
}

EXCLUDE_FILES = {".DS_Store", "Thumbs.db"}
EXCLUDE_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

SENSITIVE_FILES = {".env", ".envrc", ".secrets", "credentials.json", "secrets.yml",
                    "id_rsa", "*.pem", "*.key", "*.p12", "*.pfx"}

PLACEHOLDER_PATTERNS = [
    r"changeme", r"example", r"placeholder", r"your[-_]?key", r"your[-_]?token",
    r"dummy", r"fake", r"test[-_]?(key|token|secret|password)",
    r"xxx+", r"<[A-Z_]+>", r"\$\{[A-Z_]+\}", r"\{\{[A-Z_]+\}\}",
    r"__TODO__", r"FIXME", r"REPLACE_ME",
]

REDACTION_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED_API_KEY]"),
    (r"AKIA[A-Z0-9]{16}", "[REDACTED_AWS_KEY]"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----",
     "[REDACTED_PRIVATE_KEY]", re.DOTALL),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "[REDACTED_EMAIL]"),
    (r'(?:password|passwd|pwd|secret|token|key|api_key)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
     "[REDACTED_CREDENTIAL]", re.IGNORECASE),
]

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIDENCE V3: SIGNALS-BASED SCORING
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

TP_SIGNALS = [
    "user_input_reaches_sink", "sql_injection_confirmed", "command_injection",
    "no_parameterization", "real_hardcoded_secret", "production_config",
    "reachable_route", "secret_format_valid", "no_safe_api_used",
    "endpoint_reachable", "framework_does_not_protect", "code_not_test",
    "not_a_placeholder", "real_credential", "jwt_secret_hardcoded",
]

FP_SIGNALS = [
    "safe default", "not a vulnerability", "not a security",
    "not a secret", "not a credential", "development default",
    "standard default", "localhost", "loopback", "127.0.0.1",
    "test code", "test file", "documentation", "example",
    "false positive", "not exploitable", "intended behavior",
    "correctly", "properly", "safely", "not production",
    "not real", "mislabeled", "incorrectly identifies",
    "non-issue", "by design", "expected behavior",
    "not a file upload", "not a path traversal",
    "configuration file", "build script", "placeholder",
    "docstring", "type annotation",
]


def detect_signals(finding: dict) -> tuple[list[str], list[str]]:
    """Detect TP and FP signals from finding context + LLM reasoning."""
    tp = []
    fp = []
    text = (
        (finding.get("revalidation_reasoning") or "") + " " +
        (finding.get("title") or "") + " " +
        (finding.get("detail") or "")
    ).lower()

    for sig in TP_SIGNALS:
        if sig.replace("_", " ") in text or sig in text:
            tp.append(sig)
    for sig in FP_SIGNALS:
        if sig in text:
            fp.append(sig)

    # Context-based signals
    file_path = (finding.get("file_path") or "").lower()
    if any(kw in file_path for kw in ["/test_", "/tests/", "_test.", "/test/", "/fixtures/"]):
        fp.append("test_file")
    if file_path.endswith((".md", ".rst", ".txt")):
        fp.append("documentation_file")
    if file_path.endswith((".yaml", ".yml", ".toml", ".cfg", ".ini", ".json")):
        title = (finding.get("title") or "").lower()
        if not any(kw in title for kw in ["secret", "token", "password", "key", "credential"]):
            fp.append("config_without_secret")

    # Placeholder check
    evidence = (finding.get("detail") or "") + (finding.get("title") or "")
    if any(re.search(p, evidence, re.IGNORECASE) for p in PLACEHOLDER_PATTERNS):
        fp.append("placeholder_value")

    return tp, fp


def compute_confidence_v3(finding: dict) -> float:
    """
    V3: Signals-based confidence scoring.
    Trusts LLM reasoning + structured signals, not verdict label.
    """
    confidence = 0.35  # Start uncertain

    # LLM verdict gives base
    verdict = finding.get("revalidation_verdict", "")
    if verdict == "true-positive":
        confidence = 0.70
    elif verdict == "false-positive":
        confidence = 0.05
    elif verdict == "fixed":
        confidence = 0.10
    elif finding.get("llm_confidence"):
        confidence = float(finding["llm_confidence"])

    # No LLM → cap at uncertain
    if not finding.get("revalidation_verdict") and not finding.get("llm_verified"):
        confidence = min(confidence, 0.35)

    # Detect signals
    tp_signals, fp_signals = detect_signals(finding)

    # TP signals boost
    if len(tp_signals) >= 3:
        confidence = min(confidence + 0.25, 0.99)
    elif len(tp_signals) == 2:
        confidence = min(confidence + 0.15, 0.95)
    elif len(tp_signals) == 1:
        confidence = min(confidence + 0.05, 0.90)

    # FP signals dominate
    if len(fp_signals) >= 2:
        confidence = min(confidence, 0.08)
    elif len(fp_signals) == 1:
        confidence = min(confidence * 0.5, 0.40)

    # File context
    if "test_file" in fp_signals:
        confidence = min(confidence, 0.05)
    if "config_without_secret" in fp_signals:
        confidence = min(confidence, 0.30)
    if "documentation_file" in fp_signals:
        confidence = min(confidence, 0.10)

    # Store signals on finding
    finding["confidence_signals"] = {"tp": tp_signals, "fp": fp_signals}

    return round(max(0.0, min(1.0, confidence)), 3)


REVIEW_THRESHOLDS = {
    "confirmed": 0.80,
    "likely": 0.55,
    "uncertain": 0.35,
    # < 0.35 → false-positive
}

def review_status(confidence: float) -> str:
    for status, threshold in REVIEW_THRESHOLDS.items():
        if confidence >= threshold:
            return status
    return "false-positive"


def risk_score(severity: str, confidence: float) -> float:
    sev = SEVERITY_WEIGHTS.get(severity, 1)
    return round(min(100, sev * confidence * 10), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY-AS-CODE
# ═══════════════════════════════════════════════════════════════════════════════

def load_policy(project_path: Path) -> dict:
    """Load .gsc-audit.yml from project root, merge with profile defaults."""
    policy_file = project_path / ".gsc-audit.yml"
    if not policy_file.exists():
        return {}
    try:
        import yaml
        return yaml.safe_load(policy_file.read_text()) or {}
    except Exception:
        return {}


def merge_policy(profile_name: str, policy: dict) -> dict:
    """Merge .gsc-audit.yml overrides into profile defaults."""
    profile = dict(PROFILES.get(profile_name, PROFILES["developer-review"]))
    if not policy:
        return profile

    for key in ["llm_max_calls", "block_min_confidence", "warn_min_confidence"]:
        if key in policy:
            profile[key] = policy[key]
    for list_key in ["disabled_rules", "review_only_rules"]:
        if list_key in policy:
            profile[list_key] = list(set(profile.get(list_key, []) + policy[list_key]))
    if "exclude" in policy:
        profile["extra_exclude"] = policy["exclude"]
    return profile


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    # Meta
    repo: str
    commit: str = ""
    branch: str = "main"
    profile: str = "developer-review"
    scan_mode: str = "full"
    # Stats
    languages: list[str] = field(default_factory=list)
    files_total: int = 0
    files_scanned: int = 0
    excluded_dirs: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    # Findings
    findings_total: int = 0
    findings_blocking: int = 0
    findings_confirmed: int = 0
    findings_likely: int = 0
    findings_uncertain: int = 0
    findings_fp: int = 0
    llm_calls: int = 0
    # Policy
    policy: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = self.findings
        return d


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY
# ═══════════════════════════════════════════════════════════════════════════════

def _get_api_key() -> Optional[str]:
    # Prioritize DeepSeek direct key
    for key in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY"]:
        val = os.environ.get(key)
        if val: return val
    for env_path in [os.path.expanduser("~/.hermes/.env"), os.path.expanduser("~/.hermes/env")]:
        if not os.path.exists(env_path): continue
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(("DEEPSEEK_API_KEY=", "OPENROUTER_API_KEY=")):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception: pass
    return None


def redact(text: str) -> str:
    for pattern, replacement, *flags in REDACTION_PATTERNS:
        flag = flags[0] if flags else 0
        text = re.sub(pattern, replacement, text, flags=flag)
    return text


def should_exclude(file_path: Path, relative_to: Path) -> bool:
    try: rel = file_path.relative_to(relative_to)
    except ValueError: return True
    parts = rel.parts
    if any(p.startswith(".") for p in parts[:-1]): return True
    if any(p in EXCLUDE_DIRS for p in parts): return True
    if file_path.suffix in EXCLUDE_EXTENSIONS: return True
    if file_path.name in EXCLUDE_FILES: return True
    if ".min." in file_path.name: return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_summary(result: ScanResult) -> dict:
    """Generate summary.json."""
    blocking = [f for f in result.findings if f.get("review_status") == "confirmed"
                and f.get("category") in ("CRITICAL", "HIGH")]
    return {
        "repo": result.repo,
        "commit": result.commit,
        "profile": result.profile,
        "overall_risk": "HIGH" if len(blocking) > 0 else "MEDIUM" if result.findings_likely > 0 else "LOW",
        "findings": {
            "blocking": len(blocking),
            "confirmed": result.findings_confirmed,
            "likely": result.findings_likely,
            "uncertain": result.findings_uncertain,
            "false_positive": result.findings_fp,
            "total": result.findings_total,
        },
        "security_posture": {
            "secrets": any("GS001" in (f.get("rule_id", "") + f.get("pattern_title", ""))
                          for f in result.findings if f.get("review_status") == "confirmed"),
            "sql_injection": any("GS005" in (f.get("rule_id", "") + f.get("pattern_title", ""))
                                for f in result.findings if f.get("review_status") == "confirmed"),
            "xss": any("GS020" in (f.get("rule_id", "") + f.get("pattern_title", ""))
                      for f in result.findings if f.get("review_status") == "confirmed"),
        },
        "scanned_at": result.finished_at,
    }


def generate_markdown_report(result: ScanResult) -> str:
    """V0.12 Markdown report: Summary → Blocking → Likely → Remediation → Appendix."""
    profile = result.policy
    blocking = [f for f in result.findings
                if f.get("review_status") == "confirmed"
                and f.get("category") in ("CRITICAL", "HIGH")
                and f.get("confidence_score", 0) >= profile.get("block_min_confidence", 0.80)]
    likely = [f for f in result.findings
              if f.get("review_status") in ("confirmed", "likely")
              and f.get("confidence_score", 0) >= profile.get("warn_min_confidence", 0.55)
              and f not in blocking]
    uncertain = [f for f in result.findings
                 if f.get("review_status") == "uncertain"]

    lines = [
        f"# 🔒 GSC Developer Project Audit",
        "",
        f"**Project:** `{result.repo}`  ",
        f"**Commit:** `{result.commit}`  ",
        f"**Profile:** `{result.profile}`  ",
        f"**Languages:** {', '.join(result.languages) or 'unknown'}  ",
        f"**Files:** {result.files_scanned}/{result.files_total} scanned  ",
        f"**LLM calls:** {result.llm_calls}  ",
        f"**Date:** {result.finished_at[:19] if result.finished_at else 'N/A'}  ",
        "",
        f"## 📊 Summary",
        "",
        f"**Overall risk: {'🔴 HIGH' if len(blocking) > 0 else '🟡 MEDIUM' if result.findings_likely > 0 else '🟢 LOW'}**",
        "",
        f"| Category | Count |",
        f"|----------|------:|",
        f"| 🚨 Blocking | **{len(blocking)}** |",
        f"| 🔴 Confirmed | {result.findings_confirmed} |",
        f"| 🟡 Likely | {result.findings_likely} |",
        f"| ⚪ Uncertain | {result.findings_uncertain} |",
        f"| ✅ False Positive | {result.findings_fp} |",
        "",
    ]

    # Blocking issues
    if blocking:
        lines.append("## 🚨 Blocking Issues")
        lines.append("")
        blocking.sort(key=lambda f: f.get("risk_score", 0), reverse=True)
        for i, f in enumerate(blocking, 1):
            lines.extend(_format_finding_section(i, f, "BLOCKING"))

    # Likely issues
    if likely:
        lines.append("## 🔴 Likely Issues")
        lines.append("")
        likely.sort(key=lambda f: f.get("risk_score", 0), reverse=True)
        for i, f in enumerate(likely[:10], 1):
            lines.extend(_format_finding_section(i, f, "LIKELY"))

    # Remediation order
    if blocking or likely:
        lines.append("## 🔧 Recommended Remediation Order")
        lines.append("")
        all_risks = blocking + likely
        by_type = {}
        for f in all_risks:
            t = f.get("title", "Other")
            by_type.setdefault(t, []).append(f)
        for i, (title, finds) in enumerate(sorted(by_type.items(), key=lambda x: -len(x[1])), 1):
            lines.append(f"{i}. **{title}** — {len(finds)} finding(s)")
        lines.append("")

    # Security posture
    summary = generate_summary(result)
    lines.append("## 🛡️ Security Posture")
    lines.append("")
    for check, found in summary.get("security_posture", {}).items():
        icon = "🔴" if found else "🟢"
        lines.append(f"- {icon} **{check.replace('_', ' ').title()}**: {'Findings detected' if found else 'No issues'}")
    lines.append("")

    # Appendix: uncertain
    if uncertain and profile.get("show_uncertain", False):
        lines.append("---")
        lines.append("## ⚪ Appendix: Uncertain Findings")
        lines.append("")
        lines.append("*These findings need manual review — they may be false positives.*")
        lines.append("")
        for f in uncertain[:15]:
            fp = f.get("file_path", "?")
            ln = f.get("line_number", "?")
            lines.append(f"- **[{f.get('category')}]** `{fp}:{ln}` — {f.get('title')}")

    lines.extend([
        "",
        "---",
        f"*Scanned by GSC External Scanner v0.12 · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
    ])
    return "\n".join(lines)


def _format_finding_section(num: int, f: dict, tag: str) -> list[str]:
    lines = [
        f"### {num}. {f.get('title', 'Unknown')}",
        "",
        f"**{tag}** — Risk Score: {f.get('risk_score', 0)}/100",
        "",
        f"| Property | Value |",
        f"|----------|-------|",
        f"| Severity | {f.get('category', '?')} |",
        f"| Confidence | {f.get('confidence_score', 0):.0%} |",
        f"| Status | {f.get('review_status', '?')} |",
        f"| Rule | {f.get('rule_id') or f.get('pattern_title', '?')} |",
        f"| File | `{f.get('file_path', '?')}:{f.get('line_number', '?')}` |",
    ]
    if f.get("revalidation_reasoning"):
        lines.append(f"| Verdict | {f['revalidation_reasoning'][:200]} |")
    lines.append("")

    # Evidence
    evidence = f.get("evidence") or f.get("detail", "")
    if evidence:
        lines.extend(["**Evidence:**", "```", evidence[:500], "```", ""])

    # Signals
    signals = f.get("confidence_signals", {})
    if signals.get("tp") or signals.get("fp"):
        lines.append(f"**Signals:** TP={signals.get('tp', [])}, FP={signals.get('fp', [])}")
        lines.append("")

    return lines


def generate_sarif(result: ScanResult) -> dict:
    severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    results = []
    for f in result.findings:
        if f.get("review_status") not in ("confirmed", "likely"):
            continue
        results.append({
            "ruleId": f.get("rule_id") or f.get("pattern_title", "GSC"),
            "level": severity_map.get(f.get("category", "LOW"), "warning"),
            "message": {"text": redact(f"{f.get('title')}: {f.get('detail', '')}")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("file_path", "")},
                "region": {"startLine": f.get("line_number", 1)}
            }}],
            "properties": {
                "confidence": f.get("confidence_score", 0),
                "risk_score": f.get("risk_score", 0),
                "review_status": f.get("review_status", "unknown"),
                "security-severity": f.get("risk_score", 0) / 100,
            },
            "partialFingerprints": {
                "primary": hashlib.sha256(
                    f"{f.get('file_path')}:{f.get('line_number')}:{f.get('title')}".encode()
                ).hexdigest()[:32]
            }
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "GSC External Scanner",
            "informationUri": "https://github.com/poliakarmai/gsc",
            "version": "0.12.0",
            "rules": [],
        }}, "results": results}]
    }


def generate_pr_comment(result: ScanResult) -> str:
    profile = result.policy
    blocking = [f for f in result.findings
                if f.get("review_status") == "confirmed"
                and f.get("category") in ("CRITICAL", "HIGH")
                and f.get("confidence_score", 0) >= profile.get("block_min_confidence", 0.80)]
    warnings = [f for f in result.findings
                if f.get("review_status") in ("confirmed", "likely")
                and f.get("confidence_score", 0) >= profile.get("warn_min_confidence", 0.55)
                and f not in blocking]

    if not blocking and not warnings:
        return "## 🔒 GSC Security Scan\n\n✅ No high-confidence security issues found in this PR."

    lines = [
        "## 🔒 GSC Security Scan",
        "",
        f"**Profile:** `{result.profile}` · **Commit:** `{result.commit}`",
        f"**Blocking:** {len(blocking)} · **Warnings:** {len(warnings)}",
        "",
    ]
    if blocking:
        lines.append("### 🚨 Blocking")
        lines.append("| Severity | Rule | File | Confidence | Risk |")
        lines.append("|----------|------|------|:----------:|:----:|")
        for f in blocking[:10]:
            lines.append(
                f"| {f.get('category')} | {f.get('rule_id') or f.get('pattern_title', '?')} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | "
                f"{f.get('confidence_score', 0):.0%} | {f.get('risk_score', 0)}/100 |"
            )
        lines.append("")

    if warnings:
        lines.append("### ⚠️ Warnings")
        lines.append("| Severity | Rule | File | Confidence | Risk |")
        lines.append("|----------|------|------|:----------:|:----:|")
        for f in warnings[:5]:
            lines.append(
                f"| {f.get('category')} | {f.get('rule_id') or f.get('pattern_title', '?')} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | "
                f"{f.get('confidence_score', 0):.0%} | {f.get('risk_score', 0)}/100 |"
            )

    lines.extend([
        "",
        "---",
        "*Blocking rules: severity ≥ HIGH, confidence ≥ 80%. Review more at gsc report.*",
    ])
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def run_external_scan(target: str, profile_name: str = "developer-review",
                      mode: str = "full", ref: str = "main") -> ScanResult:
    policy = PROFILES.get(profile_name, PROFILES["developer-review"])
    mode = mode or policy.get("mode", "full")

    result = ScanResult(
        repo=target, profile=profile_name, scan_mode=mode,
        branch=ref, policy=policy,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    # Step 1: Intake
    if target.startswith("http"):
        name = target.rstrip("/").split("/")[-1].replace(".git", "")
        target_path = CLONE_ROOT / name
        if target_path.exists():
            shutil.rmtree(target_path, ignore_errors=True)
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, "--filter=blob:none", target, str(target_path)],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode != 0:
            # Try default branch
            r2 = subprocess.run(
                ["git", "clone", "--depth", "1", "--filter=blob:none", target, str(target_path)],
                capture_output=True, text=True, timeout=300
            )
            if r2.returncode != 0:
                print(f"❌ Clone failed: {r.stderr[:200]}")
                return result
        sha_r = subprocess.run(["git", "-C", str(target_path), "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=10)
        result.commit = sha_r.stdout.strip()[:12] if sha_r.returncode == 0 else "unknown"
    else:
        target_path = Path(target).resolve()
        if not target_path.exists():
            print(f"❌ Path not found: {target}")
            return result
        result.commit = "local"

    # Load project policy
    project_policy = load_policy(target_path)
    policy = merge_policy(profile_name, project_policy)
    result.policy = policy

    # Step 2: Inventory
    total = scanned = 0
    excluded = set()
    for f in target_path.rglob("*"):
        if f.is_file():
            total += 1
            if should_exclude(f, target_path):
                try: excluded.add(str(f.relative_to(target_path).parts[0]))
                except ValueError: pass
            else:
                scanned += 1
    result.files_total = total
    result.files_scanned = scanned
    result.excluded_dirs = sorted(excluded)
    result.languages = sorted(set(
        {".py": "python", ".go": "go", ".ts": "typescript", ".js": "javascript",
         ".rs": "rust", ".java": "java", ".rb": "ruby"}.get(f.suffix, "")
        for f in target_path.rglob("*") if f.is_file() and f.suffix
    ) - {""})

    print(f"📁 {scanned}/{total} files ({len(excluded)} dirs excluded)")
    print(f"🔤 Languages: {', '.join(result.languages) or 'unknown'}")
    print(f"📋 Profile: {profile_name} | Mode: {mode}")

    # Step 3: GSC scan
    print(f"🔍 Scanning...")
    raw_findings = []
    try:
        r = subprocess.run(
            [sys.executable, GSC, "scan", str(target_path), "--json", "--ci"],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode == 0 and r.stdout.strip():
            output = r.stdout.strip()
            start = output.find("[")
            end = output.rfind("]") + 1
            if start >= 0 and end > start:
                raw_findings = json.loads(output[start:end])
    except Exception:
        pass
    print(f"   Raw findings: {len(raw_findings)}")

    # Step 4: Filter + LLM revalidate (CRITICAL first)
    max_llm = policy.get("llm_max_calls", 20)
    llm_calls = 0
    enriched = []

    # Sort: CRITICAL first for LLM budget
    def _sort_key(f):
        sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sev.get(f.get("category", "LOW"), 4)
    raw_findings.sort(key=_sort_key)

    for f in raw_findings:
        fp = f.get("file_path", "")
        fp_abs = target_path / fp if not fp.startswith("/") else Path(fp)
        if should_exclude(fp_abs, target_path):
            continue
        # Skip disabled rules
        rule = f.get("rule_id") or f.get("pattern_title", "")
        if rule in policy.get("disabled_rules", []):
            continue
        # LLM revalidate
        if policy.get("llm_enabled") and llm_calls < max_llm:
            if f.get("category") in policy.get("llm_severities", ["CRITICAL", "HIGH"]):
                f = _revalidate(f, target_path)
                llm_calls += 1
        enriched.append(f)

    result.llm_calls = llm_calls
    print(f"   LLM revalidated: {llm_calls}")

    # Step 5: V3 Scoring
    for f in enriched:
        conf = compute_confidence_v3(f)
        f["confidence_score"] = conf
        f["review_status"] = review_status(conf)
        f["risk_score"] = risk_score(f.get("category", "LOW"), conf)

    # Step 6: Classify
    result.findings = enriched
    result.findings_total = len(enriched)
    result.findings_confirmed = sum(1 for f in enriched if f.get("review_status") == "confirmed")
    result.findings_likely = sum(1 for f in enriched if f.get("review_status") == "likely")
    result.findings_uncertain = sum(1 for f in enriched if f.get("review_status") == "uncertain")
    result.findings_fp = sum(1 for f in enriched if f.get("review_status") == "false-positive")
    result.findings_blocking = sum(
        1 for f in enriched
        if f.get("review_status") == "confirmed"
        and f.get("category") in ("CRITICAL", "HIGH")
        and f.get("confidence_score", 0) >= policy.get("block_min_confidence", 0.80)
    )
    result.finished_at = datetime.now(timezone.utc).isoformat()

    print(f"   Results: {result.findings_blocking} blocking, "
          f"{result.findings_confirmed} confirmed, {result.findings_likely} likely")

    if target.startswith("http"):
        shutil.rmtree(target_path, ignore_errors=True)

    return result


def _revalidate(finding: dict, project_path: Path) -> dict:
    f = dict(finding)
    if f.get("category") not in ("CRITICAL", "HIGH"):
        return f

    fp = f.get("file_path", "")
    line = f.get("line_number", f.get("line", 1))
    abs_path = project_path / fp if not fp.startswith("/") else Path(fp)
    if not abs_path.exists():
        f["revalidation_verdict"] = "fixed"
        f["revalidation_reasoning"] = "File removed"
        return f

    try:
        lines = abs_path.read_text(errors="replace").split("\n")
        start = max(0, line - 10)
        end = min(len(lines), line + 10)
        snippet = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start))
    except Exception:
        snippet = ""

    fp_lower = fp.lower()
    if any(kw in fp_lower for kw in ["/test_", "/tests/", "_test.", "/test/", "/fixtures/"]):
        f["revalidation_verdict"] = "false-positive"
        f["revalidation_reasoning"] = "Test file"
        return f

    if not snippet:
        return f

    api_key = _get_api_key()
    if not api_key:
        return f

    # Detect provider by key prefix
    if api_key.startswith("sk-or-"):
        api_url = "https://openrouter.ai/api/v1/chat/completions"
        model = "deepseek/deepseek-chat"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/poliakarmai/gsc",
            "X-Title": "GSC-External",
        }
    else:
        api_url = "https://api.deepseek.com/v1/chat/completions"
        model = "deepseek-chat"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    try:
        import requests
        safe_snippet = redact(snippet[:2000])
        safe_detail = redact((f.get("detail") or "")[:500])

        prompt = f"""Security audit. Is this a real vulnerability?

FINDING: {f.get('category')} — {f.get('title')}
Detail: {safe_detail}
File: {fp}:{line}

CODE:
```
{safe_snippet}
```

Reply JSON: {{"verdict":"true-positive"|"false-positive"|"uncertain","confidence":0.0-1.0,"reasoning":"2-3 sentences"}}

RULES: localhost/127.0.0.1 defaults → false-positive. Test files/docs → false-positive. Placeholders → false-positive. Real secrets/injection in production code → true-positive."""

        resp = requests.post(
            api_url,
            headers=headers,
            json={"model": model, "messages": [
                {"role": "system", "content": "Security auditor. JSON only."},
                {"role": "user", "content": prompt},
            ], "temperature": 0.1, "max_tokens": 300},
            timeout=20
        )
        if resp.status_code == 200:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            sj, ej = content.find("{"), content.rfind("}") + 1
            if sj >= 0 and ej > sj:
                parsed = json.loads(content[sj:ej])
                f["revalidation_verdict"] = parsed.get("verdict", "uncertain")
                f["llm_confidence"] = parsed.get("confidence", 0.5)
                f["revalidation_reasoning"] = parsed.get("reasoning", "")
                f["revalidation_checked_at"] = datetime.now(timezone.utc).isoformat()
                return f
    except Exception:
        pass
    return f


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC External Scanner v0.12 — Developer Project Reviewer")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository")
    scan.add_argument("target", help="GitHub URL or local path")
    scan.add_argument("--profile", choices=list(PROFILES.keys()), default="developer-review")
    scan.add_argument("--mode", choices=["full", "diff", "pr"])
    scan.add_argument("--ref", default="main")
    scan.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    scan.add_argument("--output", "-o", help="Output file or directory")

    report = sub.add_parser("report", help="Generate report from JSON")
    report.add_argument("input_file")
    report.add_argument("--format", choices=["json", "markdown", "sarif", "pr_comment"], required=True)
    report.add_argument("--output", "-o")

    fb = sub.add_parser("feedback", help="Record feedback")
    fb.add_argument("finding_id")
    fb.add_argument("--verdict", choices=["tp", "fp", "ignore", "fixed"], required=True)
    fb.add_argument("--reason")

    args = p.parse_args()

    if args.command == "scan":
        result = run_external_scan(args.target, args.profile, args.mode, args.ref)

        # Output directory
        name = args.target.rstrip("/").split("/")[-1].replace(".git", "")
        out_dir = EXTERNAL_DIR / name / datetime.now().strftime("%Y-%m-%d_%H%M")
        if args.output:
            out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Save artifacts
        fmt = args.format
        if fmt == "markdown":
            md = generate_markdown_report(result)
            (out_dir / "report.md").write_text(md)
            print(f"📄 {out_dir}/report.md")
        elif fmt == "sarif":
            sarif = generate_sarif(result)
            (out_dir / "report.sarif.json").write_text(json.dumps(sarif, indent=2))
            print(f"📄 {out_dir}/report.sarif.json")

        # Always save JSON + summary
        (out_dir / "scan.json").write_text(json.dumps(result.to_dict(), indent=2, default=str))
        summary = generate_summary(result)
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"📄 {out_dir}/scan.json")
        print(f"📄 {out_dir}/summary.json")

        # PR comment to stdout
        print()
        print(generate_pr_comment(result))

    elif args.command == "report":
        data = json.loads(Path(args.input_file).read_text())
        result = ScanResult(**{k: v for k, v in data.items() if k != "findings"})
        result.findings = data.get("findings", [])

        if args.format == "markdown":
            out = generate_markdown_report(result)
        elif args.format == "sarif":
            out = json.dumps(generate_sarif(result), indent=2)
        elif args.format == "pr_comment":
            out = generate_pr_comment(result)
        else:
            out = json.dumps(data, indent=2)

        if args.output:
            Path(args.output).write_text(out)
            print(f"Saved: {args.output}")
        else:
            print(out)

    elif args.command == "feedback":
        import sqlite3
        fb_file = EXTERNAL_DIR / "feedback.jsonl"
        entry = {
            "finding_id": args.finding_id,
            "verdict": args.verdict,
            "reason": args.reason or "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(fb_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
        # Update DB if available
        if DB.exists():
            conn = sqlite3.connect(str(DB))
            conn.execute("UPDATE findings SET status=? WHERE id=?",
                         (args.verdict, args.finding_id))
            conn.commit()
            conn.close()
        print(f"✅ Feedback: {args.finding_id} → {args.verdict}")


if __name__ == "__main__":
    main()
