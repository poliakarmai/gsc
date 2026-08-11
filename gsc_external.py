# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
# Copyright (c) 2024-2026 Алексей Поляков
# Licensed under Polyform Shield 1.0.0 — see LICENSE for details.
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
        "chain_budget": 5,
        "poc_budget": 5,
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
        "chain_budget": 3,
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
        "chain_budget": 10,
    },
    "precision-hunt": {
        "description": "Охота за уязвимостями — только высокоточные детекторы (FP < 50%)",
        "mode": "full",
        "llm_enabled": True,
        "llm_max_calls": 20,
        "llm_severities": ["CRITICAL", "HIGH"],
        "block_min_severity": "CRITICAL",
        "block_min_confidence": 0.85,
        "warn_min_severity": "HIGH",
        "warn_min_confidence": 0.70,
        "report_formats": ["json"],
        "show_uncertain": False,
        # Disabled: only the absolute noisiest detectors for external projects
        "disabled_rules": [
            "GS000",           # LEGACY catch-all — pattern-based, needs context
        ],
        # Review-only: medium-noise, flag but don't treat as blocking
        "review_only_rules": [
            "GS007", "GS012", "GS013",
            "GS018", "GS019", "GS015",   # GS015: entry-point coverage (INFO-level)
        ],
        "chain_budget": 0,
        "poc_budget": 0,
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
        "chain_budget": 3,
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
    """Merge .gsc-audit.yml overrides into profile defaults. Supports rollout_phase."""
    profile = dict(PROFILES.get(profile_name, PROFILES["developer-review"]))
    if not policy:
        return profile

    for key in ["llm_max_calls", "block_min_confidence", "warn_min_confidence"]:
        if key in policy:
            profile[key] = policy[key]
    # Support nested thresholds block
    if "thresholds" in policy and isinstance(policy["thresholds"], dict):
        for key in ["block_min_confidence", "warn_min_confidence"]:
            if key in policy["thresholds"]:
                profile[key] = policy["thresholds"][key]
    for list_key in ["disabled_rules", "review_only_rules"]:
        if list_key in policy:
            profile[list_key] = list(set(profile.get(list_key, []) + policy[list_key]))
    # Support nested rules block: GS003: {enabled: false} → disabled_rules
    if "rules" in policy and isinstance(policy["rules"], dict):
        for rule_id, rule_cfg in policy["rules"].items():
            if isinstance(rule_cfg, dict) and rule_cfg.get("enabled") is False:
                if "disabled_rules" not in profile:
                    profile["disabled_rules"] = []
                if rule_id not in profile["disabled_rules"]:
                    profile["disabled_rules"].append(rule_id)
    if "exclude" in policy:
        profile["extra_exclude"] = policy["exclude"]

    # Rollout phase overrides
    phase = policy.get("rollout_phase", profile.get("rollout_phase", "standard"))
    profile["rollout_phase"] = phase
    if phase == "warn-only":
        profile["fail_on_blocking"] = False
    elif phase == "blocking-critical":
        profile["block_min_severity"] = "CRITICAL"
        profile["block_min_confidence"] = max(profile.get("block_min_confidence", 0.80), 0.90)
    elif phase == "blocking-standard":
        profile["block_min_severity"] = "HIGH"
        profile["block_min_confidence"] = max(profile.get("block_min_confidence", 0.80), 0.85)

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
    # Phase 1
    dry_run: bool = False
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
# DIFF MODE (v0.13)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DiffContext:
    base_ref: str = "main"
    head_ref: str = "HEAD"
    changed_files: list[str] = field(default_factory=list)
    added_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)

@dataclass
class DiffResult:
    new_findings: list[dict] = field(default_factory=list)
    unchanged_findings: list[dict] = field(default_factory=list)
    fixed_findings: list[dict] = field(default_factory=list)
    blocking_findings: list[dict] = field(default_factory=list)
    warning_findings: list[dict] = field(default_factory=list)


def _normalize_snippet(snippet: str) -> str:
    """Normalize code snippet for soft fingerprinting — resistant to line moves."""
    s = re.sub(r'#.*$', '', snippet, flags=re.MULTILINE)   # strip comments
    s = re.sub(r'\s+', ' ', s)                                # collapse whitespace
    s = re.sub(r'["\'][^"\']*["\']', '"..."', s)             # normalize string literals
    return s.strip()


def fingerprint_finding(f: dict, soft: bool = False) -> str:
    """Stable fingerprint: sha256(rule_id + file + snippet). Soft mode ignores line numbers."""
    rule = f.get("rule_id") or f.get("pattern_title", "?")
    fp = f.get("file_path", "?")
    snippet = (f.get("detail") or f.get("title") or "")[:200]
    if soft:
        snippet = _normalize_snippet(snippet)
        key = f"{rule}|{fp}|{snippet}"
    else:
        line = f.get("line_number", f.get("line", 0))
        key = f"{rule}|{fp}|{line}|{snippet}"
    return hashlib.sha256(key.encode()).hexdigest()[:40]


def collect_changed_files(repo_path: Path, base: str = "main", head: str = "HEAD") -> DiffContext:
    """Get list of changed files between base and head."""
    ctx = DiffContext(base_ref=base, head_ref=head)
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "--name-status", f"{base}...{head}"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            r = subprocess.run(
                ["git", "-C", str(repo_path), "diff", "--name-status", base, head],
                capture_output=True, text=True, timeout=30
            )
        for line in r.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split("\t", 1)
            if len(parts) < 2: continue
            status, fname = parts[0][0], parts[1]
            ctx.changed_files.append(fname)
            if status == "A": ctx.added_files.append(fname)
            elif status == "D": ctx.deleted_files.append(fname)
            else: ctx.modified_files.append(fname)
    except Exception:
        pass
    return ctx


def build_base_baseline(repo_path: Path, diff_ctx: DiffContext) -> set[str]:
    """Scan base commit's changed files for fingerprints — without LLM."""
    fingerprints = set()
    base = diff_ctx.base_ref

    # Stash current changes, checkout base
    try:
        subprocess.run(["git", "-C", str(repo_path), "stash", "--include-untracked"],
                       capture_output=True, timeout=15)
        subprocess.run(["git", "-C", str(repo_path), "checkout", base],
                       capture_output=True, timeout=30)

        # Scan only changed files from base perspective
        for fname in diff_ctx.changed_files:
            fpath = repo_path / fname
            if not fpath.exists() or not fpath.is_file():
                continue
            if should_exclude(fpath, repo_path):
                continue
            try:
                r = subprocess.run(
                    [sys.executable, GSC, "scan", str(repo_path),
                     "--json", "--ci", "--files", fname],
                    capture_output=True, text=True, timeout=60
                )
                if r.returncode == 0 and r.stdout.strip():
                    output = r.stdout.strip()
                    sj, ej = output.find("["), output.rfind("]") + 1
                    if sj >= 0 and ej > sj:
                        findings = json.loads(output[sj:ej])
                        for f in findings:
                            fingerprints.add(fingerprint_finding(f, soft=True))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        # Restore
        try:
            subprocess.run(["git", "-C", str(repo_path), "checkout", "-"],
                           capture_output=True, timeout=30)
            subprocess.run(["git", "-C", str(repo_path), "stash", "pop"],
                           capture_output=True, timeout=15)
        except Exception:
            pass

    return fingerprints


def compare_findings(head_findings: list[dict], base_fingerprints: set[str],
                     policy: dict) -> DiffResult:
    """Compare head findings against base fingerprints. Returns DiffResult."""
    result = DiffResult()
    head_fps = {}

    for f in head_findings:
        soft_fp = fingerprint_finding(f, soft=True)
        exact_fp = fingerprint_finding(f, soft=False)
        f["_fingerprint"] = exact_fp
        f["_soft_fingerprint"] = soft_fp
        head_fps[soft_fp] = f

    for f in head_findings:
        soft_fp = f.get("_soft_fingerprint", "")
        if soft_fp in base_fingerprints:
            result.unchanged_findings.append(f)
        else:
            result.new_findings.append(f)

    # Fixed = was in base, not in head
    head_soft = {fingerprint_finding(f, soft=True) for f in head_findings}
    for bfp in base_fingerprints:
        if bfp not in head_soft:
            result.fixed_findings.append({"_fingerprint": bfp, "_status": "fixed"})

    # Classify new findings
    block_sev = policy.get("block_min_severity", "HIGH")
    block_conf = policy.get("block_min_confidence", 0.80)
    warn_conf = policy.get("warn_min_confidence", 0.55)

    for f in result.new_findings:
        rs = f.get("review_status", "")
        sev = f.get("category", "LOW")
        conf = f.get("confidence_score", 0)
        if rs == "confirmed" and sev in ("CRITICAL", "HIGH") and conf >= block_conf:
            result.blocking_findings.append(f)
        elif rs in ("confirmed", "likely") and conf >= warn_conf:
            result.warning_findings.append(f)

    return result


def generate_pr_diff_comment(result: ScanResult, diff: DiffResult, diff_ctx: DiffContext) -> str:
    """PR comment for diff mode — shows only new/fixed findings."""
    if not diff.blocking_findings and not diff.warning_findings:
        return (
            f"## 🔒 GSC Security Scan\n\n"
            f"**Profile:** `{result.profile}` · Base: `{diff_ctx.base_ref}` → Head: `{diff_ctx.head_ref}`\n"
            f"**Changed:** {len(diff_ctx.changed_files)} files · "
            f"**New findings:** {len(diff.new_findings)}\n\n"
            f"✅ No blocking or warning findings in this PR.\n\n"
            f"{'🔧 **Fixed:** ' + str(len(diff.fixed_findings)) + ' finding(s)' if diff.fixed_findings else ''}"
        )

    lines = [
        f"## 🔒 GSC Security Scan",
        "",
        f"**Profile:** `{result.profile}` · "
        f"Base: `{diff_ctx.base_ref}` → Head: `{diff_ctx.head_ref}`",
        f"**Changed:** {len(diff_ctx.changed_files)} files · "
        f"**New:** {len(diff.new_findings)} · "
        f"**Blocking:** {len(diff.blocking_findings)} · "
        f"**Warnings:** {len(diff.warning_findings)}",
    ]
    if diff.fixed_findings:
        lines.append(f"**Fixed:** {len(diff.fixed_findings)}")

    lines.append("")

    if diff.blocking_findings:
        lines.append("### 🚨 Blocking")
        lines.append("| ID | Rule | Severity | Confidence | File | Risk |")
        lines.append("|----|------|----------|:----------:|------|:----:|")
        for f in diff.blocking_findings[:10]:
            lines.append(
                f"| `{f.get('finding_key', '?')}` | {f.get('rule_id') or f.get('pattern_title', '?')} | "
                f"{f.get('category')} | {f.get('confidence_score', 0):.0%} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | "
                f"{f.get('risk_score', 0)}/100 |"
            )
        lines.append("")

    if diff.warning_findings:
        lines.append("### ⚠️ Warnings")
        lines.append("| ID | Rule | Severity | Confidence | File | Risk |")
        lines.append("|----|------|----------|:----------:|------|:----:|")
        for f in diff.warning_findings[:5]:
            lines.append(
                f"| `{f.get('finding_key', '?')}` | {f.get('rule_id') or f.get('pattern_title', '?')} | "
                f"{f.get('category')} | {f.get('confidence_score', 0):.0%} | "
                f"`{f.get('file_path', '?')}:{f.get('line_number', '?')}` | "
                f"{f.get('risk_score', 0)}/100 |"
            )
        lines.append("")

    if diff.fixed_findings:
        lines.append(f"<details><summary>🔧 {len(diff.fixed_findings)} fixed finding(s)</summary>\n")
        for f in diff.fixed_findings[:10]:
            lines.append(f"- `{f.get('_fingerprint', '?')[:12]}`")
        lines.append("\n</details>\n")

    lines.extend([
        "---",
        f"*Blocking: severity ≥ HIGH, confidence ≥ 80%.*",
    ])
    return "\n".join(lines)


def _resolve_diff_base(repo_path: Path, base: str) -> str:
    """Resolve base ref — branch name or commit SHA."""
    try:
        r = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "--verify", base],
                          capture_output=True, text=True, timeout=10)
        if r.returncode == 0: return r.stdout.strip()
        # Try origin/base
        r2 = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "--verify", f"origin/{base}"],
                           capture_output=True, text=True, timeout=10)
        if r2.returncode == 0: return r2.stdout.strip()
    except Exception: pass
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def run_external_scan(target: str, profile_name: str = "developer-review",
                      mode: str = "full", ref: str = "main",
                      base: str = "", head: str = "",
                      dry_run: bool = False,
                      scan_mode: str = "standard") -> ScanResult:
    policy = PROFILES.get(profile_name, PROFILES["developer-review"])
    mode = mode or policy.get("mode", "full")

    # Apply scan mode overrides (quick/standard/deep)
    if scan_mode:
        try:
            from gsc_scan_modes import apply_scan_mode
            policy = apply_scan_mode(policy, scan_mode)
        except ImportError:
            pass

    # Phase 1: auto-degrade to regex-only on empty API key or quick mode
    use_llm_flag = True
    # Check os.environ first, then .env file (Hermes stores keys in ~/.hermes/.env)
    _api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not _api_key:
        for _env_path in [
            os.path.expanduser("~/.hermes/.env"),
            os.path.expanduser("~/.hermes/env"),
            ".env",
        ]:
            if os.path.exists(_env_path):
                try:
                    with open(_env_path) as _f:
                        for _line in _f:
                            _line = _line.strip()
                            if _line.startswith("DEEPSEEK_API_KEY="):
                                _api_key = _line.split("=", 1)[1].strip().strip('"').strip("'")
                                if _api_key:
                                    os.environ["DEEPSEEK_API_KEY"] = _api_key
                                    break
                except Exception:
                    pass
            if _api_key:
                break
    if not _api_key:
        print("⚠️  DEEPSEEK_API_KEY not set → LLM stages disabled (regex-only mode)",
              file=sys.stderr)
        use_llm_flag = False
    # scan_mode override (e.g. quick → no LLM)
    if not policy.get("llm_enabled", True):
        use_llm_flag = False

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

    # Step 3.5: Multi-language scan
    from gsc_detectors.multi_lang import scan_multilang
    ml_findings = scan_multilang(target_path)
    if ml_findings:
        print(f"   Multi-lang findings: {len(ml_findings)}")
        raw_findings.extend(ml_findings)

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

    # Step 4.5: Rejudge multi-model consensus on top CRITICAL (if available)
    rejudge_count = 0
    if policy.get("rejudge_enabled", True):
        try:
            from gsc_rejudge import revalidate_findings as rejudge_findings
            critical_enriched = [f for f in enriched if f.get("category") == "CRITICAL"][:5]
            if critical_enriched:
                # Build temp scan.json for Rejudge
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                    json.dump({"findings": critical_enriched}, tmp)
                    tmp_path = tmp.name
                rej_result = rejudge_findings(tmp_path)
                os.unlink(tmp_path)
                rejudge_count = rej_result.get("revalidated", 0)
                # Boost confidence for findings Rejudge confirmed
                if rej_result.get("status") == "ok" and rej_result.get("verdict"):
                    for f in enriched:
                        if f.get("category") == "CRITICAL":
                            f["rejudge_verdict"] = rej_result["verdict"][:200]
                            # Boost confidence if Rejudge confirmed TP
                            if "TP" in rej_result["verdict"] or "true positive" in rej_result["verdict"].lower():
                                f["confidence"] = min(1.0, f.get("confidence", 0.7) + 0.1)
        except Exception:
            pass  # Rejudge unavailable — continue without
    if rejudge_count:
        print(f"   Rejudge consensus: {rejudge_count} findings")

    # Step 5: V3 Scoring + finding_key
    for f in enriched:
        conf = compute_confidence_v3(f)
        f["confidence_score"] = conf
        f["review_status"] = review_status(conf)
        f["risk_score"] = risk_score(f.get("category", "LOW"), conf)
        # Stable finding key for PR feedback
        rule = f.get("rule_id") or f.get("pattern_title", "?")
        fp = f.get("file_path", "?")
        snippet = (f.get("detail") or f.get("title") or "")[:100]
        f["finding_key"] = hashlib.sha256(f"{rule}|{fp}|{snippet}".encode()).hexdigest()[:12]

    # ── v0.17–v0.18: Build source_map first (needed by PoC + chains) ──
    source_map = {}
    for f in enriched:
        fp = f.get("file_path", "")
        if fp and fp not in source_map:
            fp_abs = target_path / fp if not fp.startswith("/") else Path(fp)
            if fp_abs.exists():
                try:
                    source_map[fp] = fp_abs.read_text(errors='replace')
                except Exception:
                    pass

    # ── v0.17: PoC Auto-Generation ──
    poc_budget = policy.get("poc_budget", 0)
    if poc_budget > 0 and any(f.get("confidence_score", 0) >= 0.80 for f in enriched):
        print(f"   Generating PoCs (budget: {poc_budget})...")
        try:
            from gsc_poc_generator import attach_pocs
            enriched = attach_pocs(enriched, source_map, budget=poc_budget)
            poc_generated = sum(1 for f in enriched if f.get("metadata", {}).get("poc"))
            poc_failed = sum(1 for f in enriched if f.get("metadata", {}).get("poc_failed"))
            print(f"   PoCs: {poc_generated} generated, {poc_failed} failed (confidence penalized)")
            result.poc_generated = poc_generated
            result.poc_failed = poc_failed
        except ImportError:
            pass

    # ── v0.18: Exploit Chain Composer (after PoC, before classify) ──
    chain_budget = policy.get("chain_budget", 0)
    chains = []
    if chain_budget > 0 and len(enriched) >= 2:
        print(f"   Composing attack chains (budget: {chain_budget})...")
        try:
            from gsc_chain_composer import ChainComposer
            composer = ChainComposer(budget=chain_budget)
            chains = composer.compose(enriched, source_map)
            # Mark participant findings with chain metadata
            by_key = {f.get("finding_key", ""): f for f in enriched}
            for chain in chains:
                for fk in chain.finding_keys:
                    f = by_key.get(fk)
                    if f:
                        f.setdefault("metadata", {})["chain_key"] = chain.chain_key
                        f["metadata"]["chain_severity"] = chain.composed_severity
        # Blocking decision delegated to BlockingEngine (Phase 5) — engine is sole source of truth
        except ImportError:
            pass

    # ── v0.19: Temporal Mutation Tracker (no LLM, before rollout) ──
    mutation_alerts = []
    try:
        from gsc_mutation_tracker import MutationTracker, auto_resolve
        from gsc_db import GSCDatabase
        with GSCDatabase() as db:
            tracker = MutationTracker(db)
            mutation_alerts = tracker.process(enriched, target=target, scan_mode=mode)
            if mode == "full":
                current = {f.get("finding_key", "") for f in enriched}
                resolved = auto_resolve(db, target, current, "full")
                if resolved:
                    print(f"   Auto-resolved: {resolved} disappeared findings")
        if mutation_alerts:
            print(f"   Mutations: {len(mutation_alerts)} alerts "
                  f"({sum(1 for a in mutation_alerts if a.kind == 'recurrence')} recurrences, "
                  f"{sum(1 for a in mutation_alerts if a.kind == 'mutation')} mutations)")
            result.mutation_alerts = len(mutation_alerts)
    except ImportError:
        pass

    # ── v0.25 Phase 4: Blocking Engine (replaces _apply_rollout_phase) ──
    blocking_summary = {"blocked": [], "shadow": False}
    try:
        from gsc_blocking import BlockingEngine
        from gsc_db import GSCDatabase
        with GSCDatabase() as db:
            engine = BlockingEngine(db, policy.get("rollout_phase", "warn-only"),
                                     github_context=False)
            overrides_set = set()
            blocking_summary = engine.apply(enriched, overrides=overrides_set,
                                            bypass=policy.get("bypass", False))
            result.bypass = blocking_summary.get("bypass", False)
            result.findings_blocking = len(blocking_summary.get("blocked", []))
    except ImportError:
        pass

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

    # ── v0.13: Diff mode ──
    if mode in ("diff", "pr") and base:
        print(f"\n📋 Diff mode: {base} → {head or 'HEAD'}")
        base_sha = _resolve_diff_base(target_path, base)
        diff_ctx = collect_changed_files(target_path, base_sha, head or "HEAD")
        print(f"   Changed: {len(diff_ctx.changed_files)} files "
              f"({len(diff_ctx.added_files)} added, {len(diff_ctx.modified_files)} modified, "
              f"{len(diff_ctx.deleted_files)} deleted)")

        # Build base baseline
        print(f"   Building base baseline...")
        base_fps = build_base_baseline(target_path, diff_ctx)
        print(f"   Base fingerprints: {len(base_fps)}")

        # Filter findings to only changed files
        changed_set = set(diff_ctx.changed_files)
        changed_findings = [f for f in enriched
                           if f.get("file_path", "") in changed_set]

        # Compare
        diff_result = compare_findings(changed_findings, base_fps, policy)
        print(f"   New: {len(diff_result.new_findings)}, "
              f"Unchanged: {len(diff_result.unchanged_findings)}, "
              f"Fixed: {len(diff_result.fixed_findings)}, "
              f"Blocking: {len(diff_result.blocking_findings)}, "
              f"Warnings: {len(diff_result.warning_findings)}")

        # Update result with diff-scoped data
        result.findings = diff_result.new_findings
        result.findings_total = len(diff_result.new_findings)
        result.findings_blocking = len(diff_result.blocking_findings)
        result.findings_confirmed = sum(1 for f in diff_result.new_findings
                                        if f.get("review_status") == "confirmed")
        result.findings_likely = sum(1 for f in diff_result.new_findings
                                     if f.get("review_status") == "likely")
        result.findings_uncertain = sum(1 for f in diff_result.new_findings
                                        if f.get("review_status") == "uncertain")
        result.findings_fp = sum(1 for f in diff_result.new_findings
                                 if f.get("review_status") == "false-positive")
        # Attach diff metadata
        result._diff = diff_result
        result._diff_ctx = diff_ctx

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
    scan.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="standard")
    scan.add_argument("--ref", default="main")
    scan.add_argument("--base", default="", help="Base ref for diff mode (e.g. origin/main)")
    scan.add_argument("--head", default="HEAD", help="Head ref for diff mode")
    scan.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    scan.add_argument("--output", "-o", help="Output file or directory")
    scan.add_argument("--fail-on-blocking", action="store_true",
                      help="Exit 1 if blocking findings found")

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
        result = run_external_scan(args.target, args.profile, args.mode, args.ref,
                                   getattr(args, 'base', ''), getattr(args, 'head', 'HEAD'),
                                   scan_mode=getattr(args, 'scan_mode', 'standard'))

        # Output directory
        name = args.target.rstrip("/").split("/")[-1].replace(".git", "")
        mode_suffix = f"-diff" if args.mode in ("diff", "pr") else ""
        out_dir = EXTERNAL_DIR / name / (datetime.now().strftime("%Y-%m-%d_%H%M") + mode_suffix)
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

        # PR comment
        print()
        if args.mode in ("diff", "pr") and hasattr(result, '_diff'):
            print(generate_pr_diff_comment(result, result._diff, result._diff_ctx))
        else:
            print(generate_pr_comment(result))

        # Exit code
        blocking = result.findings_blocking
        if getattr(args, 'fail_on_blocking', False) and blocking > 0:
            print(f"\n❌ BLOCKED: {blocking} blocking finding(s)")
            sys.exit(1)
        sys.exit(0)

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
