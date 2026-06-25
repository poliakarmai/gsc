#!/usr/bin/env python3
"""
GSC — Git Security Checker. Multi-echelon audit with self-learning.

Usage:
  gsc scan <project>       Run 3-echelon audit
  gsc init                 Initialize GSC in current directory
  gsc dashboard            Launch web dashboard
  gsc patterns             Manage seed patterns
  gsc db <sql>             Query audit database
"""

import sys
import os
import argparse
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime

GSC_HOME = Path.home() / ".gsc"
GSC_HOME.mkdir(parents=True, exist_ok=True)

DB_PATH = Path.home() / ".hermes" / "state" / "gsc_audit.db"
SCRIPTS_DIR = Path.home() / ".hermes" / "scripts"

# Ensure WAL mode for concurrent CI/CD access
def _init_db():
    """Enable WAL mode + busy timeout for concurrent access."""
    if DB_PATH.exists():
        import sqlite3 as _sq
        conn = _sq.connect(str(DB_PATH))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.close()
_init_db()

# File extension → language mapping
EXT_TO_LANG = {
    ".py": "python", ".pyx": "python", ".pyi": "python",
    ".go": "go",
    ".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript",
    ".rs": "rust",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "terraform",
    "Dockerfile": "docker", ".dockerfile": "docker",
    ".sql": "sql", ".sh": "shell", ".bash": "shell",
    ".yml": "yaml", ".yaml": "yaml", ".md": "markdown", ".json": "json",
    ".env": "dotenv", ".toml": "toml", ".cfg": "ini", ".ini": "ini",
}
# Universal patterns — apply to all file types
UNIVERSAL_PATTERNS = {"Hardcoded encryption key", "Hardcoded secret", "World-readable",
                      "Bare except:", "print() instead", "Хардкод", "Generic code smell"}

KNOWN_PROJECTS = {
    "pci-index": Path.home() / "pci-index",
    "bybit-ws": Path.home() / "bybit-ws",
    "vpn-infra": Path("/opt/vpn-seller-bot"),
    "apolaibot": Path.home() / "projects" / "hermes-agent-orchestration",
    "hermes-self": Path.home() / "projects" / "hermes-agent-orchestration",
    "gridsignal": Path.home() / ".local" / "bin",
}


def cmd_scan(args):
    """Run 3-echelon audit on a project."""
    project = args.project

    # Resolve project path
    project_path = KNOWN_PROJECTS.get(project)
    if not project_path:
        project_path = Path(project).resolve()
    if not project_path.exists():
        print(f"❌ Project not found: {project}")
        sys.exit(1)

    quiet = getattr(args, 'ci', False) or getattr(args, 'json', False) or getattr(args, 'sarif', False)
    if not quiet:
        print(f"🔍 GSC Scanning: {project} ({project_path})")
        print(f"   Echelons: {'all 3' if not args.echelon else args.echelon}")
        print()

    # 1. Load patterns (suppress in CI mode)
    quiet = getattr(args, 'ci', False) or getattr(args, 'json', False) or getattr(args, 'sarif', False)
    if not quiet:
        patterns_cmd = [sys.executable, str(SCRIPTS_DIR / "gsc_load_patterns.py"), project]
        patterns = subprocess.run(patterns_cmd, capture_output=True, text=True)
        print(patterns.stdout)

    # 2. Run audit
    if args.diff:
        findings = run_diff_scan(project, project_path)
    else:
        findings = run_audit_echelons(project, project_path, args.echelon, getattr(args, 'deep', False))

    # 2.5 Framework-aware filter (reduce FP)
    try:
        sys.path.insert(0, str(Path(__file__).parent / "scripts"))
        from framework_aware import filter_findings as fw_filter
        findings = fw_filter(findings)
    except Exception:
        pass

    # 3. Save findings
    save_findings(project, findings, quiet=quiet)

    # 4. Report
    if args.ci or args.json:
        print(json.dumps(findings, indent=2))
    elif args.sarif:
        print(json.dumps(export_sarif(findings, project), indent=2))
    elif args.compliance:
        print_compliance(findings, args.compliance)
    else:
        print_summary(findings)


def run_audit_echelons(project: str, path: Path, echelons: str = None, deep: bool = False) -> list[dict]:
    """Run audit checks directly (standalone mode)."""
    findings = []

    if not echelons or "1" in echelons:
        findings.extend(check_source_driven(project, path))
    if not echelons or "2" in echelons:
        findings.extend(check_security(project, path))
    if not echelons or "3" in echelons:
        findings.extend(check_adversarial(project, path))
    if deep:
        findings.extend(check_deep(project, path, findings))

    # Post-filter: remove findings in docstrings, comments, type annotations
    findings = [f for f in findings if not _is_in_docstring_or_comment(f)]

    return findings


# ── Docstring / comment filter ────────────────────────────────────────────

_file_cache: dict[str, list[str]] = {}
"""Cache of file contents to avoid re-reading for every finding."""

def _is_in_docstring_or_comment(finding: dict) -> bool:
    """Check if a finding's line is inside a docstring, comment, or type annotation (not real code).
    Returns True if finding should be DISCARDED."""
    fp = finding.get("file_path", "")
    ln = (finding.get("line_number") or 0)
    if not fp or ln <= 0:
        return False

    # Resolve path
    p = Path(fp)
    if not p.exists():
        return False

    # Use cache
    cache_key = str(p)
    if cache_key not in _file_cache:
        try:
            _file_cache[cache_key] = p.read_text().split("\n")
        except Exception:
            _file_cache[cache_key] = []
    lines = _file_cache[cache_key]
    if not lines or ln > len(lines):
        return False

    return _line_is_comment_or_docstring(lines, ln - 1)  # 0-indexed


def _line_is_comment_or_docstring(lines: list[str], idx: int) -> bool:
    """Determine if line at idx is inside a docstring or is a comment.
    Handles: # comments, '''...''' docstrings, \"\"\"...\"\"\" docstrings."""
    line = lines[idx].strip() if idx < len(lines) else ""

    # Pure comment line
    if line.startswith("#") or line.startswith("//") or line.startswith("--"):
        return True

    # Check if inside triple-quoted docstring
    in_docstring = False
    doc_delim = None
    for i, l in enumerate(lines):
        stripped = l.strip()

        # Toggle docstring state
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = True
                doc_delim = '"""' if stripped.startswith('"""') else "'''"
                # Single-line docstring
                cnt = stripped.count(doc_delim)
                if cnt >= 2 and stripped.endswith(doc_delim):
                    in_docstring = False
        else:
            if doc_delim and doc_delim in stripped:
                in_docstring = False

        if i == idx:
            return in_docstring

    return False


def infer_lang_from_title(title: str) -> str:
    """Infer language from pattern title (e.g. 'Java: SQL injection' → 'java')."""
    prefixes = {"Go:": "go", "TS:": "typescript", "Java:": "java", "Rust:": "rust",
                "Docker:": "docker", "Terraform:": "terraform", "Python:": "python"}
    for prefix, lang in prefixes.items():
        if title.startswith(prefix):
            return lang
    return ""

def lang_to_rg_types(lang: str) -> str:
    """Convert language name to ripgrep -t type string."""
    mapping = {"python": "py", "go": "go", "typescript": "ts", "javascript": "js",
               "rust": "rs", "java": "java", "terraform": "tf", "docker": "docker"}
    return mapping.get(lang, "")


def check_source_driven(project: str, path: Path) -> list[dict]:
    """Echelon 1: Source-driven checks."""
    findings = []
    patterns = load_patterns(project, echelon=1)

    # Run grep-based patterns
    for p in patterns:
        if p.get("pattern_type", "regex") not in ("grep", "regex"):
            continue
        search_pattern = p.get("search_pattern", "")
        if not search_pattern:
            continue
        # Language filter: skip if file extension doesn't match pattern's language
        p_lang = p.get("language", "") or infer_lang_from_title(p.get("title", ""))
        try:
            # Use file-type filter for ripgrep to speed up
            file_types = lang_to_rg_types(p_lang) if p_lang else None
            rg_args = ["rg", "--no-heading", "-n", search_pattern, str(path)]
            if file_types:
                rg_args.insert(2, "-t")
                rg_args.insert(3, file_types)
            result = subprocess.run(rg_args, capture_output=True, text=True, timeout=30)
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    findings.append({
                        "category": p.get("category", "MEDIUM"),
                        "echelon": 1,
                        "title": p["title"],
                        "file_path": parts[0],
                        "line_number": int(parts[1]) if parts[1].isdigit() else 0,
                        "detail": p.get("description", ""),
                        "pattern_title": p["title"],
                    })
        except Exception:
            pass

    return findings


def check_security(project: str, path: Path) -> list[dict]:
    """Echelon 2: Security checks."""
    findings = []
    patterns = load_patterns(project, echelon=2)

    for p in patterns:
        if p.get("pattern_type") == "regex":
            search_pattern = p.get("search_pattern", "")
            if not search_pattern:
                continue
            # Language filter
            p_lang = p.get("language", "") or infer_lang_from_title(p.get("title", ""))
            file_types = lang_to_rg_types(p_lang) if p_lang else None
            try:
                rg_args = ["rg", "--no-heading", "-n", search_pattern, str(path)]
                if file_types:
                    rg_args.insert(2, "-t")
                    rg_args.insert(3, file_types)
                # Exclude markdown/docs from security patterns
                if p.get("echelon") == 2 and not file_types:
                    rg_args.insert(2, "-g")
                    rg_args.insert(3, "!*.md")
                result = subprocess.run(rg_args, capture_output=True, text=True, timeout=30)
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        findings.append({
                            "category": p.get("category", "MEDIUM"),
                            "echelon": 2,
                            "title": p["title"],
                            "file_path": parts[0],
                            "line_number": int(parts[1]) if parts[1].isdigit() else 0,
                            "detail": f"Match: {parts[2][:100]}" if len(parts) > 2 else p.get("description", ""),
                            "pattern_title": p["title"],
                        })
            except Exception:
                pass

    # Check file permissions for data files
    for data_dir in [path / "data", path / ".local" / "share"]:
        if not data_dir.exists():
            continue
        for f in data_dir.rglob("*"):
            if f.is_file() and f.suffix in (".db", ".json", ".log", ".env", ".yaml", ".yml", ".key", ".pem"):
                perms = oct(f.stat().st_mode)[-3:]
                if int(perms[-1]) >= 4:  # world-readable
                    findings.append({
                        "category": "HIGH",
                        "echelon": 2,
                        "title": f"World-readable file: {f.name} ({perms})",
                        "file_path": str(f),
                        "line_number": 0,
                        "detail": f"Permissions {perms} — should be 600 for sensitive files",
                        "pattern_title": "chmod: World-readable sensitive files",
                    })

    # Also check root-level sensitive files (including dotfiles)
    sensitive_names = {".env", ".envrc", ".secrets", ".credentials"}
    for f in path.glob("*"):
        is_sensitive = (f.name in sensitive_names or 
                       f.suffix in (".db", ".json", ".log", ".yaml", ".yml", ".key", ".pem"))
        if f.is_file() and is_sensitive:
            perms = oct(f.stat().st_mode)[-3:]
            if int(perms[-1]) >= 4:
                findings.append({
                    "category": "HIGH", "echelon": 2,
                    "title": f"World-readable file: {f.name} ({perms})",
                    "file_path": str(f), "line_number": 0,
                    "detail": f"Permissions {perms} — should be 600",
                    "pattern_title": "chmod: World-readable",
                })

    return findings


def check_adversarial(project: str, path: Path) -> list[dict]:
    """Echelon 3: Adversarial/logic checks."""
    findings = []
    patterns = load_patterns(project, echelon=3)

    # Check for known anti-patterns
    for p in patterns:
        if p.get("pattern_type") != "semantic":
            continue
        search_pattern = p.get("search_pattern", "")
        if not search_pattern:
            continue
        try:
            result = subprocess.run(
                ["rg", "--no-heading", "-n", search_pattern, str(path)],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    findings.append({
                        "category": p.get("category", "MEDIUM"),
                        "echelon": 3,
                        "title": p["title"],
                        "file_path": parts[0],
                        "line_number": int(parts[1]) if parts[1].isdigit() else 0,
                        "detail": p.get("description", ""),
                        "pattern_title": p["title"],
                    })
        except Exception:
            pass

    return findings


def check_deep(project: str, path: Path, findings: list[dict] = None) -> list[dict]:
    """Echelon 4: LLM-powered deep analysis."""
    # Check for OpenRouter key — works both in Hermes and standalone
    has_llm = False
    try:
        import yaml
        cfg_path = os.path.expanduser("~/.hermes/config.yaml")
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            has_llm = bool(cfg.get("auxiliary", {}).get("vision", {}).get("api_key", ""))
    except Exception:
        pass
    if not has_llm:
        has_llm = bool(os.environ.get("OPENROUTER_API_KEY"))

    if not has_llm:
        return [{
            "category": "INFO", "echelon": 4,
            "title": "Deep analysis requires OpenRouter API key",
            "file_path": "", "line_number": 0,
            "detail": "Set OPENROUTER_API_KEY env var or configure in ~/.hermes/config.yaml"
        }]

    print("  🧠 E4: LLM deep analysis...", file=sys.stderr)
    try:
        from scripts.e4_llm import run_e4_scan

        # Use passed findings, or load from DB as fallback
        if findings is None:
            findings = []
            if DB_PATH.exists():
                conn = sqlite3.connect(str(DB_PATH))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM findings WHERE project=? AND status='open' ORDER BY CASE category WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END LIMIT 20",
                    (project,)
                ).fetchall()
                findings = [dict(r) for r in rows]
                conn.close()

        enriched = run_e4_scan(findings)
        return [{
            "category": f.get('category', 'INFO'), "echelon": 4,
            "title": f"[E4] {f.get('title','')}",
            "file_path": f.get('file_path', ''), "line_number": f.get('line_number', 0),
            "detail": json.dumps(f.get('e4_result', {}))
        } for f in enriched if f.get('e4_analyzed')]
    except Exception as e:
        return [{"category": "INFO", "echelon": 4, "title": f"E4 error: {e}", "file_path": "", "line_number": 0, "detail": str(e)}]


def run_diff_scan(project: str, path: Path) -> list[dict]:
    """Scan only changed files (git diff HEAD). Falls back to full scan if no git."""
    import subprocess as sp
    changed_files = []

    try:
        r = sp.run(["git", "-C", str(path), "diff", "--name-only", "HEAD"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            changed_files = [f for f in r.stdout.strip().split("\n") if f]
    except Exception:
        pass

    if not changed_files:
        return run_audit_echelons(project, path)

    findings = []
    for fname in changed_files:
        fpath = path / fname
        if not fpath.exists() or not fpath.suffix in ('.py', '.go', '.ts', '.rs', '.java', '.tf', '.js', '.yaml', '.yml'):
            continue

        # Run patterns on this file only
        for pattern in load_patterns(project):
            search = pattern.get('search_pattern', '')
            if not search:
                continue
            try:
                r = sp.run(["rg", "--no-heading", "-n", search, str(fpath)], capture_output=True, text=True, timeout=10)
                for line in r.stdout.strip().split("\n"):
                    if not line: continue
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        findings.append({
                            "category": pattern.get("category", "MEDIUM"),
                            "echelon": pattern.get("echelon", 1),
                            "title": pattern["title"],
                            "file_path": parts[0], "line_number": int(parts[1]) if parts[1].isdigit() else 0,
                            "detail": pattern.get("description", ""), "pattern_title": pattern["title"],
                        })
            except Exception:
                pass

    # Check file permissions for changed files
    for fname in changed_files:
        fpath = path / fname
        if fpath.exists() and fpath.suffix in ('.db', '.json', '.log', '.env', '.yaml', '.yml', '.key', '.pem'):
            perms = oct(fpath.stat().st_mode)[-3:]
            if int(perms[-1]) >= 4:
                findings.append({
                    "category": "HIGH", "echelon": 2,
                    "title": f"World-readable file: {fpath.name} ({perms})",
                    "file_path": str(fpath), "line_number": 0,
                    "detail": f"Permissions {perms} — should be 600", "pattern_title": "chmod: World-readable",
                })

    return findings


def print_compliance(findings: list[dict], framework: str):
    """Print compliance report for PCI DSS, SOC2, or ISO 27001."""
    # Mapping from compliance.md
    mapping = {
        "pci-dss": {
            "Req 3": ["Hardcoded encryption key", "Hardcoded secret", "Hardcoded API key"],
            "Req 4": ["Insecure TLS", "crypto/md5", "crypto/sha1", "math/rand for crypto"],
            "Req 6": ["SQL injection", "eval()", "pickle.load", "Bare except"],
            "Req 7": ["World-readable"],
            "Req 8": ["Hardcoded password", "Token in /proc"],
            "Req 10": ["print() instead", "console.log"],
        },
        "soc2": {
            "CC6.1": ["World-readable"],
            "CC6.6": ["SQL injection", "XSS", "Command injection"],
            "CC6.7": ["Insecure TLS", "crypto"],
            "CC6.8": ["eval()", "pickle.load"],
            "CC7.2": ["print()", "missing HEALTHCHECK"],
        },
        "iso27001": {
            "A.9": ["Hardcoded credential", "token leak"],
            "A.10": ["MD5", "SHA1", "insecure random", "Insecure TLS"],
            "A.14": ["SQL injection", "XSS"],
            "A.16": ["swallowed exception", "Bare except"],
        },
    }

    frameworks = list(mapping.keys()) if framework == "all" else [framework]

    print(f"\n📋 Compliance Report — {', '.join(frameworks).upper()}")
    print("=" * 55)

    for fw in frameworks:
        print(f"\n## {fw.upper()}")
        total = passed = failed = 0
        for req, patterns in mapping.get(fw, {}).items():
            total += 1
            matched = [f for f in findings if any(p.lower() in f.get("title","").lower() for p in patterns)]
            if matched:
                failed += 1
                crit_count = sum(1 for f in matched if f.get("category") == "CRITICAL")
                print(f"  ❌ {req}: {len(matched)} findings ({crit_count} critical)")
            else:
                passed += 1
                print(f"  ✅ {req}: pass")

        if total > 0:
            print(f"\n  Score: {passed}/{total} passed, {failed} failed")
            if failed == 0:
                print("  🟢 Compliant")


def export_sarif(findings: list[dict], project: str) -> dict:
    """Export findings as SARIF 2.1.0 for GitHub Code Scanning."""
    rules = {}
    results = []

    for f in findings:
        rid = f"GSC-{f.get('pattern_title','generic')[:40].replace(' ','-')}"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.get("pattern_title", f.get("title", "Unknown")),
                "shortDescription": {"text": f.get("title", "")},
                "defaultConfiguration": {"level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.get("category", "MEDIUM"), "warning")}
            }
        results.append({
            "ruleId": rid,
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.get("category", "MEDIUM"), "warning"),
            "message": {"text": f.get("detail", f.get("title", ""))},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("file_path", "")}, "region": {"startLine": f.get("line_number", 1)}}}]
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "GSC", "informationUri": "https://github.com/poliakarmai/gsc", "rules": list(rules.values())}}, "results": results}]
    }


def save_findings(project: str, findings: list[dict], quiet: bool = False):
    """Persist findings to GSC database."""
    if not DB_PATH.exists():
        print("⚠️  GSC DB not found — findings not saved")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO audit_runs (project, started_at) VALUES (?, datetime('now'))",
        (project,)
    )
    run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    for f in findings:
        conn.execute(
            """INSERT OR IGNORE INTO findings
               (run_id, project, echelon, category, title, file_path, line_number, detail, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,'open',datetime('now'))""",
            (run_id, project, f.get("echelon", 1), f.get("category", "MEDIUM"),
             f["title"], f.get("file_path", ""), f.get("line_number", 0),
             f.get("detail", ""))
        )

    total = conn.execute("SELECT COUNT(*) FROM findings WHERE run_id = ?", (run_id,)).fetchone()[0]
    conn.execute(
        "UPDATE audit_runs SET finished_at = datetime('now'), total_findings = ?, new_findings = ? WHERE id = ?",
        (total, total, run_id)
    )
    conn.commit()
    conn.close()
    if not quiet:
        print(f"💾 Saved: {total} findings (run #{run_id})")


def load_patterns(project: str, echelon: int = None) -> list[dict]:
    """Load patterns from DB or seed files."""
    patterns = []

    # Try DB first
    if DB_PATH.exists():
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM patterns WHERE (project = ? OR project = '*')"
        params = [project]
        if echelon:
            query += " AND echelon = ?"
            params.append(echelon)
        rows = conn.execute(query, params).fetchall()
        patterns = [dict(r) for r in rows]
        conn.close()

    # Fallback: load from seed files
    if not patterns:
        seed_dir = Path(__file__).parent / "patterns"
        for seed_file in seed_dir.glob("*.json"):
            try:
                seed_patterns = json.loads(seed_file.read_text())
                for p in seed_patterns:
                    if not echelon or p.get("echelon") == echelon:
                        p["project"] = p.get("project", "*")
                        patterns.append(p)
            except Exception:
                pass

    return patterns


def print_summary(findings: list[dict]):
    """Print human-readable summary."""
    critical = [f for f in findings if f.get("category") == "CRITICAL"]
    high = [f for f in findings if f.get("category") == "HIGH"]
    medium = [f for f in findings if f.get("category") == "MEDIUM"]
    low = [f for f in findings if f.get("category") == "LOW"]

    print(f"\n{'='*50}")
    print(f"🔒 GSC Audit Complete — {len(findings)} findings")
    print(f"   CRITICAL: {len(critical)}")
    print(f"   HIGH:     {len(high)}")
    print(f"   MEDIUM:   {len(medium)}")
    print(f"   LOW:      {len(low)}")

    if critical:
        print(f"\n🔴 CRITICAL:")
        for f in critical[:5]:
            print(f"   {f['file_path']}:{f.get('line_number','?')} — {f['title']}")


def cmd_init(args):
    """Initialize GSC in a project directory."""
    target = Path(args.dir or ".").resolve()
    gsc_dir = target / ".gsc"
    gsc_dir.mkdir(parents=True, exist_ok=True)
    # Also create GitHub Actions dir
    (target / ".github" / "workflows").mkdir(parents=True, exist_ok=True)

    # Create config
    config = {
        "project": target.name,
        "created": datetime.now().isoformat(),
        "ignore_patterns": ["**/__pycache__/**", "**/node_modules/**", "**/.git/**"],
        "thresholds": {"critical": 0, "high": 5, "medium": 20, "low": 50},
    }
    (gsc_dir / "config.yaml").write_text(
        "# GSC Configuration\n" + "\n".join(f"{k}: {v}" for k, v in config.items())
    )

    # Create gitignore
    (gsc_dir / ".gitignore").write_text("*.log\n")

    # Create GitHub Actions workflow
    workflows = target / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "gsc.yml").write_text("""\
name: GSC Audit
on: [pull_request, push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: poliakarmai/gsc-action@v1
        with:
          project: ${{ github.event.repository.name }}
""")

    print(f"✅ GSC initialized in {target}")
    print(f"   Config: {gsc_dir / 'config.yaml'}")
    print(f"   CI:     {workflows / 'gsc.yml'}")
    print(f"\nNext: gsc scan {target.name}")


def cmd_dashboard(args):
    """Launch web dashboard."""
    import http.server
    import socketserver

    dashboard_html = generate_dashboard_html()
    dash_path = GSC_HOME / "dashboard.html"
    dash_path.write_text(dashboard_html)

    port = args.port or 8080

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/" or self.path == "/dashboard":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(dashboard_html.encode())
            else:
                super().do_GET()

    os.chdir(str(GSC_HOME))
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"🌐 GSC Dashboard: http://localhost:{port}")
        print(f"   Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Stopped")


def generate_dashboard_html() -> str:
    """Generate HTML dashboard from GSC data."""
    stats = get_dashboard_stats()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GSC Dashboard</title>
<style>
:root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --dim: #8b949e; --green: #3fb950; --red: #f85149; --blue: #58a6ff; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:-apple-system,sans-serif; padding:20px; max-width:1000px; margin:0 auto; }}
h1 {{ color:var(--blue); margin-bottom:8px; }}
.subtitle {{ color:var(--dim); font-size:13px; margin-bottom:24px; }}
.kpi-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }}
.kpi {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; text-align:center; }}
.kpi .value {{ font-size:28px; font-weight:700; }}
.kpi .label {{ color:var(--dim); font-size:12px; margin-top:4px; }}
table {{ width:100%; border-collapse:collapse; margin-bottom:24px; }}
th {{ text-align:left; color:var(--dim); padding:8px 12px; border-bottom:1px solid var(--border); }}
td {{ padding:8px 12px; border-bottom:1px solid var(--border); }}
.green {{ color:var(--green); }}
.red {{ color:var(--red); }}
.section {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:24px; }}
.section h2 {{ font-size:16px; margin-bottom:12px; color:var(--blue); }}
</style>
</head>
<body>
<h1>🔒 GSC Dashboard</h1>
<div class="subtitle">Self-learning audit system · {datetime.now().strftime('%d.%m.%Y %H:%M')}</div>

<div class="kpi-grid">
  <div class="kpi"><div class="value">{stats['total_findings']}</div><div class="label">Total Findings</div></div>
  <div class="kpi"><div class="value green">{stats['fixed']}</div><div class="label">Fixed</div></div>
  <div class="kpi"><div class="value">{stats['audit_runs']}</div><div class="label">Audit Runs</div></div>
  <div class="kpi"><div class="value">{stats['patterns']}</div><div class="label">Patterns</div></div>
</div>

<div class="section">
<h2>📊 Projects</h2>
<table>
<tr><th>Project</th><th>Findings</th><th>Fixed</th><th>Status</th></tr>
{generate_project_rows(stats['projects'])}
</table>
</div>

<div class="section">
<h2>🧠 Top Patterns</h2>
<table>
<tr><th>Pattern</th><th>Category</th><th>Effectiveness</th></tr>
{generate_pattern_rows(stats['top_patterns'])}
</table>
</div>

</body>
</html>"""


def get_dashboard_stats() -> dict:
    """Collect dashboard statistics from DB."""
    if not DB_PATH.exists():
        return {"total_findings": 0, "fixed": 0, "audit_runs": 0, "patterns": 0, "projects": [], "top_patterns": []}

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
    fixed = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status='fixed'").fetchone()["c"]
    runs = conn.execute("SELECT COUNT(*) as c FROM audit_runs").fetchone()["c"]
    patterns = conn.execute("SELECT COUNT(*) as c FROM patterns").fetchone()["c"]

    projects = []
    for row in conn.execute(
        "SELECT project, COUNT(*) as total, SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) as fixed FROM findings GROUP BY project ORDER BY total DESC"
    ).fetchall():
        projects.append({"name": row["project"], "total": row["total"], "fixed": row["fixed"]})

    top_patterns = []
    for row in conn.execute(
        "SELECT title, category, true_positive_count, false_positive_count FROM patterns WHERE true_positive_count > 0 ORDER BY true_positive_count DESC LIMIT 10"
    ).fetchall():
        eff = row["true_positive_count"] / max(1, row["true_positive_count"] + row["false_positive_count"]) * 100
        top_patterns.append({"title": row["title"], "category": row["category"], "effectiveness": eff})

    conn.close()
    return {
        "total_findings": total, "fixed": fixed, "audit_runs": runs, "patterns": patterns,
        "projects": projects, "top_patterns": top_patterns
    }


def generate_project_rows(projects: list) -> str:
    rows = []
    for p in projects:
        ok = p["total"] == p["fixed"] and p["total"] > 0
        status = '<span class="green">✅</span>' if ok else '<span class="red">🔴</span>'
        rows.append(f"<tr><td>{p['name']}</td><td>{p['total']}</td><td>{p['fixed']}</td><td>{status}</td></tr>")
    return "\n".join(rows)


def generate_pattern_rows(patterns: list) -> str:
    rows = []
    for p in patterns:
        color = "green" if p["effectiveness"] >= 80 else "red" if p["effectiveness"] < 50 else ""
        rows.append(f"<tr><td>{p['title'][:60]}</td><td>{p['category']}</td><td class='{color}'>{p['effectiveness']:.0f}%</td></tr>")
    return "\n".join(rows)


def cmd_patterns(args):
    """Manage patterns — export/import/list."""
    action = getattr(args, 'pat_action', None) or 'list'
    if action == 'export':
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_marketplace.py'), 'export', getattr(args, 'file', '') or 'gsc_patterns.yaml'])
    elif action == 'import':
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_marketplace.py'), 'import', getattr(args, 'file', '') or ''])
    else:
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_marketplace.py')])


def seed_patterns(count: int):
    """Generate and seed patterns into DB."""
    if not DB_PATH.exists():
        print("❌ GSC DB not found — run gsc scan first")
        sys.exit(1)

    patterns = generate_seed_patterns(count)
    conn = sqlite3.connect(str(DB_PATH))

    seeded = 0
    for p in patterns:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO patterns
                   (project, echelon, category, title, pattern_type, search_pattern, description) 
                   VALUES (?,?,?,?,?,?,?)""",
                ("*", p["echelon"], p["category"], p["title"], p["pattern_type"],
                 p.get("search_pattern", ""), p.get("description", ""))
            )
            if conn.changes > 0:
                seeded += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"🌱 Seeded {seeded} new patterns ({len(patterns)} total generated)")


def generate_seed_patterns(count: int) -> list[dict]:
    """Generate OWASP/CWE/Python seed patterns."""
    patterns = []

    # OWASP Top 10 (2021)
    owasp = [
        ("Broken Access Control", "A01", 2, "CRITICAL", "chmod: World-readable configs", "regex", r"chmod.*[0-7][4-7][4-7]"),
        ("Cryptographic Failures", "A02", 2, "CRITICAL", "Hardcoded encryption key", "regex", r"(key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"),
        ("Injection", "A03", 1, "CRITICAL", "SQL injection risk: f-string in query", "regex", r"""f['\"].*SELECT|f['\"].*INSERT|f['\"].*UPDATE|f['\"].*DELETE"""),
        ("Insecure Design", "A04", 3, "HIGH", "Missing rate limiting", "semantic", r"def (handler|endpoint|route).*:.*\n(?!.*rate)"),
        ("Security Misconfiguration", "A05", 2, "HIGH", "Debug mode enabled", "regex", r"DEBUG\s*=\s*True|debug\s*=\s*true"),
        ("Vulnerable Components", "A06", 2, "MEDIUM", "Outdated dependency pattern", "regex", r"(requirements\.txt|pyproject\.toml|package\.json)"),
        ("Auth Failures", "A07", 2, "CRITICAL", "Weak password validation", "regex", r"min_length\s*=\s*[0-7]"),
        ("Software/Data Integrity", "A08", 3, "HIGH", "Missing signature verification", "semantic", r"json\.loads\(.*\)(?!.*verify|.*validate)"),
        ("Logging/Monitoring", "A09", 1, "MEDIUM", "print() instead of logging", "regex", r"print\(.*\)(?!.*flush)"),
        ("SSRF", "A10", 2, "HIGH", "User-controlled URL in request", "regex", r"requests\.(get|post)\(.*format\(|requests\.(get|post)\(.*f['\"]"),
    ]

    for name, owasp_id, echelon, category, title, ptype, search in owasp:
        patterns.append({
            "echelon": echelon, "category": category, "title": title,
            "pattern_type": ptype, "search_pattern": search,
            "description": f"OWASP {owasp_id}: {name}",
            "project": "*", "true_positive_count": 0, "false_positive_count": 0,
        })

    # Python-specific patterns
    python_patterns = [
        (1, "HIGH", "Unused import", "regex", r"^import \w+\s*$.*(?!.*\b\w+\b)"),
        (1, "MEDIUM", "Missing docstring", "regex", r"^def \w+\(.*\):\s*$\n\s+(?!\"\"\"|''')"),
        (1, "MEDIUM", "Bare except:", "regex", r"except\s*:"),
        (2, "HIGH", "eval() or exec() usage", "regex", r"\beval\(|\bexec\("),
        (2, "CRITICAL", "pickle.load() — unsafe deserialization", "regex", r"pickle\.(load|loads)\("),
        (2, "HIGH", "os.system() without sanitization", "regex", r"os\.system\(.*format\(|os\.system\(.*f['\"]"),
        (2, "MEDIUM", "Hardcoded IP address", "regex", r"\b(?!127\.)(\d{1,3}\.){3}\d{1,3}\b"),
        (2, "HIGH", "API key in git history", "semantic", r"(ghp_|sk-|xai-|eyJ).{10,}"),
        (3, "HIGH", "Race condition: check-then-act", "semantic", r"if.*exists\(\):.*\n.*(open|read|write|remove)"),
        (3, "MEDIUM", "No timeout on network call", "regex", r"requests\.(get|post|put|delete)\((?!.*timeout)"),
        (3, "MEDIUM", "Missing fcntl/flock on file write", "semantic", r"with open\(.*w.*\)(?!.*flock|.*fcntl)"),
        (3, "LOW", "float division without zero-check", "regex", r"/ (?!.*== 0|.*!= 0|.*> 0|.*else)"),
    ]

    for echelon, category, title, ptype, search in python_patterns:
        patterns.append({
            "echelon": echelon, "category": category, "title": title,
            "pattern_type": ptype, "search_pattern": search,
            "description": f"Python: {title.lower()}",
            "project": "*", "true_positive_count": 0, "false_positive_count": 0,
        })

    # Return only real patterns — no generic padding
    return patterns


def list_patterns():
    """List active patterns from DB."""
    if not DB_PATH.exists():
        print("No patterns database found")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT title, category, echelon, pattern_type, true_positive_count, false_positive_count FROM patterns ORDER BY echelon, category"
    ).fetchall()

    for r in rows:
        eff = r["true_positive_count"] / max(1, r["true_positive_count"] + r["false_positive_count"]) * 100
        print(f"  [{r['category']:8s}] E{r['echelon']} {r['title'][:50]:50s} {r['pattern_type']:8s} {eff:.0f}%")

    print(f"\nTotal: {len(rows)} patterns")
    conn.close()


def cmd_db(args):
    """Run SQL query against GSC database."""
    if not DB_PATH.exists():
        print("No GSC database found")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(args.sql).fetchall()
        for r in rows:
            print(dict(r))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()


def cmd_triage(args):
    """Interactive finding review — y/n/i/$/q + bulk mode."""
    if args.bulk:
        return triage_bulk(args)
    if args.group_by == "pattern":
        return triage_by_pattern(args)

    project = args.project or "all"
    if not DB_PATH.exists():
        print("No GSC database found"); return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM findings WHERE status='open'"
    params = []
    if project != "all":
        query += " AND project = ?"
        params.append(project)
    rows = conn.execute(query, params).fetchall()
    if not rows:
        print("✅ No open findings to triage"); conn.close(); return

    print(f"🔍 Triage: {len(rows)} open findings\n")
    print("  [y] TP  [n] FP  [i] skip  [$] skip pattern  [e] explain  [q] quit\n")

    tp = fp = skipped = spo = 0
    skipped_patterns = set()

    for r in rows:
        pid = r['pattern_id']
        # Fallback: match by title if pattern_id is NULL
        if not pid and r['title']:
            pid_row = conn.execute("SELECT id FROM patterns WHERE title=? LIMIT 1", (r['title'],)).fetchone()
            pid = pid_row['id'] if pid_row else None
        if pid and pid in skipped_patterns:
            skipped += 1; continue

        print(f"[{r['category']}] {r['title'][:80]}")
        print(f"  {r['file_path'] or '?'}:{r['line_number'] or '?'}")
        try:
            choice = input("  [y/n/i/$/e/q] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == 'y':
            conn.execute("UPDATE findings SET status='confirmed', reviewed_at=datetime('now') WHERE id=?", (r['id'],))
            if pid:
                conn.execute("""UPDATE patterns SET 
                    true_positive_count = true_positive_count + 1,
                    last_seen_at = datetime('now'),
                    effectiveness = CAST(true_positive_count + 1 AS REAL) / NULLIF(true_positive_count + 1 + false_positive_count, 0)
                    WHERE id=?""", (pid,))
                # Auto-deactivate if <30% AND >=10 ratings
                conn.execute("""UPDATE patterns SET active = 0, deactivated_at = datetime('now')
                    WHERE id=? AND effectiveness < 0.3 AND (true_positive_count + false_positive_count) >= 10""", (pid,))
            tp += 1
        elif choice == 'n':
            conn.execute("UPDATE findings SET status='false_positive', reviewed_at=datetime('now') WHERE id=?", (r['id'],))
            if pid:
                conn.execute("""UPDATE patterns SET 
                    false_positive_count = false_positive_count + 1,
                    effectiveness = CAST(true_positive_count AS REAL) / NULLIF(true_positive_count + false_positive_count + 1, 0)
                    WHERE id=?""", (pid,))
            fp += 1
        elif choice == '$':
            if pid: skipped_patterns.add(pid)
            spo += 1
        elif choice == 'e':
            print(f"  Pattern: {r['pattern_title'] or 'none'}")
            print(f"  Detail: {(r['detail'] or '')[:200]}")
            continue
        elif choice == 'i': skipped += 1; continue
        elif choice == 'q': break

    conn.commit()
    conn.close()
    print(f"\n✅ Triage: {tp} TP, {fp} FP, {spo} pattern-skips, {skipped} skipped")


def triage_by_pattern(args):
    """Group findings by pattern — accept/reject entire clusters at once."""
    project = args.project or "all"
    if not DB_PATH.exists():
        print("No GSC database found"); return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    where = f"WHERE project = '{project}'" if project != "all" else "WHERE 1=1"
    rows = conn.execute(f"SELECT pattern_title, title, COUNT(*) as cnt, category FROM findings {where} AND status='open' GROUP BY pattern_title ORDER BY cnt DESC").fetchall()

    if not rows:
        print("✅ No open findings to triage"); conn.close(); return

    tp = fp = 0
    for r in rows:
        pat = r['pattern_title'] or r['title']
        cnt = r['cnt']
        cat = r['category']
        print(f"\n[{cat}] {pat} — {cnt} findings")
        try:
            choice = input("  [y] accept all  [n] reject all  [i] skip  [q] quit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == 'y':
            conn.execute(f"UPDATE findings SET status='confirmed', reviewed_at=datetime('now') WHERE pattern_title=? AND status='open'", (pat,))
            conn.execute(f"UPDATE patterns SET true_positive_count = true_positive_count + {cnt}, effectiveness = CAST(true_positive_count + {cnt} AS REAL) / NULLIF(true_positive_count + {cnt} + false_positive_count, 0) WHERE title=?", (pat,))
            tp += cnt
        elif choice == 'n':
            conn.execute(f"UPDATE findings SET status='false_positive', reviewed_at=datetime('now') WHERE pattern_title=? AND status='open'", (pat,))
            conn.execute(f"UPDATE patterns SET false_positive_count = false_positive_count + {cnt}, effectiveness = CAST(true_positive_count AS REAL) / NULLIF(true_positive_count + false_positive_count + {cnt}, 0) WHERE title=?", (pat,))
            fp += cnt
        elif choice == 'q':
            break

    conn.commit()
    conn.close()
    print(f"\n✅ Bulk: {tp} TP, {fp} FP")


def triage_bulk(args):
    """Bulk triage from stdin JSON."""
    import json as _j
    data = _j.loads(sys.stdin.read())
    findings = data if isinstance(data, list) else data.get('findings', [])

    if not findings:
        print("No findings in input"); return

    if not DB_PATH.exists():
        print("No GSC database found"); return

    conn = sqlite3.connect(str(DB_PATH))
    auto = args.auto_accept

    tp = 0
    for f in findings:
        fid = f.get('id')
        if not fid: continue
        if auto and f.get('category') == 'CRITICAL':
            conn.execute("UPDATE findings SET status='confirmed', reviewed_at=datetime('now') WHERE id=?", (fid,))
            tp += 1
        elif auto:
            conn.execute("UPDATE findings SET status='confirmed', reviewed_at=datetime('now') WHERE id=?", (fid,))
            tp += 1

    conn.commit()
    conn.close()
    print(f"✅ Bulk: {tp} accepted out of {len(findings)}")


def cmd_explain(args):
    """Detailed explanation of a finding."""
    if not DB_PATH.exists():
        print("No database")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    fid = args.finding_id
    row = (conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone() if fid.isdigit()
           else conn.execute("SELECT * FROM findings WHERE title LIKE ? LIMIT 1", (f"%{fid}%",)).fetchone())

    if not row:
        print(f"Not found: {fid}")
        conn.close()
        return

    cat = row['category']
    threats = {"CRITICAL": ("Remotely exploitable", "CVSS 9.0+ — fix immediately"),
               "HIGH": ("Locally exploitable, data leak", "CVSS 7.0-8.9 — fix this sprint"),
               "MEDIUM": ("Weakens defenses", "CVSS 4.0-6.9 — fix within month"),
               "LOW": ("Best practice", "CVSS <4.0 — tech debt")}

    t = threats.get(cat, ("Unknown", "Unknown"))
    print(f"🔍 #{row['id']}: {row['title']}")
    fp = row['file_path'] or '?'
    ln = row['line_number'] or '?'
    st = row['status'] or 'open'
    print(f"   File: {fp}:{ln}")
    print(f"   Status: {st} | Category: {cat}")
    print(f"   Threat: {t[0]}")
    print(f"   Impact: {t[1]}")
    if row['detail']:
        print(f"   Detail: {row['detail'][:200]}")
    conn.close()


def cmd_fix(args):
    """AI-suggested fix using OpenRouter."""
    if not DB_PATH.exists():
        print("No database"); return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    fid = args.finding_id
    row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone() if fid.isdigit() else None
    if not row:
        print(f"Not found: {fid}"); conn.close(); return

    fp = row['file_path']
    project = row['project']
    # Resolve relative path against known project dirs
    if project in KNOWN_PROJECTS:
        fp = str(KNOWN_PROJECTS[project] / fp)
    elif not Path(fp).is_absolute():
        fp = str(Path.home() / project / fp)
    if not fp or not Path(fp).exists():
        print(f"File not found: {fp}"); conn.close(); return

    # Read code context
    code = Path(fp).read_text()
    lines = code.split("\n")
    ln = row['line_number'] or 1
    start = max(0, ln - 10)
    end = min(len(lines), ln + 10)
    snippet = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[start:end], start))

    print(f"🔧 GSC fix #{row['id']}: {row['title']}")
    print(f"   File: {fp}:{ln}")
    print(f"   Analyzing with OpenRouter...")

    try:
        sys.path.insert(0, str(Path(__file__).parent / "scripts"))

        # Build a fix-specific prompt (not E4 analysis — different format)
        fix_prompt = f"""## Finding
Title: {row['title']}
Category: {row['category']}
Detail: {(row['detail'] or '')}

## Code Context ({fp}:{ln})
```python
{snippet}
```

## Task
Generate the MINIMAL fix that addresses this finding. Output ONLY the diff in unified format.
Use the existing code style of this project. Do NOT refactor unrelated code.

Output format:
```diff
--- a/{fp}
+++ b/{fp}
@@ ... @@
 [your fix here]
```"""

        # Use direct OpenRouter call for fix generation
        import requests, yaml

        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            cfg_path = os.path.expanduser("~/.hermes/config.yaml")
            if os.path.exists(cfg_path):
                with open(cfg_path) as f:
                    cfg = yaml.safe_load(f)
                api_key = cfg.get("auxiliary", {}).get("vision", {}).get("api_key", "")

        if not api_key:
            print("   ❌ No OpenRouter API key found")
            conn.close(); return

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/poliakarmai/gsc",
            "X-Title": "GSC-Fix"
        }

        body = {
            "model": "google/gemini-2.5-flash",
            "messages": [
                {"role": "system", "content": "You are GSC-Fix, a code repair engine. You receive security findings and code context. Output ONLY the fix in unified diff format. Do NOT explain — just the diff."},
                {"role": "user", "content": fix_prompt}
            ],
            "max_tokens": 1200,
            "temperature": 0.1
        }

        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers, json=body, timeout=30
        )

        if r.status_code == 200:
            data = r.json()
            content = data["choices"][0]["message"]["content"]
            print(f"\n   💡 Suggested fix:\n{content}")
        else:
            print(f"   ❌ OpenRouter error {r.status_code}: {r.text[:200]}")

    except Exception as e:
        print(f"   ❌ Fix generation failed: {e}")

    conn.close()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GSC — Git Security Checker")
    sub = parser.add_subparsers(dest="command")

    # gsc scan
    scan = sub.add_parser("scan", help="Run audit on a project")
    scan.add_argument("project", help="Project name or path")
    scan.add_argument("--echelon", help="Echelons to run (e.g., '12' for source+security)")
    scan.add_argument("--deep", action="store_true", help="Enable LLM-powered deep analysis (Echelon 4)")
    scan.add_argument("--diff", action="store_true", help="Scan only changed files (git diff HEAD)")
    scan.add_argument("--sarif", action="store_true", help="Export as SARIF (GitHub Code Scanning)")
    scan.add_argument("--compliance", choices=["pci-dss","soc2","iso27001","all"], help="Compliance framework")
    scan.add_argument("--quiet", action="store_true", help="Silent mode (CI-friendly)")
    scan.add_argument("--ci", action="store_true", help="CI mode: JSON output, no interactive prompts")
    scan.add_argument("--json", action="store_true", help="Output JSON")

    # gsc init
    init = sub.add_parser("init", help="Initialize GSC in a project")
    init.add_argument("dir", nargs="?", help="Project directory (default: current)")

    # gsc dashboard
    dash = sub.add_parser("dashboard", help="Launch web dashboard")
    dash.add_argument("--port", type=int, help="Port (default: 8080)")

    # gsc patterns (with subcommands)
    patterns = sub.add_parser('patterns', help='Manage patterns')
    pat_sub = patterns.add_subparsers(dest='pat_action')
    pat_export = pat_sub.add_parser('export', help='Export patterns to YAML')
    pat_export.add_argument('file', nargs='?')
    pat_import = pat_sub.add_parser('import', help='Import patterns from YAML')
    pat_import.add_argument('file')
    pat_import.add_argument('--force', action='store_true')
    pat_list = pat_sub.add_parser('list', help='List patterns')

    # gsc db
    db = sub.add_parser("db", help="Query GSC database")
    db.add_argument("sql", help="SQL query")

    # gsc triage
    triage = sub.add_parser("triage", help="Interactive finding review (y/n/i)")
    triage.add_argument("project", nargs="?", help="Project name")
    triage.add_argument("--bulk", action="store_true", help="Bulk mode: read JSON from stdin")
    triage.add_argument("--auto-accept", action="store_true", help="Auto-accept all CRITICAL in bulk mode")
    triage.add_argument("--group-by", type=str, choices=["pattern"], help="Group by pattern (accept/reject all at once)")

    # gsc explain
    explain = sub.add_parser("explain", help="Detailed explanation of a finding")
    explain.add_argument("finding_id", help="Finding ID or pattern title")

    # gsc fix
    fix = sub.add_parser("fix", help="AI-suggested fix for a finding")
    fix.add_argument("finding_id", help="Finding ID")

    # gsc doctor
    doctor = sub.add_parser("doctor", help="Diagnose GSC environment")

    # gsc config
    config = sub.add_parser('config', help='Manage GSC settings')
    config.add_argument('action', nargs='?', choices=['show','set','init'])
    config.add_argument('key', nargs='?')
    config.add_argument('value', nargs='?')

    # gsc metrics
    metrics = sub.add_parser('metrics', help='Precision/recall metrics')

    # gsc encrypt-db
    encrypt = sub.add_parser("encrypt-db", help="Encrypt GSC database (Fernet)")

    # gsc issue
    issue = sub.add_parser('issue', help='Create Jira/Linear ticket')
    issue.add_argument('finding_id')
    issue.add_argument('--jira', action='store_true')
    issue.add_argument('--linear', action='store_true')
    issue.add_argument('--md', action='store_true')

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "init":
        cmd_init(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "patterns":
        cmd_patterns(args)
    elif args.command == "db":
        cmd_db(args)
    elif args.command == "triage":
        cmd_triage(args)
    elif args.command == "explain":
        cmd_explain(args)
    elif args.command == "fix":
        cmd_fix(args)
    elif args.command == 'config':
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_config.py'), args.action or 'show', args.key or '', args.value or ''])

    elif args.command == 'metrics':
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_metrics.py')])

    elif args.command == 'patterns':
        subprocess.run([sys.executable, str(Path(__file__).parent / 'scripts' / 'gsc_marketplace.py'), args.pat_action or 'list', getattr(args, 'file', '') or ''])

    elif args.command == 'issue':
        import importlib.util as _iu
        spec = _iu.spec_from_file_location('gsc_issue', str(Path(__file__).parent / 'scripts' / 'gsc_issue.py'))
        mod = _iu.module_from_spec(spec); spec.loader.exec_module(mod)
        finding = mod.get_finding(args.finding_id)
        if finding:
            if args.jira: mod.create_jira(finding)
            elif args.linear: mod.create_linear(finding)
            else: mod.print_markdown(finding)

    elif args.command == 'doctor':
        subprocess.run([sys.executable, str(Path(__file__).parent / "scripts" / "gsc_doctor.py")])
    elif args.command == "encrypt-db":
        subprocess.run([sys.executable, str(Path(__file__).parent / "scripts" / "db_encrypt.py"), "encrypt"])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
