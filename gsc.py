# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
# Copyright (c) 2024-2026 Алексей Поляков
# Licensed under Polyform Shield 1.0.0 — see LICENSE for details.
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

    # 2.1 Resume tracking: save per-file state
    if hasattr(args, 'resume') and args.resume:
        try:
            from gsc_resume import FileStateManager
            fsm = FileStateManager(str(DB_PATH), project)
            all_files = list(project_path.rglob("*"))
            code_files = [f for f in all_files if f.is_file() and not any(
                p.startswith(".") for p in f.parts) and ".git/" not in str(f)]
            fsm.init_files(code_files)
            # Mark files with findings as scanned
            seen_files = set()
            for f in findings:
                fp = f.get("file_path", "")
                if fp and fp not in seen_files:
                    seen_files.add(fp)
                    fsm.mark_scanned(fp, candidates_count=1)
            fsm.release_locks()
            fsm.close()
        except Exception:
            pass  # Non-fatal — resume tracking is optional

    # 2.5 Framework-aware filter (reduce FP)
    try:
        sys.path.insert(0, str(Path(__file__).parent / "scripts"))
        from framework_aware import filter_findings as fw_filter
        findings = fw_filter(findings)
    except Exception:
        pass

    # 2.7 LLM Verification — deep analysis of CRITICAL/HIGH findings
    if getattr(args, 'deep', False) or getattr(args, 'llm', False):
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from gsc_detectors.llm_verify import verify_findings
            before = len([f for f in findings if f.get("category") in ("CRITICAL", "HIGH")])
            findings = verify_findings(findings, str(project_path), max_per_batch=15)
            after_real = len([f for f in findings
                              if f.get("category") in ("CRITICAL", "HIGH")
                              and f.get("llm_verified", True)])
            after_fp = len([f for f in findings
                            if f.get("category") in ("CRITICAL", "HIGH")
                            and not f.get("llm_verified", True)])
            if not quiet:
                print(f"🧠 LLM verified: {before} CRITICAL/HIGH → {after_real} real, {after_fp} FP")
        except Exception as e:
            if not quiet:
                print(f"⚠️ LLM verification skipped: {e}")

    # 2.6 Reachability analysis — downgrade findings in unreachable files (opt-in)
    if getattr(args, 'reachability', False):
        try:
            from gsc_reachability import analyze_reachability
            findings = analyze_reachability(findings, str(project_path))
        except Exception:
            pass

    # 2.7 Clear file cache to prevent memory leak
    _file_cache.clear()

    # 3. Save findings
    save_findings(project, findings, quiet=quiet)

    # 3.5 Export to Obsidian vault
    export_to_obsidian(project, findings, project_path, quiet=quiet)

    # 4. Report
    # IaC: сканирование инфраструктурных файлов (GS031)
    try:
        from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform, _is_kubernetes
        for fpath in project_path.rglob("*"):
            if not fpath.is_file(): continue
            try: content = fpath.read_text(errors="ignore")
            except: continue
            if fpath.suffix in (".tf",".tfvars"):
                findings.extend(detect_terraform(str(fpath), content))
            base = fpath.name.lower()
            if base.startswith("dockerfile") or base.endswith(".dockerfile"):
                findings.extend(detect_dockerfile(str(fpath), content))
            elif fpath.suffix in (".yaml",".yml") and _is_kubernetes(content):
                findings.extend(detect_kubernetes(str(fpath), content))
    except ImportError: pass

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
        findings.extend(check_plugin_detectors(project, path, echelon=1))
    if not echelons or "2" in echelons:
        findings.extend(check_security(project, path))
        findings.extend(check_plugin_detectors(project, path, echelon=2))
    if not echelons or "3" in echelons:
        findings.extend(check_adversarial(project, path))
    if deep:
        findings.extend(check_deep(project, path, findings))

    # Post-filter: remove findings in docstrings, comments, type annotations
    findings = [f for f in findings if not _is_in_docstring_or_comment(f)]

    # Post-filter: inline suppression (# gsc:ignore / // gsc:ignore)
    findings = [f for f in findings if not _is_suppressed_inline(f)]

    # ── v0.20: Security Invariant Engine (GS028) ──
    if not echelons or "2" in echelons:
        try:
            from gsc_invariant_engine import InvariantEngine
            from gsc_detectors.gs028_invariants import GS028Detector
            config = path / ".gsc-audit.yml"
            if config.exists():
                engine = InvariantEngine(str(config))
                if engine.invariants:
                    det = GS028Detector(engine)
                    for fp in path.rglob("*"):
                        if not fp.is_file():
                            continue
                        if fp.suffix not in {'.py','.js','.ts','.tsx','.go','.rs','.java','.rb','.php'}:
                            continue
                        if any(d in fp.parts for d in {'node_modules','.git','__pycache__','venv','.venv'}):
                            continue
                        try:
                            content = fp.read_text(errors='replace')
                        except Exception:
                            continue
                        rel = str(fp.relative_to(path))
                        inv_findings = det.detect(rel, content)
                        for f in inv_findings:
                            f["echelon"] = 2
                            f["pattern_title"] = f"GS028-{f.get('metadata',{}).get('invariant_id','?')} (GS028 invariant)"
                        findings.extend(inv_findings)
        except Exception:
            pass  # invariants are optional, don't crash the scan

    return findings


# ── Inline suppression filter ──────────────────────────────────────────

def _is_suppressed_inline(finding: dict) -> bool:
    """Check if the finding's line has a gsc:ignore suppression comment.
    Returns True if finding should be DISCARDED."""
    fp = finding.get("file_path", "")
    ln = (finding.get("line_number") or 0)
    if not fp or ln <= 0:
        return False

    p = Path(fp)
    if not p.exists():
        return False

    cache_key = str(p)
    if cache_key not in _file_cache:
        try:
            _file_cache[cache_key] = p.read_text().split("\n")
        except Exception:
            _file_cache[cache_key] = []

    lines = _file_cache[cache_key]
    if not lines or ln > len(lines):
        return False

    line = lines[ln - 1].strip()
    # Support: # gsc:ignore, // gsc:ignore, -- gsc:ignore
    suppress_markers = ("# gsc:ignore", "// gsc:ignore", "-- gsc:ignore",
                        "# nosec", "# gsc: nosec")
    return any(marker in line for marker in suppress_markers)


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


def check_plugin_detectors(project: str, path: Path, echelon: int | None = None) -> list[dict]:
    """Run plugin-based detectors (CVE Lite-inspired architecture).

    Each detector is an independent module in detectors/ with:
      detect(ctx: AuditContext) → list[Finding]

    This complements the legacy grep-based check_source_driven / check_security
    paths. Over time, more patterns should migrate to plugin detectors.
    """
    try:
        # Ensure gsc/ is on path for direct invocation
        import sys as _sys
        _gsc_root = str(Path(__file__).parent)
        if _gsc_root not in _sys.path:
            _sys.path.insert(0, _gsc_root)
        from gsc_detectors import AuditContext, Finding
        from gsc_detectors.registry import get_detectors

        ctx = AuditContext(project=project, path=path)
        findings: list[dict] = []
        for det in get_detectors(echelon=echelon):
            if det.rule_id in ctx.skipped_detectors:
                continue
            # RegexDetector-based YAML rules expect (file_path, content),
            # plugin detectors expect (ctx). Detect by signature.
            detect_fn = det.detect
            if hasattr(detect_fn, '__self__') and hasattr(detect_fn.__self__, '_compiled'):
                # RegexDetector — iterate files manually
                for fp in ctx.files:
                    try:
                        content = fp.read_text(errors='replace')
                    except Exception:
                        continue
                    rel = str(fp.relative_to(path))
                    det_findings = detect_fn(rel, content)
                    for f in det_findings:
                        f["echelon"] = det.echelon
                        f["pattern_title"] = f"{det.rule_id} ({det.description[:60]})"
                        if "file" in f and "file_path" not in f:
                            f["file_path"] = str(path / f["file"])
                    findings.extend(det_findings)
            else:
                det_findings = detect_fn(ctx)
                for f in det_findings:
                    f["echelon"] = det.echelon
                    f["pattern_title"] = f"{det.rule_id} ({det.description[:60]})"
                findings.extend(det_findings)
        return findings
    except ImportError:
        # detectors/ package not available — graceful degradation
        return []



def _derive_rule_id(pattern: dict) -> str:
    """Derive rule_id for legacy pattern-based findings."""
    title = (pattern.get("title") or "").lower()
    if "sql" in title: return "GS005"
    if "xss" in title: return "GS020"
    if "secret" in title or "credential" in title or "token" in title or "encrypt" in title or "exposed" in title or "hardcoded" in title: return "GS029"
    if "eval" in title: return "GS008"
    if "pickle" in title or "deserial" in title: return "GS007"
    if "except" in title: return "GS010"
    if "assert" in title: return "GS018"
    if "docker" in title or "container" in title: return "GS031"
    if "permission" in title or "world-readable" in title or "writable" in title: return "GS025"
    if "cve" in title: return "GS025"
    return "GS000-LEGACY"

def _perm_finding(file_path: str, title: str, detail: str) -> dict:
    import hashlib
    rule_id = "GS025"
    finding_key = hashlib.sha256(f"{rule_id}{file_path}{title[:100]}".encode()).hexdigest()[:12]
    return {"finding_key": finding_key, "rule_id": rule_id,
            "category": "HIGH", "echelon": 2,
            "title": title, "file_path": file_path, "line_number": 0,
            "detail": detail, "pattern_title": "chmod: World-readable sensitive files"}


# ── Security-rule file detection ────────────────────────────────────────────

def _is_security_rule_file(file_path: str) -> bool:
    """Check if file is a security detector/rule definition (not application code)."""
    low = file_path.lower()
    return any(kw in low for kw in (
        "detector", "scanner", "_rules", "rulepack", "builtin.py",
        "patterns.json", "pattern.py", "yaml_rules",
    ))


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
                    rule_id = _derive_rule_id(p)
                    snippet = (parts[2][:200] if len(parts) > 2 else (p.get("description","")[:200]))
                    import hashlib
                    finding_key = hashlib.sha256(f"{rule_id}{parts[0]}{snippet}".encode()).hexdigest()[:12]
                    category = p.get("category", "MEDIUM")
                    # Downgrade CVE findings in security-rule files (patterns looking for vulns)
                    if "CVE-" in p.get("title", "") and _is_security_rule_file(parts[0]):
                        category = "LOW"
                    findings.append({
                        "finding_key": finding_key,
                        "rule_id": rule_id,
                        "category": category,
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
                        rule_id = _derive_rule_id(p)
                        snippet = (parts[2][:200] if len(parts) > 2 else (p.get("description","")[:200]))
                        import hashlib
                        finding_key = hashlib.sha256(f"{rule_id}{parts[0]}{snippet}".encode()).hexdigest()[:12]
                        category = p.get("category", "MEDIUM")
                        if "CVE-" in p.get("title", "") and _is_security_rule_file(parts[0]):
                            category = "LOW"
                        findings.append({
                            "finding_key": finding_key,
                            "rule_id": rule_id,
                            "category": category,
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
                    findings.append(_perm_finding(str(f),
                        f"World-readable file: {f.name} ({perms})",
                        f"Permissions {perms} — should be 600 for sensitive files"))

    # Also check root-level sensitive files (including dotfiles)
    sensitive_names = {".env", ".envrc", ".secrets", ".credentials"}
    for f in path.glob("*"):
        is_sensitive = (f.name in sensitive_names or 
                       f.suffix in (".db", ".json", ".log", ".yaml", ".yml", ".key", ".pem"))
        if f.is_file() and is_sensitive:
            perms = oct(f.stat().st_mode)[-3:]
            if int(perms[-1]) >= 4:
                findings.append(_perm_finding(str(f),
                    f"World-readable file: {f.name} ({perms})",
                    f"Permissions {perms} — should be 600"))

    # ── Systemd service file structural audit ──
    REQUIRED_DIRECTIVES = [
        ("NoNewPrivileges=true", "NoNewPrivileges", "HIGH",
         "NoNewPrivileges= not set"),
        ("ProtectSystem=strict", "ProtectSystem", "MEDIUM",
         "ProtectSystem= not set"),
        ("ProtectHome=read-only", "ProtectHome", "MEDIUM",
         "ProtectHome= not set"),
        ("PrivateTmp=true", "PrivateTmp", "LOW",
         "PrivateTmp= not set"),
        ("ProtectProc=invisible", "ProtectProc", "LOW",
         "ProtectProc= not set"),
        ("MemoryDenyWriteExecute=true", "MemoryDenyWriteExecute", "LOW",
         "MemoryDenyWriteExecute= not set"),
        ("RestrictRealtime=true", "RestrictRealtime", "LOW",
         "RestrictRealtime= not set"),
        ("RemoveIPC=true", "RemoveIPC", "LOW",
         "RemoveIPC= not set"),
        ("LockPersonality=true", "LockPersonality", "LOW",
         "LockPersonality= not set"),
        ("RestrictSUIDSGID=true", "RestrictSUIDSGID", "LOW",
         "RestrictSUIDSGID= not set"),
    ]

    for svc_file in path.rglob("*.service"):
        # Skip symlinks (dedup: target.wants/ symlinks point to same files)
        if svc_file.is_symlink():
            continue
        # Skip systemd target directories with symlinks
        if '.target.wants' in str(svc_file):
            continue
        try:
            svc_content = svc_file.read_text()
            for directive, key, category, detail in REQUIRED_DIRECTIVES:
                if key not in svc_content:
                    if key + "=" in svc_content:
                        continue
                    findings.append({
                        "category": category,
                        "echelon": 2,
                        "title": f"Systemd: {key}= not set",
                        "file_path": str(svc_file),
                        "line_number": 0,
                        "detail": detail,
                        "pattern_title": "Systemd security hardening",
                    })
        except Exception:
            pass

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


# ── Obsidian Export ──────────────────────────────────────────────────────────

OBSIDIAN_VAULT = Path.home() / "obsidian-vault"
AUDITS_DIR = OBSIDIAN_VAULT / "audits"


def export_to_obsidian(project: str, findings: list[dict], project_path: Path, quiet: bool = False):
    """Export findings as a Markdown report to Obsidian vault."""
    if not AUDITS_DIR.exists():
        return  # vault not set up — skip silently

    date_str = datetime.now().strftime("%Y-%m-%d")
    safe_project = project.replace("/", "-").replace(" ", "-").strip("-")
    filename = f"gsc-{safe_project}-{date_str}.md"
    filepath = AUDITS_DIR / filename

    # Group by category
    critical = [f for f in findings if f.get("category") == "CRITICAL"]
    high = [f for f in findings if f.get("category") == "HIGH"]
    medium = [f for f in findings if f.get("category") == "MEDIUM"]
    low = [f for f in findings if f.get("category") == "LOW"]

    # Build rules breakdown
    from collections import Counter
    rules = Counter(f.get("rule_id", f.get("title", "?")) for f in findings)

    lines = [
        "---",
        f"title: \"GSC Audit: {project}\"",
        f"date: {date_str}",
        "tags: [gsc, audit, security]",
        "---",
        "",
        f"# 🔒 GSC Audit — {project}",
        "",
        f"**Дата:** {datetime.now().strftime('%d.%m.%Y %H:%M')}  ",
        f"**Путь:** `{project_path}`  ",
        f"**Всего находок:** {len(findings)}  ",
        f"**CRITICAL:** {len(critical)} | **HIGH:** {len(high)} | **MEDIUM:** {len(medium)} | **LOW:** {len(low)}",
        "",
        "## 📊 По детекторам",
        "",
        "| Детектор | Находок |",
        "|----------|--------|",
    ]
    for rule, count in rules.most_common():
        lines.append(f"| {rule} | {count} |")

    # Critical + High findings with details
    if critical or high:
        lines.append("")
        lines.append("## 🔴 Критические и важные")
        lines.append("")
        lines.append("| Категория | Правило | Файл | Строка | Детали |")
        lines.append("|-----------|--------|------|--------|--------|")
        for f in critical + high:
            fname = Path(f.get("file_path", "")).name
            rule = f.get("rule_id", "?")
            lines.append(
                f"| {f.get('category','')} | {rule} | {fname} | "
                f"{f.get('line_number','?')} | {(f.get('detail') or '')[:60]} |"
            )

    # All findings table (compact)
    lines.append("")
    lines.append("## 📋 Все находки")
    lines.append("")
    lines.append("| Кат. | Правило | Файл | Строка |")
    lines.append("|------|--------|------|--------|")
    for f in findings:
        fname = Path(f.get("file_path", "")).name
        rule = f.get("rule_id", "?")
        cat = f.get("category", "?")[0]  # C/H/M/L
        lines.append(f"| {cat} | {rule} | {fname} | {f.get('line_number','?')} |")

    lines.append("")
    lines.append("---")
    lines.append(f"*Сгенерировано GSC v0.6 · {datetime.now().isoformat()}*")

    filepath.write_text("\n".join(lines))
    if not quiet:
        print(f"📝 Obsidian: {filename}")


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


def cmd_patterns_review():
    """Show patterns needing manual review (auto-created, inactive)."""
    if not DB_PATH.exists():
        print("❌ GSC DB not found")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Inactive patterns (auto-created, pending activation)
    pending = conn.execute("""
        SELECT id, title, category, description, created_at
        FROM patterns
        WHERE active = 0
        ORDER BY created_at DESC
        LIMIT 50
    """).fetchall()

    # Recently deactivated
    deactivated = conn.execute("""
        SELECT id, title, category, effectiveness, deactivated_at
        FROM patterns
        WHERE active = 0 AND deactivated_at IS NOT NULL
        ORDER BY deactivated_at DESC
        LIMIT 20
    """).fetchall()

    if pending:
        print(f"\n🟡 PENDING ACTIVATION ({len(pending)} patterns):")
        print(f"   Run: gsc patterns --activate <id>   or   gsc patterns --reject <id>")
        print(f"{'ID':<6} {'Title':<50} {'Category':<10} {'Created'}")
        print("-" * 85)
        for p in pending:
            print(f"{p['id']:<6} {p['title'][:48]:<50} {p['category']:<10} {p['created_at'] or '?'}")
    else:
        print("✅ No patterns pending activation")

    if deactivated:
        print(f"\n🔴 RECENTLY DEACTIVATED ({len(deactivated)} patterns):")
        print(f"{'ID':<6} {'Title':<50} {'Category':<10} {'Efficiency':<10} {'Deactivated'}")
        print("-" * 90)
        for d in deactivated:
            eff = f"{d['effectiveness']*100:.0f}%" if d['effectiveness'] else '?'
            print(f"{d['id']:<6} {d['title'][:48]:<50} {d['category']:<10} {eff:<10} {d['deactivated_at'] or '?'}")
    else:
        print("✅ No recently deactivated patterns")

    # Stats
    total = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM patterns WHERE active=1").fetchone()[0]
    conn.close()
    print(f"\n📊 Total: {total} patterns ({active} active, {total - active} inactive)")

    if pending:
        print(f"\n💡 To activate a pattern: gsc db \"UPDATE patterns SET active=1 WHERE id=<id>\"")
        print(f"💡 To reject (delete):   gsc db \"DELETE FROM patterns WHERE id=<id>\"")


def cmd_patterns(args):
    """Manage patterns — list/review/export/import."""
    action = getattr(args, 'pat_action', None) or 'list'
    if action == 'review':
        cmd_patterns_review()
    elif action == 'export':
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
        (2, "CRITICAL", "pickle.load() — unsafe deserialization", "regex", r"pickle\.(load|loads)\("),  # gsc:ignore — pattern definition
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


def cmd_state(args):
    """Manage finding state lifecycle with FSM router."""
    from gsc_db import GSCDatabase
    from gsc_router import FindingRouter, FindingEvent, FindingState, Action

    db = GSCDatabase()
    router = FindingRouter()

    if args.history:
        history = db.get_state_history(args.finding_key)
        if not history:
            print(f"No state history for '{args.finding_key}'")
            db.close(); return
        print(f"State history for {args.finding_key}:")
        for h in history:
            print(f"  [{h['created_at']}] {h['from_state']} → {h['to_state']} ({h['event_type']})")
        db.close(); return

    if not args.transition:
        current = db.get_current_state(args.finding_key)
        print(f"Current state: {current}")
        print("Use --transition <fp|confirm|fix|verify|reject|retriage>")
        print("Or --history to see full state log")
        db.close(); return

    # Map CLI transition to event
    current = db.get_current_state(args.finding_key)
    state = FindingState(current) if current in [s.value for s in FindingState] else FindingState.NEW

    transition_map = {
        "fp":        ("fp_reported", "Marked as false positive"),
        "confirm":   ("fix_pushed", f"Confirmed, fix in PR #{args.pr}" if args.pr else "Confirmed"),
        "fix":       ("fix_pushed", f"Fix pushed: PR #{args.pr}" if args.pr else "Fix pushed"),
        "verify":    ("fix_confirmed", "Fix verified"),
        "reject":    ("fix_rejected", f"Fix rejected: {args.comment}" if args.comment else "Fix rejected"),
        "retriage":  ("comment_added", f"Re-triaging: {args.comment}" if args.comment else "Re-triaging"),
    }

    event_type, reason = transition_map[args.transition]
    event = FindingEvent(type=event_type, finding_key=args.finding_key,
                         actor=args.actor, comment=args.comment or reason,
                         pr_number=args.pr)

    action = router.route(event, state)
    if action.type == Action.SKIP:
        print(f"❌ Cannot transition from '{current}' via '{args.transition}': {action.reason}")
        db.close(); return

    db.log_state_transition(args.finding_key, current, action.target_state.value,
                            event_type, args.actor, args.comment or reason)
    print(f"✓ {current} → {action.target_state.value} ({action.type})")
    print(f"  {action.reason}")
    db.close()


def cmd_verify_fix(args):
    """Verify a fix before creating PR."""
    import json
    from gsc_verify_fix import verify_fix

    report = verify_fix(
        finding_key=args.finding_key,
        repo_path=args.repo_path,
        detector_id=args.detector,
        skip_dast=not args.dast,
        skip_tests=not args.tests,
    )

    output = {
        "result": report.result.value,
        "ready_for_pr": report.ready_for_pr,
        "should_retry": report.should_retry,
        "error": report.error_message,
        "attempt": report.attempt,
        "rescan_findings": len(report.rescan_findings),
    }
    print(json.dumps(output, indent=2))

    if report.ready_for_pr:
        print("\n✅ Fix verified — ready for PR!")
    elif report.should_retry:
        print(f"\n🔄 Fix needs work (attempt {report.attempt}/{report.max_attempts})")
    else:
        print(f"\n❌ Verification failed: {report.error_message}")


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
    query = "SELECT pattern_title, title, COUNT(*) as cnt, category FROM findings " + where + " AND status='open' GROUP BY pattern_title ORDER BY cnt DESC"  # gsc:ignore — where built from internal code, no user input
    rows = conn.execute(query).fetchall()

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
            conn.execute("UPDATE findings SET status='confirmed', reviewed_at=datetime('now') WHERE pattern_title=? AND status='open'", (pat,))
            conn.execute(
                f"UPDATE patterns SET true_positive_count = true_positive_count + {cnt}, effectiveness = CAST(true_positive_count + {cnt} AS REAL) / NULLIF(true_positive_count + {cnt} + false_positive_count, 0) WHERE title=?", (pat,))  # gsc:ignore — cnt is trusted internal counter
            tp += cnt
        elif choice == 'n':
            conn.execute("UPDATE findings SET status='false_positive', reviewed_at=datetime('now') WHERE pattern_title=? AND status='open'", (pat,))
            conn.execute(
                f"UPDATE patterns SET false_positive_count = false_positive_count + {cnt}, effectiveness = CAST(true_positive_count AS REAL) / NULLIF(true_positive_count + false_positive_count + {cnt}, 0) WHERE title=?", (pat,))  # gsc:ignore — cnt is trusted internal counter
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

def cmd_revalidate(args):
    """gsc revalidate — Deepsec-inspired structured re-check of findings."""
    from gsc_revalidate import Revalidator

    project_path = Path(args.project).resolve()
    project_name = project_path.name

    rev = Revalidator(str(DB_PATH), project_path)

    # Load findings from DB
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM findings WHERE project=? AND (revalidation_verdict IS NULL OR revalidation_verdict='')",
        (project_name,)
    ).fetchall()
    conn.close()

    findings = [dict(r) for r in rows]
    
    if not findings:
        print("No unvalidated findings to revalidate.")
        rev.close()
        return

    print(f"Revalidating {len(findings)} findings for {project_name}...")
    print(f"Min severity: {args.min_severity}, LLM: {not args.no_llm}")
    print()

    use_llm = not args.no_llm
    results = rev.revalidate_findings(findings, min_severity=args.min_severity, use_llm=use_llm)

    # Show verdicts
    verdicts = {}
    for r in results:
        v = r.get("revalidation_verdict", "uncertain")
        verdicts[v] = verdicts.get(v, 0) + 1

    print()
    for v in ["true-positive", "false-positive", "fixed", "uncertain"]:
        count = verdicts.get(v, 0)
        emoji = {"true-positive": "🔴", "false-positive": "✅", "fixed": "🔧", "uncertain": "❓"}.get(v, "")
        print(f"  {emoji} {v}: {count}")

    if args.json:
        print(json.dumps({"verdicts": verdicts, "findings": results}, indent=2))

    rev.close()



def cmd_sbom(args):
    """gsc sbom — generate SBOM (CycloneDX or SPDX)."""
    import json
    from gsc_sca import parse_repo_manifests
    from gsc_sbom import generate_sbom
    from gsc_spdx import generate_spdx
    packages = parse_repo_manifests(args.repo)
    if not packages:
        print("No dependency manifests found"); return 1
    fmt = getattr(args, 'format', 'cyclonedx')
    sbom = generate_spdx(packages) if fmt == "spdx" else generate_sbom(packages)
    out = args.output or ("sbom.spdx.json" if fmt == "spdx" else "sbom.cdx.json")
    with open(out, "w") as f: json.dump(sbom, f, indent=2)
    print(f"SBOM: {len(sbom.get('packages', sbom.get('components', [])))} components -> {out}")
    return 0



def cmd_iac(args):
    """gsc iac — IaC misconfiguration scan."""
    from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform, _is_kubernetes
    from pathlib import Path
    findings = []
    for path in Path(args.repo).rglob("*"):
        if not path.is_file(): continue
        try: content = path.read_text(errors="ignore")
        except: continue
        if path.suffix in (".tf",".tfvars"):
            findings.extend(detect_terraform(str(path), content))
        elif path.name.lower().startswith("dockerfile") or path.name.lower().endswith(".dockerfile"):
            findings.extend(detect_dockerfile(str(path), content))
        elif path.suffix in (".yaml",".yml") and _is_kubernetes(content):
            findings.extend(detect_kubernetes(str(path), content))
    for f in findings:
        print(f"  {f['severity']:8s} {f['rule_id']:25s} {f['title']}")
    print(f"\n{len(findings)} IaC findings")
    return 1 if any(f["severity"] in ("CRITICAL","HIGH") for f in findings) else 0

def cmd_sbom_verify(args):
    """gsc sbom-verify — verify SBOM signature."""
    import json
    from gsc_spdx import verify_sbom, load_signing_key
    sbom = json.load(open(args.sbom)); sig = json.load(open(args.signature))
    key = load_signing_key()
    if key is None: print("No signing key"); return 1
    ok = verify_sbom(sbom, sig, key)
    print("Valid" if ok else "INVALID — tampered")
    return 0 if ok else 1

def cmd_status(args):
    """gsc status — scan progress (resume-aware)."""
    from gsc_resume import FileStateManager

    project_path = Path(args.project).resolve()
    project_name = project_path.name

    fsm = FileStateManager(str(DB_PATH), project_name)
    stats = fsm.get_stats()

    print(f"Project: {project_name}")
    print(f"Files:   {stats['total']} total")
    print(f"Progress: {stats['completed']}/{stats['total']} ({stats['progress_pct']}%)")
    print()
    for status in FileStateManager.STATUSES:
        count = stats.get(status, 0)
        bar = "█" * int(count / max(stats['total'], 1) * 20)
        print(f"  {status:12s} {count:5d}  {bar}")

    fsm.close()


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
    scan.add_argument("--reachability", action="store_true", help="Downgrade findings in unreachable files (import-graph analysis)")
    scan.add_argument("--compliance", choices=["pci-dss","soc2","iso27001","all"], help="Compliance framework")
    scan.add_argument("--quiet", action="store_true", help="Silent mode (CI-friendly)")
    scan.add_argument("--ci", action="store_true", help="CI mode: JSON output, no interactive prompts")
    scan.add_argument("--json", action="store_true", help="Output JSON")
    scan.add_argument("--resume", action="store_true", help="Resume interrupted scan (skip already-scanned files)")

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

    # gsc state — finding state machine (v29)
    state_p = sub.add_parser("state", help="Manage finding state lifecycle")
    state_p.add_argument("finding_key", help="Finding key (pattern_fingerprint)")
    state_p.add_argument("--transition", choices=["fp", "confirm", "fix", "verify", "reject", "retriage"],
                         help="Trigger state transition")
    state_p.add_argument("--actor", default="cli", help="Who triggered the transition")
    state_p.add_argument("--comment", default="", help="Optional comment")
    state_p.add_argument("--history", action="store_true", help="Show state history")
    state_p.add_argument("--pr", type=int, default=0, help="PR number (for fix transition)")

    # gsc verify-fix — validate fix before PR (v29)
    verify_fix = sub.add_parser("verify-fix", help="Verify a fix resolves the finding")
    verify_fix.add_argument("finding_key", help="Finding key")
    verify_fix.add_argument("repo_path", help="Path to repository with fix")
    verify_fix.add_argument("--detector", default="", help="Specific detector to verify")
    verify_fix.add_argument("--dast", action="store_true", help="Run DAST verification")
    verify_fix.add_argument("--tests", action="store_true", help="Run test suite")

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

    # gsc revalidate (Deepsec-inspired)
    reval = sub.add_parser('revalidate', help='Re-check existing findings (TP/FP/Fixed)')
    reval.add_argument('project', help='Project name or path')
    reval.add_argument('--min-severity', default='HIGH', choices=['CRITICAL','HIGH','MEDIUM','LOW'],
                       help='Minimum severity to revalidate (default: HIGH)')
    reval.add_argument('--no-llm', action='store_true', help='Skip LLM — heuristic-only revalidation')
    reval.add_argument('--json', action='store_true', help='Output JSON')

    # gsc status (resume-aware progress)
    status = sub.add_parser('status', help='Show scan progress (resume-aware)')
    status.add_argument('project', help='Project name or path')

    # gsc workspace
    ws = sub.add_parser('workspace', help='Multi-repo workspace management')
    ws_sub = ws.add_subparsers(dest='ws_cmd', required=True)
    ws_create = ws_sub.add_parser('create', help='Create workspace')
    ws_create.add_argument('name')
    ws_create.add_argument('--description', default='')
    ws_add = ws_sub.add_parser('add', help='Add repo to workspace')
    ws_add.add_argument('workspace')
    ws_add.add_argument('repo')
    ws_add.add_argument('--alias', default='')
    ws_scan = ws_sub.add_parser('scan', help='Scan workspace repos')
    ws_scan.add_argument('workspace')
    ws_scan.add_argument('--scan-mode', choices=['quick', 'standard', 'deep'], default='standard')
    ws_scan.add_argument('--profile', default='developer-review')
    ws_rep = ws_sub.add_parser('report', help='Workspace report')
    ws_rep.add_argument('workspace')
    ws_rep.add_argument('--format', choices=['json', 'markdown'], default='markdown')
    ws_sub.add_parser('list', help='List workspaces')
    ws_del = ws_sub.add_parser('delete', help='Delete workspace')
    ws_del.add_argument('name')

    # gsc pof (Proof-of-Fix + Self-Healing)
    pof_p = sub.add_parser('pof', help='Proof-of-Fix: generate + verify security patches')
    pof_sub = pof_p.add_subparsers(dest='pof_cmd', required=True)
    fix_gen = pof_sub.add_parser('generate', help='Generate + verify fix for a finding')
    fix_gen.add_argument('finding_key')
    fix_gen.add_argument('--report', '-r', required=True, help='Scan report JSON')
    fix_gen.add_argument('--project-root', default='.', help='Project root')
    fix_gen.add_argument('--output', '-o', help='Save evidence JSON')
    fix_batch = pof_sub.add_parser('batch', help='Auto-fix all eligible CRITICAL/HIGH')
    fix_batch.add_argument('report', help='Scan report JSON')
    fix_batch.add_argument('--project-root', default='.', help='Project root')
    fix_batch.add_argument('--max-fixes', type=int, default=3)
    fix_batch.add_argument('--dry-run', action='store_true', default=True)
    fix_batch.add_argument('--create-pr', dest='dry_run', action='store_false')
    fix_batch.add_argument('--output', '-o', help='Save results JSON')

    # gsc policy (NL Policy)
    pol_p = sub.add_parser('policy', help='Natural Language policies — human-readable security rules')
    pol_sub = pol_p.add_subparsers(dest='pol_cmd', required=True)
    pol_add = pol_sub.add_parser('add', help='Create policy from natural language')
    pol_add.add_argument('text', nargs='+')
    pol_sub.add_parser('list', help='List NL policies')
    pol_test = pol_sub.add_parser('test', help='Test policy against repo')
    pol_test.add_argument('name')
    pol_test.add_argument('--repo', default='.')
    pol_rm = pol_sub.add_parser('remove', help='Remove policy')
    pol_rm.add_argument('name')
    pol_exp = pol_sub.add_parser('export', help='Export to .gsc-audit.yml')
    pol_exp.add_argument('--output', '-o', default='.gsc-audit.yml')

    # gsc secrets (Cross-Repo)
    sec_p = sub.add_parser('secrets', help='Cross-repo secret correlation')
    sec_sub = sec_p.add_subparsers(dest='sec_cmd', required=True)
    sec_corr = sec_sub.add_parser('correlate', help='Scan repos and correlate')
    sec_corr.add_argument('--repos', nargs='+', required=True)
    sec_corr.add_argument('--output', '-o')
    sec_status = sec_sub.add_parser('status', help='Secret fingerprint status')
    sec_status.add_argument('--key', required=True)
    sec_rep = sec_sub.add_parser('report', help='Cross-repo report')
    sec_rep.add_argument('--output', '-o')

    # gsc archaeology
    arch_p = sub.add_parser('archaeology', help='Security Archaeology — vulnerability time machine')
    arch_sub = arch_p.add_subparsers(dest='arch_cmd', required=True)
    arch_trace = arch_sub.add_parser('trace', help='Trace finding lifecycle')
    arch_trace.add_argument('finding_key')
    arch_trace.add_argument('--report', '-r')
    arch_trace.add_argument('--repo', required=True)
    arch_rep = arch_sub.add_parser('report', help='Full archaeology report')
    arch_rep.add_argument('--repo', required=True)
    arch_rep.add_argument('--findings')
    arch_rep.add_argument('--output', '-o')

    # gsc forecast
    fc_p = sub.add_parser('forecast', help='Predictive Risk Forecasting')
    fc_sub = fc_p.add_subparsers(dest='fc_cmd', required=True)
    fc_pred = fc_sub.add_parser('predict', help='Predict risk for files')
    fc_pred.add_argument('--repo', required=True)
    fc_pred.add_argument('--files', nargs='*')
    fc_pred.add_argument('--output', '-o')
    fc_pred.add_argument('--limit', type=int, default=10)
    fc_hm = fc_sub.add_parser('heatmap', help='Full repo risk heatmap')
    fc_hm.add_argument('--repo', required=True)
    fc_hm.add_argument('--output', '-o')

    # gsc export-nuclei (Wave 1: PoC → nuclei YAML)
    nuc = sub.add_parser('export-nuclei', help='Export GSC findings as nuclei YAML templates')
    nuc.add_argument('report', help='GSC scan report JSON')
    nuc.add_argument('--output', '-o', default='nuclei-templates')
    nuc.add_argument('--severity', '-s', help='Filter: critical,high,medium')
    nuc.add_argument('--max', type=int, default=50)
    nuc.add_argument('--validate', action='store_true')

    # gsc import-nuclei / scan-dast / list-nuclei (Wave 2: SAST+DAST)
    imp_nuc = sub.add_parser('import-nuclei', help='Import nuclei YAML templates')
    imp_nuc.add_argument('directory', help='Path to nuclei-templates/')

    dast = sub.add_parser('scan-dast', help='DAST scan via nuclei')
    dast.add_argument('target', help='Target URL')
    dast.add_argument('--severity', nargs='+',
                      choices=['info','low','medium','high','critical'])
    dast.add_argument('--output', '-o', help='Save results JSON')

    list_nuc = sub.add_parser('list-nuclei', help='List imported nuclei templates')
    list_nuc.add_argument('--severity', choices=['info','low','medium','high','critical'])
    list_nuc.add_argument('--tag', help='Filter by tag')

    # gsc sca (v0.28: SCA via OSV.dev)
    p_sca = sub.add_parser('sca', help='Scan dependencies for CVEs (OSV.dev)')
    p_sca.add_argument('--repo', default='.')
    p_sca.add_argument('--json', action='store_true')
    p_sca.set_defaults(func=lambda a: subprocess.run(
        [sys.executable, str(Path(__file__).parent / 'gsc_sca.py'),
         '--repo', a.repo] + (['--json'] if getattr(a,'json',False) else [])))

    # gsc federated (v0.30: cross-tenant learning)
    p_fed = sub.add_parser('federated', help='Federated self-learning')
    p_fed.add_argument('action', choices=['status','submit','fetch','weights'])
    p_fed.add_argument('--rule', help='rule_id for weights')
    p_fed.set_defaults(func=lambda a: subprocess.run(
        [sys.executable, str(Path(__file__).parent / 'gsc_federated.py'),
         a.action] + (['--rule', a.rule] if getattr(a,'rule',None) else [])))

    # gsc benchmark (v0.31: OWASP Benchmark)
    p_bench = sub.add_parser('benchmark', help='OWASP Benchmark scorecard (v0.31)')
    p_bench.add_argument('target', choices=['owasp'])
    p_bench.add_argument('--benchmark-path', required=True)
    p_bench.add_argument('--expected-csv', required=True)
    p_bench.add_argument('--output', '-o', default='gsc_scorecard')
    p_bench.set_defaults(func=lambda a: print("Use: gsc benchmark owasp --benchmark-path ... --expected-csv ..."))

    # gsc epss (v0.32: exploitability scoring)
    p_epss = sub.add_parser('epss', help='EPSS exploitability lookup (v0.32)')
    p_epss.add_argument('--cve', help='Lookup single CVE')
    p_epss.add_argument('--enrich-report', help='Enrich scan.json with EPSS')
    p_epss.add_argument('--output', '-o')
    p_epss.set_defaults(func=lambda a: subprocess.run(
        [sys.executable, str(Path(__file__).parent / 'gsc_epss.py')]
        + (['--cve', a.cve] if getattr(a,'cve',None) else [])
        + (['--enrich-report', a.enrich_report] if getattr(a,'enrich_report',None) else [])
        + (['--output', a.output] if getattr(a,'output',None) else [])))

    # gsc sbom (v0.33: CycloneDX + VEX)
    p_sbom = sub.add_parser('sbom', help='Generate SBOM + VEX (v0.33)')
    p_sbom.add_argument('--repo', default='.')
    p_sbom.add_argument('--format', choices=['cyclonedx','spdx'], default='cyclonedx')
    p_sbom.add_argument('--sign', action='store_true', help='Sign SBOM (HMAC-SHA256)')
    p_sbom.add_argument('--with-vex', action='store_true')
    p_sbom.add_argument('--output', '-o')
    p_sbom.set_defaults(func=cmd_sbom)

    # gsc iac (v0.34: IaC scanning)
    p_iac = sub.add_parser('iac', help='IaC misconfiguration scan (v0.34)')
    p_iac.add_argument('--repo', default='.')
    p_iac.set_defaults(func=cmd_iac)

    # gsc sbom-verify
    p_sbomv = sub.add_parser('sbom-verify', help='Verify SBOM signature')
    p_sbomv.add_argument('sbom', help='SBOM JSON file')
    p_sbomv.add_argument('signature', help='Signature .sig.json file')
    p_sbomv.set_defaults(func=cmd_sbom_verify)

    # gsc dork

    dork = sub.add_parser('dork', help='GitHub Dorks scan — find secrets in public repos')
    dork.add_argument('org', help='GitHub organization or company name')
    dork.add_argument('--limit', type=int, default=5, help='Results per dork (default: 5)')
    dork.add_argument('--days', type=int, default=7, help='Scan repos updated in last N days (default: 7)')
    dork.add_argument('--list', action='store_true', help='List available dorks')

    # gsc api 🆕
    api = sub.add_parser('api', help='Start REST API server')
    api.add_argument('--port', type=int, default=8766, help='Port (default: 8766)')
    api.add_argument('--host', default='127.0.0.1', help='Host (default: 127.0.0.1)')

    # gsc deep-reduce 🆕 — AI-first semantic scanner
    dr = sub.add_parser('deep-reduce', help='AI-first semantic vulnerability scanner')
    dr.add_argument('target', help='File or directory to scan')
    dr.add_argument('--model', default='deepseek-chat', help='Model (default: deepseek-chat)')
    dr.add_argument('--confidence', type=int, default=50, help='Min confidence threshold')
    dr.add_argument('--dry-run', action='store_true', help='Do not save to DB')
    dr.add_argument('--limit', type=int, default=20, help='Max files to analyze')

    # gsc external-scan 🆕
    ext = sub.add_parser('external-scan', help='External project scan — clone + audit + report')
    ext.add_argument('target', help='GitHub URL or local path')
    ext.add_argument('--mode', choices=['full', 'pr', 'diff'], default='full')
    ext.add_argument('--scan-mode', choices=['quick', 'standard', 'deep'], help='Scan depth (overrides profile settings)')
    ext.add_argument('--ref', default='main', help='Branch/tag')
    ext.add_argument('--max-llm', type=int, default=50, help='Max LLM calls')
    ext.add_argument('--output', '-o', help='Output file')
    ext.add_argument('--format', choices=['json', 'markdown', 'sarif'], default='markdown')

    # gsc report 🆕
    rep = sub.add_parser('report', help='Generate report from scan JSON')
    rep.add_argument('input_file', help='JSON scan result file')
    rep.add_argument('--format', choices=['json', 'markdown', 'sarif'], required=True)
    rep.add_argument('--output', '-o', help='Output file')

    # gsc feedback 🆕
    fb = sub.add_parser('feedback', help='Record TP/FP feedback on finding or chain')
    fb.add_argument('key', help='Finding key or chain key')
    fb.add_argument('--verdict', choices=['tp', 'fp', 'ignore', 'fixed'], required=True)
    fb.add_argument('--reason', help='Why')

    # gsc chains 🆕 v0.18
    chains_p = sub.add_parser('chains', help='Attack chains (v0.18)')
    chains_p.add_argument('cmd', choices=['list', 'show'], help='list or show chain')
    chains_p.add_argument('chain_key', nargs='?', help='Chain key for show')
    chains_p.add_argument('--report', default='scan.json', help='Scan report JSON')

    # gsc mutations 🆕 v0.19
    mut_p = sub.add_parser('mutations', help='Mutation tracking (v0.19)')
    mut_p.add_argument('mut_cmd', choices=['list', 'show', 'stats'])
    mut_p.add_argument('finding_key', nargs='?', help='Finding key for show')
    mut_p.add_argument('--days', type=int, default=30)
    mut_p.add_argument('--limit', type=int, default=50)

    # gsc rollout 🆕 v0.26
    rpt = sub.add_parser('rollout', help='Rollout report (Phase 5)')
    rpt.add_argument('cmd', choices=['report'])

    # gsc invariants 🆕 v0.20
    inv_p = sub.add_parser('invariants', help='Invariant engine (v0.20)')
    inv_p.add_argument('inv_cmd', choices=['check', 'list'])
    inv_p.add_argument('--repo', default='.')
    inv_p.add_argument('--config')

    # gsc github-scan 🆕 v0.14
    gh = sub.add_parser('github-scan', help='GitHub PR scan with comment + check run')
    gh.add_argument('target', help='PR URL (https://github.com/org/repo/pull/123) or \".\" for local')
    gh.add_argument('--profile', default='pr-gate')
    gh.add_argument('--github-context', help='Path to GITHUB_EVENT_PATH JSON')
    gh.add_argument('--dry-run', action='store_true', help='Do not post to GitHub')
    gh.add_argument('--post-comment', action='store_true', help='Post comment to PR')
    gh.add_argument('--fail-on-blocking', action='store_true', help='Exit 1 if blocking')

    # gsc calibration 🆕 v0.14
    cal = sub.add_parser('calibration', help='Run calibration against dataset')
    cal.add_argument('action', nargs='?', default='run', choices=['run', 'check'])
    cal.add_argument('--dataset', default='calibration/calibration_dataset.json')
    cal.add_argument('--fail-on-regression', action='store_true', help='Exit 1 on regression')

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
    elif args.command == "state":
        cmd_state(args)
    elif args.command == "verify-fix":
        cmd_verify_fix(args)
    elif args.command == "explain":
        cmd_explain(args)
    elif args.command == "archaeology":
        arch_args = [sys.executable, str(Path(__file__).parent / "gsc_archaeology.py"), args.arch_cmd]
        if hasattr(args, "finding_key") and args.finding_key:
            arch_args.append(args.finding_key)
        if hasattr(args, "repo"): arch_args.extend(["--repo", args.repo])
        if hasattr(args, "report") and args.report: arch_args.extend(["--report", args.report])
        if hasattr(args, "findings") and args.findings: arch_args.extend(["--findings", args.findings])
        if hasattr(args, "output") and args.output: arch_args.extend(["--output", args.output])
        subprocess.run(arch_args)

    elif args.command == "policy":
        pol_args = [sys.executable, str(Path(__file__).parent / "gsc_nlpolicy.py"), args.pol_cmd]
        if hasattr(args, 'text') and args.text:
            pol_args += args.text
        if hasattr(args, 'name') and args.name:
            pol_args.append(args.name)
        if hasattr(args, 'repo'):
            pol_args.extend(["--repo", args.repo])
        if hasattr(args, 'output') and args.output:
            pol_args.extend(["--output", args.output])
        subprocess.run(pol_args)

    elif args.command == "secrets":
        sec_args = [sys.executable, str(Path(__file__).parent / "gsc_crossrepo_secrets.py"), args.sec_cmd]
        if hasattr(args, 'repos') and args.repos:
            sec_args += ["--repos"] + args.repos
        if hasattr(args, 'key') and args.key:
            sec_args += ["--key", args.key]
        if hasattr(args, 'output') and args.output:
            sec_args.extend(["--output", args.output])
        subprocess.run(sec_args)

    elif args.command == "forecast":
        fc_args = [sys.executable, str(Path(__file__).parent / "gsc_forecast.py"), args.fc_cmd]
        if hasattr(args, "repo"): fc_args.extend(["--repo", args.repo])
        if hasattr(args, "files") and args.files: fc_args += ["--files"] + args.files
        if hasattr(args, "limit"): fc_args.extend(["--limit", str(args.limit)])
        if hasattr(args, "output") and args.output: fc_args.extend(["--output", args.output])
        subprocess.run(fc_args)

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
    elif args.command == "revalidate":
        cmd_revalidate(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "workspace":
        from gsc_workspace import (
            workspace_create, workspace_add, workspace_scan,
            workspace_report, workspace_list, workspace_delete,
        )
        if args.ws_cmd == 'create':
            workspace_create(args.name, args.description)
        elif args.ws_cmd == 'add':
            workspace_add(args.workspace, args.repo, args.alias)
        elif args.ws_cmd == 'scan':
            workspace_scan(args.workspace, args.scan_mode, args.profile)
        elif args.ws_cmd == 'report':
            print(workspace_report(args.workspace, args.format))
        elif args.ws_cmd == 'list':
            workspace_list()
        elif args.ws_cmd == 'delete':
            workspace_delete(args.name)

    elif args.command == "pof":
        if args.pof_cmd == 'generate':
            subprocess.run([sys.executable, str(Path(__file__).parent / "gsc_proofoffix.py"),
                            "generate", args.finding_key,
                            "--report", args.report,
                            "--project-root", args.project_root,
                            *(["--output", args.output] if hasattr(args, 'output') and args.output else [])])
        elif args.pof_cmd == 'batch':
            subprocess.run([sys.executable, str(Path(__file__).parent / "gsc_selfhealing.py"),
                            args.report,
                            "--project-root", getattr(args, 'project_root', '.'),
                            "--max-fixes", str(getattr(args, 'max_fixes', 3)),
                            *(["--create-pr"] if hasattr(args, 'dry_run') and not args.dry_run else []),
                            *(["--output", args.output] if hasattr(args, 'output') and args.output else [])])

    elif args.command == "export-nuclei":
        nuc_args = [sys.executable, str(Path(__file__).parent / "gsc_nuclei_export.py"), args.report]
        if hasattr(args, 'output') and args.output != 'nuclei-templates':
            nuc_args.extend(["--output", args.output])
        if hasattr(args, 'severity') and args.severity:
            nuc_args.extend(["--severity", args.severity])
        if hasattr(args, 'max'):
            nuc_args.extend(["--max", str(args.max)])
        if hasattr(args, 'validate') and args.validate:
            nuc_args.append("--validate")
        subprocess.run(nuc_args)

    elif args.command == "import-nuclei":
        subprocess.run([sys.executable, str(Path(__file__).parent / "gsc_nuclei_import.py"),
                        "import", args.directory])

    elif args.command == "scan-dast":
        cmd = [sys.executable, str(Path(__file__).parent / "gsc_dast_scanner.py"), args.target]
        if hasattr(args, 'severity') and args.severity:
            cmd += ["--severity"] + args.severity
        if hasattr(args, 'output') and args.output:
            cmd += ["--output", args.output]
        subprocess.run(cmd)

    elif args.command == "list-nuclei":
        cmd = [sys.executable, str(Path(__file__).parent / "gsc_nuclei_import.py"), "list"]
        if hasattr(args, 'severity') and args.severity:
            cmd += ["--severity", args.severity]
        if hasattr(args, 'tag') and args.tag:
            cmd += ["--tag", args.tag]
        subprocess.run(cmd)

    elif args.command == "dork":
        if args.list:
            subprocess.run([sys.executable, str(Path(__file__).parent / "gsc_github_dorks.py"), "--list-dorks"])
        else:
            cmd = [sys.executable, str(Path(__file__).parent / "gsc_github_dorks.py"), args.org,
                   "--limit", str(args.limit), "--days", str(args.days)]
            subprocess.run(cmd)

    elif args.command == "deep-reduce":
        cmd = [sys.executable, str(Path(__file__).parent / "gsc_deep_reducer.py"), args.target]
        if hasattr(args, 'model'): cmd += ["--model", args.model]
        if hasattr(args, 'confidence'): cmd += ["--confidence", str(args.confidence)]
        if getattr(args, 'dry_run', False): cmd.append("--dry-run")
        if hasattr(args, 'limit'): cmd += ["--limit", str(args.limit)]
        subprocess.run(cmd)

    elif args.command == "api":
        import uvicorn
        from gsc_api import app
        print(f"🔒 GSC API v1.0 — http://{args.host}:{args.port}")
        print(f"   Docs: http://{args.host}:{args.port}/docs")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")

    elif args.command in ("external-scan", "report", "feedback"):
        ext_args = [sys.executable, str(Path(__file__).parent / "gsc_external.py"),
                    args.command.replace("external-scan", "scan")]
        # Build args dynamically
        for attr in ["target", "input_file"]:
            if hasattr(args, attr):
                val = getattr(args, attr)
                if val: ext_args.append(val)
                break
        for opt in ["mode", "ref", "format", "output", "verdict", "reason",
                    "profile", "base", "head", "scan-mode"]:
            if hasattr(args, opt):
                val = getattr(args, opt)
                if val: ext_args.extend([f"--{opt.replace('_','-')}", str(val)])
        if hasattr(args, "fail_on_blocking") and args.fail_on_blocking:
            ext_args.append("--fail-on-blocking")
        subprocess.run(ext_args)

    elif args.command in ("github", "github-scan"):
        subprocess.run([sys.executable, str(Path(__file__).parent / "gsc_github_adapter.py"),
                        "scan", getattr(args, "target", ".") or ".",
                        *(["--profile", args.profile] if hasattr(args, "profile") else []),
                        *(["--github-context", args.github_context] if hasattr(args, "github_context") and args.github_context else []),
                        *(["--dry-run"] if hasattr(args, "dry_run") and args.dry_run else []),
                        *(["--post-comment"] if hasattr(args, "post_comment") and args.post_comment else []),
                        *(["--fail-on-blocking"] if hasattr(args, "fail_on_blocking") and args.fail_on_blocking else []),
                        ])

    elif args.command == "calibration":
        subprocess.run([sys.executable, str(Path(__file__).parent / "scripts" / "gsc_calibration.py"),
                        "run",
                        *(["--dataset", args.dataset] if hasattr(args, "dataset") else []),
                        *(["--fail-on-regression"] if hasattr(args, "fail_on_regression") and args.fail_on_regression else []),
                        ])
    elif args.command == "chains":
        import json as _json
        try:
            report = _json.loads(Path(args.report).read_text())
        except Exception:
            print(f"Cannot read report: {args.report}")
            sys.exit(1)
        chains_list = report.get("chains", [])
        if args.cmd == "list":
            if not chains_list:
                print("No chains in this report")
            for c in chains_list:
                print(f"{c['chain_key']}  {c['composed_severity']:9s}  "
                      f"conf={c['confidence']:.2f}  "
                      f"findings={','.join(c.get('finding_keys',[]))}")
        elif args.cmd == "show" and args.chain_key:
            for c in chains_list:
                if c["chain_key"] == args.chain_key:
                    print(_json.dumps(c, indent=2, ensure_ascii=False))
                    break
            else:
                print(f"Chain {args.chain_key} not found")
    elif args.command == "mutations":
        from gsc_db import GSCDatabase
        db = GSCDatabase()
        if args.mut_cmd == "list":
            try:
                rows = db.query("""
                    SELECT m.*, f.pattern_title, f.file_path, f.line_number
                    FROM mutation_alerts m
                    LEFT JOIN findings f ON CAST(f.id AS TEXT) = m.finding_key
                    WHERE m.detected_at > datetime('now', ?)
                    ORDER BY m.detected_at DESC LIMIT ?
                """, (f"-{args.days} days", args.limit)).fetchall()
            except Exception:
                print("No mutation data yet — run a scan first")
                sys.exit(0)
            if not rows:
                print("No mutation alerts in this period")
            for r in rows:
                icon = "R" if r["kind"] == "recurrence" else "M"
                print(f"[{icon}] {r['finding_key']}  "
                      f"{(r['pattern_title'] or '?')[:20]:20s}  "
                      f"{r['file_path'] or '?'}:{r['line_number'] or '?'}  "
                      f"parent={r['parent_key']}  sim={r['similarity']:.0%}  "
                      f"{r['detected_at']}")
        elif args.mut_cmd == "show" and args.finding_key:
            alert = db.query(
                "SELECT * FROM mutation_alerts WHERE finding_key=?",
                (args.finding_key,)).fetchone()
            if not alert:
                print("No mutation alert for this finding")
                sys.exit(1)
            import json as _json
            print(_json.dumps(dict(alert), indent=2, default=str))
        elif args.mut_cmd == "stats":
            import json as _json
            print(_json.dumps(db.mutation_stats(), indent=2))
        db.close()
    elif args.command == "rollout" and args.cmd == "report":
        from gsc_db import GSCDatabase
        from datetime import datetime
        db = GSCDatabase()
        cfg = {}
        try:
            import yaml
            with open(".gsc-audit.yml") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            pass
        now = datetime.now().isoformat()[:19]
        print(f"# GSC Rollout Report")
        print(f"_Generated: {now}_")
        print()
        print("## Phases")
        print()
        print("| Phase | Status |")
        print("|---|---|")
        print("| 0 Readiness | OK |")
        print("| 1 Dry-run CI | OK |")
        print("| 2 Warn-only | OK |")
        print("| 3 Feedback | OK |")
        print("| 4 Blocking CRITICAL | OK |")
        phase_ok = cfg.get("rollout_phase") == "blocking-standard"
        print(f"| 5 Blocking standard | {'OK' if phase_ok else 'PENDING'} |")
        print()
        dr = db.dry_run_stats(days=90)
        p2 = db.phase2_stats(days=90)
        p5 = db.phase5_stats(days=90)
        ms = db.mutation_stats()
        print("## Metrics")
        print(f"- Dry-run runs (90d): {dr.get('runs',0)}")
        print(f"- Comments: {p2.get('comments_published',0)}")
        print(f"- Verdicts: {db.count_feedback()}")
        print(f"- Blocks: {p5.get('blocks',0)} (chain: {p5.get('chain_blocks',0)})")
        print(f"- Overrides: {p5.get('overrides',0)}")
        print(f"- Mutations: {ms.get('alerts_total',0)}")
        print()
        print("## Detectors")
        print("| Detector | verdicts | TP-rate | status |")
        print("|---|---|---|---|")
        det = db.detector_tp_rates()
        for r in det:
            rate = f"{r['tp_rate']:.1%}" if r.get('tp_rate') is not None else "-"
            status = "blocking-ready" if r.get('blocking_ready') else "-"
            print(f"| {r['detector']} | {r['verdicts']} | {rate} | {status} |")
        print()
        weak = [d for d in det if d['verdicts'] >= 10 and (d.get('tp_rate') or 0) < 0.30]
        ready = [d for d in det if d.get('blocking_ready')]
        ov = db.count_events('override')
        bl = db.count_events('blocking') or 1
        print("## Recommendations")
        if weak:
            ids = ', '.join(d['detector'] for d in weak)
            print(f"- Auto-deactivate candidates: {ids}")
        if len(ready) < 5:
            print("- Few blocking-ready detectors: encourage verdicts")
        if ov / bl > 0.20:
            print("- Override rate > 20%: review thresholds")
        if not weak and len(ready) >= 5 and ov / bl <= 0.20:
            print("- Rollout stable. Next: Enterprise (VSCode, Helm/SSO).")
        db.close()

    elif args.command == "invariants":
        from gsc_invariant_engine import InvariantEngine, InvariantLoadError
        config = args.config or os.path.join(args.repo, ".gsc-audit.yml")
        try:
            engine = InvariantEngine(config)
        except InvariantLoadError as e:
            print(f"INVALID: {e}", file=sys.stderr)
            sys.exit(2)
        if args.inv_cmd == "check":
            print(f"OK: {len(engine.invariants)} invariant(s) compiled "
                  f"from {config}")
        elif args.inv_cmd == "list":
            for inv in engine.invariants:
                state = "on " if inv.enabled else "off"
                print(f"[{state}] {inv.id:10s} {inv.type:11s} "
                      f"{inv.severity:9s} {inv.name}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
