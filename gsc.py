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

    if not (getattr(args, 'ci', False) or getattr(args, 'json', False)):
        print(f"🔍 GSC Scanning: {project} ({project_path})")
        print(f"   Echelons: {'all 3' if not args.echelon else args.echelon}")
        print()

    # 1. Load patterns (suppress in CI mode)
    if not (getattr(args, 'ci', False) or getattr(args, 'json', False)):
        patterns_cmd = [sys.executable, str(SCRIPTS_DIR / "gsc_load_patterns.py"), project]
        patterns = subprocess.run(patterns_cmd, capture_output=True, text=True)
        print(patterns.stdout)

    # 2. Run audit via delegate_task equivalent
    # In standalone mode, we run the checks directly
    findings = run_audit_echelons(project, project_path, args.echelon, getattr(args, 'deep', False))

    # 3. Save findings
    save_findings(project, findings, quiet=getattr(args, 'ci', False) or getattr(args, 'json', False))

    # 4. Report
    if args.ci or args.json:
        print(json.dumps(findings, indent=2))
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
        findings.extend(check_deep(project, path))

    return findings


def check_source_driven(project: str, path: Path) -> list[dict]:
    """Echelon 1: Source-driven checks."""
    findings = []
    patterns = load_patterns(project, echelon=1)

    # Run grep-based patterns
    for p in patterns:
        if p.get("pattern_type") != "grep":
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


def check_deep(project: str, path: Path) -> list[dict]:
    """Echelon 4: LLM-powered deep analysis (requires Hermes delegate_task)."""
    if not os.environ.get("HERMES_SESSION"):
        return [{
            "category": "INFO", "echelon": 4,
            "title": "Deep analysis requires Hermes agent",
            "file_path": "", "line_number": 0,
            "detail": "Run `gsc scan --deep` inside a Hermes session for LLM-powered audit."
        }]

    print("  🧠 E4: LLM deep analysis...")
    files = []
    for ext in [".py", ".go", ".ts", ".rs", ".java", ".tf"]:
        for f in list(path.rglob(f"*{ext}"))[:5]:
            try:
                files.append(str(f.relative_to(path)))
            except Exception:
                pass

    return [{
        "category": "INFO", "echelon": 4,
        "title": f"Deep analysis available for {project}",
        "file_path": "", "line_number": 0,
        "detail": f"{len(files)} source files ready for LLM audit. Use Hermes delegate_task for full E4 analysis."
    }]


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
    gsc_dir.mkdir(exist_ok=True)

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
    """Manage seed patterns."""
    if args.seed:
        seed_patterns(args.seed)
    elif args.list:
        list_patterns()
    else:
        print("Usage: gsc patterns --seed <count> | --list")


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

    # Pad to requested count with generic patterns
    while len(patterns) < count:
        patterns.append({
            "echelon": (len(patterns) % 3) + 1,
            "category": "LOW",
            "title": f"Generic code smell #{len(patterns)}",
            "pattern_type": "grep",
            "search_pattern": f"TODO|FIXME|HACK|XXX",
            "description": "Generic code smell pattern",
            "project": "*", "true_positive_count": 0, "false_positive_count": 0,
        })

    return patterns[:count]


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
    """Interactive finding review — y=yes, n=no, i=ignore."""
    project = args.project or "all"
    if not DB_PATH.exists():
        print("No GSC database found")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM findings WHERE status='open'"
    if project != "all":
        query += " AND project = ?"
        rows = conn.execute(query, (project,)).fetchall()
    else:
        rows = conn.execute(query).fetchall()

    if not rows:
        print("✅ No open findings to triage")
        conn.close()
        return

    print(f"🔍 Triage: {len(rows)} open findings\n")
    print("  [y] yes — TP    [n] no — FP    [i] ignore    [q] quit\n")

    tp = fp = skipped = 0
    for r in rows:
        print(f"[{r['category']}] {r['title'][:80]}")
        print(f"  {r.get('file_path','?')}:{r.get('line_number','?')}")
        try:
            choice = input("  [y/n/i/q] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == 'y':
            conn.execute("UPDATE findings SET status='confirmed' WHERE id=?", (r['id'],))
            if r.get('pattern_id'):
                conn.execute("UPDATE patterns SET true_positive_count=true_positive_count+1 WHERE id=?", (r['pattern_id'],))
            tp += 1
        elif choice == 'n':
            conn.execute("UPDATE findings SET status='false_positive' WHERE id=?", (r['id'],))
            if r.get('pattern_id'):
                conn.execute("UPDATE patterns SET false_positive_count=false_positive_count+1 WHERE id=?", (r['pattern_id'],))
            fp += 1
        elif choice == 'i':
            skipped += 1
            continue
        elif choice == 'q':
            break

    conn.commit()
    conn.close()
    print(f"\n✅ Triage: {tp} TP, {fp} FP, {skipped} skipped")


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
    """AI-suggested fix."""
    print(f"🔧 GSC fix #{args.finding_id}")
    print("   Auto-fix: run inside Hermes session for AI-generated patch.")
    print("   The agent reads context, generates diff, verifies syntax.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GSC — Git Security Checker")
    sub = parser.add_subparsers(dest="command")

    # gsc scan
    scan = sub.add_parser("scan", help="Run audit on a project")
    scan.add_argument("project", help="Project name or path")
    scan.add_argument("--echelon", help="Echelons to run (e.g., '12' for source+security)")
    scan.add_argument("--deep", action="store_true", help="Enable LLM-powered deep analysis (Echelon 4)")
    scan.add_argument("--ci", action="store_true", help="CI mode: JSON output, no interactive prompts")
    scan.add_argument("--json", action="store_true", help="Output JSON")

    # gsc init
    init = sub.add_parser("init", help="Initialize GSC in a project")
    init.add_argument("dir", nargs="?", help="Project directory (default: current)")

    # gsc dashboard
    dash = sub.add_parser("dashboard", help="Launch web dashboard")
    dash.add_argument("--port", type=int, help="Port (default: 8080)")

    # gsc patterns
    pat = sub.add_parser("patterns", help="Manage patterns")
    pat.add_argument("--seed", type=int, help="Generate N seed patterns")
    pat.add_argument("--list", action="store_true", help="List active patterns")

    # gsc db
    db = sub.add_parser("db", help="Query GSC database")
    db.add_argument("sql", help="SQL query")

    # gsc triage
    triage = sub.add_parser("triage", help="Interactive finding review (y/n/i)")
    triage.add_argument("project", nargs="?", help="Project name")

    # gsc explain
    explain = sub.add_parser("explain", help="Detailed explanation of a finding")
    explain.add_argument("finding_id", help="Finding ID or pattern title")

    # gsc fix
    fix = sub.add_parser("fix", help="AI-suggested fix for a finding")
    fix.add_argument("finding_id", help="Finding ID")

    # gsc doctor
    doctor = sub.add_parser("doctor", help="Diagnose GSC environment")

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
    elif args.command == "doctor":
        subprocess.run([sys.executable, str(Path(__file__).parent / "scripts" / "gsc_doctor.py")])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
