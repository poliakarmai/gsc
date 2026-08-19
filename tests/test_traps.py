"""Trap corpus — lookalike-but-safe snippets to guard FP rate (from DS double-free-samples idea).

Каждый trap — это код, который *выглядит* уязвимо, но безопасен. Если GSC
поднимает на нём CRITICAL/HIGH — это ложное срабатывание (регресс precision).

Методика заимствована из обзора Digital Security «SAST для самых маленьких»:
уязвимые кейсы + «ловушки» (lookalike) для замера FP. Здесь — только ловушки.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from test_corpus import scan_file


def _no_finding(findings, keyword, category=None) -> bool:
    """True если НЕТ находки с keyword (и, опц., category) — т.е. ловушка не поймана."""
    for f in findings:
        if keyword.lower() in f.get("title", "").lower():
            if category is None or f.get("category") == category:
                return False
    return True


def _assert_no_finding(code, keyword, category=None, label=""):
    findings = scan_file(code)
    assert _no_finding(findings, keyword, category), \
        f"[{label or keyword}] FP: safe code flagged as {category or keyword}. " \
        f"findings={[f.get('title') for f in findings]}"


# ── Secrets (GS001/GS029): placeholders / examples не должны палиться ─────────

def test_trap_secret_placeholder():
    _assert_no_finding(
        'password = "changeme"\napi_key = "your-api-key-here"\n',
        "secret", "HIGH", "placeholder secret")


# ── SQLi (GS005): параметризация и ORM безопасны ─────────────────────────────

def test_trap_parameterized_sql():
    _assert_no_finding(
        'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
        "sql", "CRITICAL", "parameterized SQL")


def test_trap_orm_query():
    _assert_no_finding(
        'row = User.query.filter_by(id=uid).first()\n',
        "sql", "CRITICAL", "ORM query")


# ── XSS (GS020): sanitizer / autoescape безопасны ────────────────────────────

def test_trap_sanitized_xss():
    _assert_no_finding(
        'from markupsafe import escape\nhtml = escape(user_input)\n',
        "xss", "CRITICAL", "sanitized XSS")


def test_trap_jinja_autoescape():
    _assert_no_finding(
        'return render_template("page.html", name=user_input)\n',
        "xss", "CRITICAL", "jinja autoescape")


# ── Command injection (GS004): fixed argv без shell безопасен ────────────────

def test_trap_fixed_subprocess():
    _assert_no_finding(
        'import subprocess\nsubprocess.run(["git", "status"])\n',
        "subprocess", "CRITICAL", "fixed argv subprocess")


# ── eval / deserialization: безопасные альтернативы ──────────────────────────

def test_trap_ast_literal_eval():
    _assert_no_finding(
        'import ast\nval = ast.literal_eval(data)\n',
        "eval", "HIGH", "ast.literal_eval")


def test_trap_json_not_pickle():
    _assert_no_finding(
        'import json\nobj = json.loads(data)\n',
        "pickle", "CRITICAL", "json.loads not pickle")
