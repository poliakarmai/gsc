"""tests/test_gs020_xss_injection.py — positive/negative fixtures for GS020.

Covers the SSTI precision fix: render_template_string(<CONSTANT>) / a static
literal is a static template (not user input) and must NOT fire, while user
input reaching the template string (variable / f-string / request.args) still
must. Also guards the OWASP seed: the "print() instead of logging" quality
pattern must be gone (it produced 45/47 legacy noise on real projects).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs020_xss_injection as gs020


@pytest.fixture()
def scan(tmp_path):
    def _scan(files):
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        ctx = AuditContext(project="test", path=tmp_path)
        return gs020.detect(ctx)
    return _scan


def _titles(fs):
    return [f["title"] for f in fs]


# ── SSTI precision: static template vs user input ──────────────────────────

def test_ssti_template_const_skip(scan):
    # module-level UPPER_SNAKE constant — static template, not user input
    fs = scan({"web.py": "TEMPLATE = '<html></html>'\n"
                          "return render_template_string(TEMPLATE, data=x)\n"})
    assert not any("SSTI" in t for t in _titles(fs))


def test_ssti_static_literal_skip(scan):
    # plain string literal without interpolation/concat — static
    fs = scan({"web.py": "return render_template_string('<b>hi</b>')\n"})
    assert not any("SSTI" in t for t in _titles(fs))


def test_ssti_user_input_fires(scan):
    fs = scan({"web.py": "return render_template_string(user_input)\n"})
    assert any("SSTI" in t for t in _titles(fs))


def test_ssti_fstring_fires(scan):
    fs = scan({"web.py": 'return render_template_string(f"<b>{name}</b>")\n'})
    assert any("SSTI" in t for t in _titles(fs))


def test_ssti_request_args_fires(scan):
    fs = scan({"web.py": "return render_template_string(request.args.get('input', ''))\n"})
    assert any("SSTI" in t for t in _titles(fs))


def test_innerhtml_variable_fires(scan):
    # .innerHTML = <variable> is ambiguous — must NOT be suppressed. The variable
    # may be attacker-controlled (pygoat a9.js `li.innerHTML = data.logs[i]`).
    # Only static string literals are FP-suppressed (in _is_false_positive).
    fs = scan({"app.js": "li.innerHTML = data.logs[i];\n"})
    assert any(".innerHTML" in t for t in _titles(fs))


def test_fstring_function_param_fires(scan):
    # reflected XSS where the interpolated value arrives as a function argument
    # (taint source lives in the caller, outside the context window) — must fire.
    fs = scan({"web.py": "def render(name):\n    return f\"<div>{name}</div>\"\n"})
    assert any("f-string" in t for t in _titles(fs))


# ── OWASP seed: no "print() instead of logging" quality noise ──────────────

def test_seed_has_no_print_instead_of_logging():
    from gsc_cli.main import generate_seed_patterns
    titles = [p["title"] for p in generate_seed_patterns(200)]
    assert not any("print() instead of logging" in t for t in titles)
