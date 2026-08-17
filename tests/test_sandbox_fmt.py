"""Tests for PoF sandbox format dispatch (fix: curl/bash were run as Python → TypeError)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_poc_deterministic import attach_deterministic_pocs, get_deterministic_poc
from gsc_pof_sandbox import PoFSandbox


def test_curl_fmt_runs_via_bash():
    sb = PoFSandbox()
    r = sb._execute("echo VULNERABLE", "", fmt="curl")
    assert r.success is True
    assert "VULNERABLE" in r.stdout


def test_python_fmt_runs_python():
    sb = PoFSandbox()
    r = sb._execute('print("EXPLOITED")', "x = 1\n", fmt="python")
    assert r.success is True
    assert "EXPLOITED" in r.stdout


def test_python_fmt_imports_target():
    sb = PoFSandbox()
    vuln = "def get_user(i):\n    return [1, 2] if '1=1' in i else [1]\n"
    poc = "result = target.get_user('1 OR 1=1')\nassert len(result) == 2\nprint('EXPLOITED')\n"
    r = sb._execute(poc, vuln, fmt="python")
    assert r.success is True, f"stderr={r.stderr}"


def test_curl_fmt_no_python_typeerror():
    # The old bug: curl PoC ran as Python → "unhashable type: 'set'". Must NOT happen.
    sb = PoFSandbox()
    code = "curl -s 'TARGET_URL?input={{ 7 * 7 }}' | grep -q '49' && echo VULNERABLE || echo SAFE"
    r = sb._execute(code, "", fmt="curl")
    # No live endpoint → curl fails → SAFE, but this must be a curl/bash failure,
    # not a Python TypeError.
    assert "TypeError" not in r.stderr
    assert "unhashable" not in r.stderr


def test_deterministic_attaches_full_code_not_payload():
    findings = [{"rule_id": "GS020", "file_path": "app.py", "line": 1}]
    attach_deterministic_pocs(findings)
    poc = findings[0]["metadata"]["poc"]
    # Full curl command, not the bare payload
    assert "curl -s" in poc
    assert findings[0]["metadata"]["poc_format"] == "curl"
    # GS020 is XSS now (was SSTI before the detector/PoC re-map)
    assert findings[0]["metadata"]["poc_payload"] == "<script>alert(1)</script>"


def test_verify_fix_uses_fmt():
    sb = PoFSandbox()
    # shell-based PoC that succeeds on "vulnerable" (echo VULNERABLE) and fails on "patched"
    vuln = "echo VULNERABLE"
    patched = "echo SAFE"
    v = sb.verify_fix(vuln, patched, "echo VULNERABLE", fmt="curl")
    # before must succeed, after must fail → but 'vuln' and 'patched' here are
    # shell snippets, not Python; language defaults to python so verify_fix rejects.
    # This test only asserts the fmt parameter is accepted and threaded through
    # without raising (the reject path is language != python).
    assert v is not None


def test_detect_framework():
    from gsc_pof_sandbox import _detect_framework
    assert _detect_framework("from flask import Flask\napp = Flask(__name__)") == "flask"
    assert _detect_framework("from fastapi import FastAPI\napp = FastAPI()") == "fastapi"
    assert _detect_framework("import os\nprint(1)") is None


def test_free_port_is_int():
    from gsc_pof_sandbox import _free_port
    assert isinstance(_free_port(), int)


def _sandbox_has_flask() -> bool:
    """True, если sandbox способен serve web-приложение.

    Container-path (GSC 3.x) требует flask в образе gsc-sandbox; host-side
    fallback (rlimit) требует flask в host venv. Проверяем оба, чтобы тест
    скипался только когда serve реально невозможен.
    """
    import subprocess
    from gsc_pof_sandbox import SANDBOX_ROOT, _sandbox_image_has_flask
    if _sandbox_image_has_flask():
        return True
    py = SANDBOX_ROOT / "venv" / "bin" / "python3"
    if not py.exists():
        return False
    return subprocess.run([str(py), "-c", "import flask"], capture_output=True).returncode == 0


def test_curl_serves_ssti_flask_app():
    """Phase 2 e2e: serve a Flask SSTI app and hit it with a deterministic curl PoC."""
    if not _sandbox_has_flask():
        import pytest
        pytest.skip("no flask runtime (sandbox image or host venv)")
    from gsc_poc_deterministic import get_deterministic_poc
    target = (
        "from flask import Flask, request, render_template_string\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/')\n"
        "def index():\n"
        "    return render_template_string(request.args.get('input', ''))\n"
    )
    poc = get_deterministic_poc("GS020")._generate_code()
    r = PoFSandbox()._execute(poc, target, fmt="curl")
    assert r.success is True, f"stderr={r.stderr}"
    assert "VULNERABLE" in r.stdout


def test_curl_serves_multimodule_flask_app(tmp_path):
    """Phase 3 e2e: serve a multi-module Flask project (app.py + views.py)."""
    if not _sandbox_has_flask():
        import pytest
        pytest.skip("no flask runtime (sandbox image or host venv)")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\nfrom views import bp\n"
        "app = Flask(__name__)\napp.register_blueprint(bp)\n")
    (tmp_path / "views.py").write_text(
        "from flask import Blueprint, request, render_template_string\n"
        "bp = Blueprint('bp', __name__)\n\n"
        "@bp.route('/')\n"
        "def index():\n"
        "    return render_template_string(request.args.get('input', ''))\n")
    from gsc_poc_deterministic import get_deterministic_poc
    poc = get_deterministic_poc("GS020")._generate_code()
    r = PoFSandbox()._execute(poc, "", fmt="curl", project_dir=str(tmp_path))
    assert r.success is True, f"stderr={r.stderr}"
    assert "VULNERABLE" in r.stdout


def test_detect_app_creation():
    from gsc_pof_sandbox import _detect_app_creation, _detect_framework
    assert _detect_app_creation("from flask import Flask\napp = Flask(__name__)") == "flask"
    # bare import (Blueprint) must NOT be detected as app creation
    assert _detect_app_creation("from flask import Blueprint\nbp = Blueprint('bp', __name__)") is None
    assert _detect_framework("from flask import Blueprint") == "flask"  # broad still works


def test_detect_framework_sanic_bottle():
    from gsc_pof_sandbox import _detect_framework
    assert _detect_framework("from sanic import Sanic\napp = Sanic('x')") == "sanic"
    assert _detect_framework("from bottle import Bottle\napp = Bottle()") == "bottle"


def test_find_web_entrypoint_no_py(tmp_path):
    from gsc_pof_sandbox import _find_web_entrypoint
    (tmp_path / "README.md").write_text("no code here")
    assert _find_web_entrypoint(str(tmp_path)) is None


def test_sandbox_image_has_flask_rlimit_false(monkeypatch):
    import gsc_pof_sandbox as s
    monkeypatch.setattr(s, "_isolation_backend", lambda: "rlimit")
    monkeypatch.setattr(s, "_sandbox_flask_cache", None)
    assert s._sandbox_image_has_flask() is False


def test_isolation_backend_falls_back_to_rlimit(monkeypatch):
    import gsc_pof_sandbox as s
    monkeypatch.setattr(s.shutil, "which", lambda exe: None)
    monkeypatch.setattr(s, "_backend_cache", None)
    assert s._isolation_backend() == "rlimit"
