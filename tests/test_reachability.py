"""Tests for Reachability Analysis (Ф5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_reachability import (
    collect_python_usage, collect_js_usage, collect_go_usage,
    is_reachable, module_names_for_package,
)


def test_collect_imports_and_calls(tmp_path):
    (tmp_path / "app.py").write_text(
        "import yaml\nimport requests\n\ndef f():\n    yaml.load(data)\n    requests.get(url)\n"
    )
    usage = collect_python_usage(tmp_path)
    assert "yaml" in usage["imports"]
    assert "requests" in usage["imports"]
    assert "load" in usage["calls"]
    assert "get" in usage["calls"]


def test_skips_venv_and_pycache(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "x.py").write_text("import secret\n")
    (tmp_path / "real.py").write_text("import flask\n")
    usage = collect_python_usage(tmp_path)
    assert "secret" not in usage["imports"]
    assert "flask" in usage["imports"]


def test_is_reachable_via_mapping():
    usage = {"imports": {"yaml", "requests"}, "calls": set()}
    assert is_reachable("PyYAML", usage) is True     # via PACKAGE_IMPORT_MAP
    assert is_reachable("requests", usage) is True


def test_is_not_reachable():
    usage = {"imports": {"flask"}, "calls": set()}
    assert is_reachable("django", usage) is False


def test_is_reachable_by_call():
    usage = {"imports": set(), "calls": {"load"}}
    assert is_reachable("PyYAML", usage, vulnerable_funcs={"load"}) is True


def test_module_names_mapping():
    assert "yaml" in module_names_for_package("PyYAML")
    assert "pil" in module_names_for_package("Pillow")


def test_sca_findings_downgrade_not_reachable():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="django", version="2.2", ecosystem="PyPI",
                  manifest="requirements.txt", line=1, raw="django==2.2")
    osv = {("PyPI", "django", "2.2"): [{
        "id": "CVE-2020-1",
        "summary": "x",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"flask"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "not_reachable"
    assert findings[0]["severity"] == "HIGH"          # CRITICAL → HIGH downgrade
    assert findings[0]["metadata"]["original_severity"] == "CRITICAL"


def test_sca_findings_reachable_keeps_severity():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="django", version="2.2", ecosystem="PyPI",
                  manifest="requirements.txt", line=1, raw="django==2.2")
    osv = {("PyPI", "django", "2.2"): [{
        "id": "CVE-2020-1",
        "summary": "x",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"django"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "reachable"
    assert findings[0]["severity"] == "CRITICAL"


# ── JS/TS (npm) reachability ────────────────────────────────

def test_collect_js_usage_esm_and_require(tmp_path):
    (tmp_path / "app.js").write_text(
        "import _ from 'lodash';\nimport x from '@babel/core/lib/parser';\n"
        "const y = require('express');\nimport './local-util';\nimport fs from 'node:fs';\n"
    )
    usage = collect_js_usage(tmp_path)
    assert "lodash" in usage["imports"]
    assert "@babel/core" in usage["imports"]       # scoped → root specifier
    assert "express" in usage["imports"]
    assert "./local-util" not in usage["imports"]  # relative dropped
    assert "node:fs" not in usage["imports"]       # builtin dropped


def test_js_reachable_via_import():
    usage = {"imports": {"lodash"}}
    assert is_reachable("lodash", usage, ecosystem="npm") is True
    assert is_reachable("react", usage, ecosystem="npm") is False


def test_js_scoped_package_reachable():
    usage = {"imports": {"@babel/core"}}
    assert is_reachable("@babel/core", usage, ecosystem="npm") is True
    assert is_reachable("@babel/preset-env", usage, ecosystem="npm") is False


def test_sca_findings_npm_downgrade_not_reachable():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm",
                  manifest="package.json", line=1, raw="lodash@4.17.20")
    osv = {("npm", "lodash", "4.17.20"): [{
        "id": "CVE-2021-23337",
        "summary": "command injection",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"react"}, "calls": set()}  # lodash never imported
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "not_reachable"
    assert findings[0]["severity"] == "HIGH"          # CRITICAL → HIGH
    assert findings[0]["metadata"]["original_severity"] == "CRITICAL"


def test_sca_findings_npm_reachable_keeps_severity():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm",
                  manifest="package.json", line=1, raw="lodash@4.17.20")
    osv = {("npm", "lodash", "4.17.20"): [{
        "id": "CVE-2021-23337",
        "summary": "command injection",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"lodash"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "reachable"
    assert findings[0]["severity"] == "CRITICAL"


# ── Go reachability ─────────────────────────────────────────

def test_collect_go_usage_single_and_block(tmp_path):
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'import (\n    "fmt"\n    "github.com/spf13/cobra"\n)\n'
        '// import "github.com/commented/out"\n'
    )
    usage = collect_go_usage(tmp_path)
    assert "github.com/gin-gonic/gin" in usage["imports"]
    assert "github.com/spf13/cobra" in usage["imports"]
    assert "github.com/commented/out" not in usage["imports"]  # comment stripped


def test_go_reachable_exact_and_subpackage():
    usage = {"imports": {"github.com/gin-gonic/gin"}}
    assert is_reachable("github.com/gin-gonic/gin", usage, ecosystem="Go") is True
    # subpackage import counts as reachable for the parent module
    usage = {"imports": {"github.com/gin-gonic/gin/binding"}}
    assert is_reachable("github.com/gin-gonic/gin", usage, ecosystem="Go") is True
    assert is_reachable("github.com/spf13/cobra", usage, ecosystem="Go") is False


def test_collect_go_usage_aliased_imports(tmp_path):
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import f "fmt"\n'
        'import _ "net/http/pprof"\n'
        'import . "github.com/foo/bar"\n'
    )
    usage = collect_go_usage(tmp_path)
    assert "fmt" in usage["imports"]                 # aliased
    assert "net/http/pprof" in usage["imports"]      # side-effect (blank)
    assert "github.com/foo/bar" in usage["imports"]  # dot import


# ── Cross-ecosystem isolation (regression: no FP reachability) ──

def test_no_cross_ecosystem_reachability():
    # Python code imports 'express'; npm package 'express' is NOT imported in JS.
    usage = {
        "PyPI": {"imports": {"express"}, "calls": set()},
        "npm": {"imports": set()},
        "Go": {"imports": set()},
    }
    assert is_reachable("express", usage, ecosystem="npm") is False


def test_no_cross_ecosystem_reachability_reverse():
    # JS imports 'react'; a PyPI package literally named 'react' must NOT match.
    usage = {
        "PyPI": {"imports": set(), "calls": set()},
        "npm": {"imports": {"react"}},
        "Go": {"imports": set()},
    }
    assert is_reachable("react", usage, ecosystem="PyPI") is False


def test_js_dynamic_import_and_comment_fp(tmp_path):
    (tmp_path / "app.js").write_text(
        "// import x from 'commented-out';\n"
        "const m = await import('lazy-pkg');\n"
        "myimport y from 'not-a-real-import';\n"
    )
    usage = collect_js_usage(tmp_path)
    assert "commented-out" not in usage["imports"]  # comment stripped
    assert "lazy-pkg" in usage["imports"]           # dynamic import() caught
    assert "not-a-real-import" not in usage["imports"]  # myimport identifier not matched


def test_sca_findings_go_downgrade_not_reachable():
    from gsc_sca import sca_findings, Package
    pkg = Package(name="github.com/gin-gonic/gin", version="1.7.0", ecosystem="Go",
                  manifest="go.mod", line=1, raw="github.com/gin-gonic/gin v1.7.0")
    osv = {("Go", "github.com/gin-gonic/gin", "1.7.0"): [{
        "id": "CVE-2020-28483",
        "summary": "x",
        "affected": [{"database_specific": {"severity": "CRITICAL"}}],
    }]}
    usage = {"imports": {"github.com/spf13/cobra"}, "calls": set()}
    findings = sca_findings([pkg], osv, usage=usage)
    assert findings[0]["metadata"]["reachability"] == "not_reachable"
    assert findings[0]["severity"] == "HIGH"
