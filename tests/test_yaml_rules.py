"""Tests for the Semgrep YAML-DSL compiler (Ф3)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_yaml_rules import semgrep_pattern_to_regex, YamlRule


def test_metavariable():
    assert semgrep_pattern_to_regex("eval($X)") == r"eval\([\w.]+\)"


def test_ellipsis():
    assert semgrep_pattern_to_regex("danger(...)") == r"danger\([\s\S]*?\)"


def test_spread():
    assert semgrep_pattern_to_regex("foo($...ARGS)") == r"foo\([\s\S]*?\)"


def test_inline_regex_passthrough():
    assert semgrep_pattern_to_regex(r'/password\s*=\s*"[^"]+"/') == r'password\s*=\s*"[^"]+"'


def test_literal_escaping():
    assert semgrep_pattern_to_regex("a.b(c)") == r"a\.b\(c\)"


def test_yaml_rule_semgrep_pattern_compiles():
    rule = YamlRule({
        "id": "python-eval-injection",
        "severity": "ERROR",
        "message": "eval with dynamic input",
        "languages": ["python"],
        "pattern": "eval($X)",
    })
    assert len(rule.patterns) == 1
    assert rule.severity == "CRITICAL"


def test_yaml_rule_pattern_either():
    rule = YamlRule({
        "id": "dangerous-calls",
        "severity": "WARNING",
        "message": "dangerous call",
        "languages": ["python"],
        "pattern-either": [
            {"pattern": "eval($X)"},
            {"pattern": "exec($X)"},
        ],
    })
    assert len(rule.patterns) == 2
    assert rule.severity == "HIGH"


def test_detector_contract_file_path():
    rule = YamlRule({
        "id": "python-eval-injection",
        "severity": "ERROR",
        "message": "eval",
        "languages": ["python"],
        "pattern": "eval($X)",
    })
    ns = {}
    exec(rule.to_detector_code(), ns)
    det = ns["detector"]
    res = det.detect("app.py", "x = eval(user_input)\n", "python")
    assert res, "expected a finding"
    f = res[0]
    assert f["file_path"] == "app.py"
    assert f["line_number"] == 1
    assert "eval" in f["detail"]
    assert f["category"] == "CRITICAL"
