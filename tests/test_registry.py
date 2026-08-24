"""Tests for the GSC rule registry (Phase 3 — own rule registry).

Contract:
- compile_rules() compiles source YAML rules from gsc-rules/;
- to_detector_code() generates an executable detector with a correct import;
- compile_and_write() is merge-safe: does not clobber already-existing rules;
- compiled rules connect to the detector registry (rule_id = YAML-*);
- YAML_RULES_DIR is the canonical path, CWD-independent.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_yaml_rules import (
    YamlRule, compile_rules, compile_and_write, _regenerate_init, YAML_RULES_DIR,
)


def _sample_rule(id="test-rule", severity="HIGH", confidence=0.8):
    return YamlRule({
        "id": id,
        "severity": severity,
        "confidence": confidence,
        "languages": ["python"],
        "message": "test rule",
        "patterns": [{"regex": r"os\.system\(", "title": "os.system()"}],
    })


def test_yaml_rules_dir_is_absolute_and_canonical():
    assert YAML_RULES_DIR.is_absolute()
    assert YAML_RULES_DIR.name == "yaml_rules"
    assert "gsc_detectors" in YAML_RULES_DIR.parts


def test_compile_rules_from_gsc_rules_dir():
    repo_root = Path(__file__).parent.parent
    sample = repo_root / "gsc-rules" / "no-unsafe-deserialization.yml"
    assert sample.exists(), "sample rule is missing from gsc-rules/"
    rules = compile_rules(str(sample))
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "no-unsafe-deserialization"
    assert r.severity == "CRITICAL"
    assert len(r.patterns) >= 3
    assert len(r.not_patterns) >= 1


def test_to_detector_code_has_correct_import_and_contract():
    rule = _sample_rule()
    code = rule.to_detector_code()
    # absolute import — works via the top-level gsc_detectors shim
    assert "from gsc_detectors.base import RegexDetector" in code
    ns = {}
    exec(code, ns)
    det = ns["detector"]
    res = det.detect("app.py", "os.system('id')\n", "python")
    assert res, "detector should yield a finding"
    f = res[0]
    assert f["file_path"] == "app.py"
    assert f["rule_id"].startswith("YAML-")


def test_compile_and_write_is_merge_safe():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # simulate an already-compiled rule
        (d / "existing_rule.py").write_text("# pre-existing\n")
        compile_and_write([_sample_rule(id="new-rule")], str(d))
        init = (d / "__init__.py").read_text()
        # merge-safe: both must remain in __all__
        assert "existing_rule" in init, "MERGE BUG: existing rule was lost"
        assert "new_rule" in init, "new rule was not added"


def test_regenerate_init_lists_all_py():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.py").write_text("# a")
        (d / "b.py").write_text("# b")
        (d / "c.py").write_text("# c")
        modules = _regenerate_init(d)
        assert modules == ["a", "b", "c"]
        init = (d / "__init__.py").read_text()
        assert "__all__ = ['a', 'b', 'c']" in init


def test_compiled_rules_connected_to_registry():
    from gsc_detectors.registry import get_detectors
    yaml_ids = [d.rule_id for d in get_detectors() if d.rule_id.startswith("YAML-")]
    assert len(yaml_ids) >= 5, "expected ≥5 connected YAML rules"
