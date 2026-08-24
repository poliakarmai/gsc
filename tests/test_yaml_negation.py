"""Negation guards (pattern-not / not / not-patterns) — YAML-DSL (#3).

`pattern-not`: правило матчит позитивный паттерн,
но НЕ поднимает находку, если строка с матчем попадает под guard-паттерн.
Реализация — line-level (regex-движок без AST): многострочный/AST-level
negation (double-free через переприсваивание в соседнем statement) вне
скоупа regex-детектора.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_yaml_rules import YamlRule


def _detector(rule_dict):
    ns = {}
    exec(YamlRule(rule_dict).to_detector_code(), ns)
    return ns["detector"]


# ── Парсинг ────────────────────────────────────────────────────────────────

def test_parse_pattern_not():
    rule = YamlRule({
        "id": "eval-no-literal",
        "severity": "CRITICAL",
        "message": "eval with dynamic input",
        "languages": ["python"],
        "pattern": "eval($X)",
        "pattern-not": "ast.literal_eval($X)",
    })
    assert rule.not_patterns == [r"ast\.literal_eval\([\w.]+\)"]


def test_parse_gsc_not_list():
    rule = YamlRule({
        "id": "eval-no-literal",
        "severity": "CRITICAL",
        "message": "eval",
        "languages": ["python"],
        "patterns": [{"regex": r"\beval\s*\(", "title": "eval()"}],
        "not": [{"regex": r"ast\.literal_eval"}],
    })
    assert rule.not_patterns == [r"ast\.literal_eval"]


def test_parse_not_patterns_alias():
    rule = YamlRule({
        "id": "x",
        "message": "x",
        "pattern": "eval($X)",
        "not-patterns": [r"literal_eval"],
    })
    assert rule.not_patterns == [r"literal_eval"]


def test_no_negation_means_empty():
    rule = YamlRule({
        "id": "x",
        "message": "x",
        "pattern": "eval($X)",
    })
    assert rule.not_patterns == []


# ── Поведение детектора ────────────────────────────────────────────────────

def test_negation_suppresses_guard_line():
    det = _detector({
        "id": "eval-no-literal",
        "severity": "CRITICAL",
        "message": "eval",
        "languages": ["python"],
        "pattern": "eval($X)",
        "pattern-not": "ast.literal_eval($X)",
    })
    # vulnerable — флагается
    assert det.detect("a.py", "x = eval(user_input)\n", "python")
    # safe — та же строка под guard → не флагается
    assert not det.detect("a.py", "x = ast.literal_eval(user_input)\n", "python")


def test_negation_only_suppresses_matching_line():
    det = _detector({
        "id": "eval-no-literal",
        "severity": "CRITICAL",
        "message": "eval",
        "languages": ["python"],
        "pattern": "eval($X)",
        "pattern-not": "ast.literal_eval($X)",
    })
    code = "safe = ast.literal_eval(a)\nbad = eval(user_input)\n"
    res = det.detect("a.py", code, "python")
    # только одна находка — на строке eval (не literal_eval)
    assert len(res) == 1
    assert res[0]["line_number"] == 2


def test_gsc_not_regex_suppresses():
    det = _detector({
        "id": "print-secret",
        "severity": "HIGH",
        "message": "print secret",
        "languages": ["python"],
        "patterns": [{"regex": r"\bprint\s*\(.*(?:password|secret)", "title": "print secret"}],
        "not": [{"regex": r"redact|masked|\[:4\]"}],
    })
    # реальная утечка — флагается
    assert det.detect("a.py", "print(password)\n", "python")
    # замаскированный вывод — не флагается
    assert not det.detect("a.py", "print(masked)\n", "python")
