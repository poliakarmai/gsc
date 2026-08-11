"""
Tests for gsc_auto_detector validation gate.

Run: pytest tests/test_auto_detector.py -v
"""
import sys, os, pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.gsc_auto_detector import (
    validate_generated_pattern, PatternValidationError,
    split_for_validation, _split_by_pattern_hash, _leave_one_out,
    Sample, generate_rule_id, ValidationResult, validate_pattern,
    generate_pattern, load_training_data,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ReDoS Guard tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_redos_guard_rejects_nested_quantifiers():
    with pytest.raises(PatternValidationError, match="ReDoS"):
        validate_generated_pattern("(a+)+$")


def test_redos_guard_rejects_long_pattern():
    with pytest.raises(PatternValidationError, match="too long"):
        validate_generated_pattern("a" * 300)


def test_redos_guard_accepts_safe_pattern():
    validate_generated_pattern(r"execute\s*\(f[\"'].*\{")  # does not raise


def test_redos_guard_rejects_empty_pattern():
    with pytest.raises(PatternValidationError, match="empty"):
        validate_generated_pattern("")


def test_redos_guard_rejects_invalid_regex():
    with pytest.raises(PatternValidationError, match="invalid"):
        validate_generated_pattern("[unclosed")


# ═══════════════════════════════════════════════════════════════════════════════
# Split tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_leave_one_out_for_small_n():
    pos = [Sample(code=f"vuln{i}", pattern_hash=f"h{i}") for i in range(5)]
    splits = split_for_validation(pos)
    assert len(splits) == 5                     # LOO: 5 splits
    for train, test in splits:
        assert len(test) == 1 and len(train) == 4


def test_split_by_pattern_hash_no_leakage():
    """Two samples with SAME pattern_hash must end up in same set."""
    pos = [
        Sample(code="a", pattern_hash="SAME"),
        Sample(code="b", pattern_hash="SAME"),
        Sample(code="c", pattern_hash="X1"),
        Sample(code="d", pattern_hash="X2"),
        Sample(code="e", pattern_hash="X3"),
        Sample(code="f", pattern_hash="X4"),
        Sample(code="g", pattern_hash="X5"),
        Sample(code="h", pattern_hash="X6"),
        Sample(code="i", pattern_hash="X7"),
        Sample(code="j", pattern_hash="X8"),
    ]
    train, test = _split_by_pattern_hash(pos, seed=42)
    train_hashes = {s.pattern_hash for s in train}
    test_hashes = {s.pattern_hash for s in test}
    assert not (train_hashes & test_hashes), "leakage: shared pattern_hash in train and test"


def test_split_by_pattern_hash_non_empty_test():
    """Even with many groups, test set must not be empty."""
    pos = [Sample(code=f"v{i}", pattern_hash=f"h{i}") for i in range(15)]
    train, test = _split_by_pattern_hash(pos, seed=42)
    assert len(test) > 0, "test set must not be empty"
    assert len(train) > 0


def test_leave_one_out_each_sample_is_test_once():
    pos = [Sample(code=f"v{i}", pattern_hash=f"h{i}") for i in range(7)]
    splits = _leave_one_out(pos)
    test_codes = set()
    for _, test in splits:
        assert len(test) == 1
        test_codes.add(test[0].code)
    assert len(test_codes) == 7  # Every sample was held-out exactly once


# ═══════════════════════════════════════════════════════════════════════════════
# rule_id tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_rule_id_scheme():
    rid = generate_rule_id("CWE-79", "javascript")
    assert rid == "GSAUTO-79-javascript"
    assert __import__('re').match(r"^GSAUTO-\d+-\w+$", rid)


def test_rule_id_scheme_python():
    rid = generate_rule_id("CWE-88", "python")
    assert rid == "GSAUTO-88-python"


def test_rule_id_scheme_go():
    rid = generate_rule_id("CWE-22", "go")
    assert rid == "GSAUTO-22-go"


# ═══════════════════════════════════════════════════════════════════════════════
# Validation tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_validate_passes_on_perfect_split():
    """Pattern matches all test examples, 0 FP on clean."""
    test_samples = [Sample("vuln_function()", "h0")]
    train_samples = [Sample("vuln_function()", "h1"), Sample("vuln_func()", "h2")]
    splits = [(train_samples, test_samples)]
    vr = validate_pattern(
        pattern=r"vuln_function\(",
        splits=splits,
        negatives=[],
        clean_project_files=[("clean.py", "safe code here")])
    assert vr.passed is True
    assert vr.tp_rate == 1.0
    assert vr.clean_critical_fp == 0


def test_validate_fails_on_clean_fp():
    """Pattern matching clean code → fails."""
    train = [Sample("vuln()", "h1"), Sample("vuln()", "h2")]
    test = [Sample("vuln()", "h3")]
    splits = [(train, test)]
    vr = validate_pattern(
        pattern=r"vuln",
        splits=splits,
        negatives=[],
        clean_project_files=[("clean.py", "vuln in clean code too")])
    assert vr.passed is False
    assert vr.clean_critical_fp > 0


def test_validate_fails_on_low_tp():
    """Pattern misses held-out examples → fails."""
    train = [Sample("vuln()", "h1"), Sample("vuln()", "h2")]
    test = [Sample("different_code()", "h3")]
    splits = [(train, test)]
    vr = validate_pattern(
        pattern=r"vuln\(",
        splits=splits,
        negatives=[],
        clean_project_files=[])
    assert vr.passed is False
    assert vr.tp_rate == 0.0


def test_validate_counts_fp_on_negatives():
    """FP on negatives is counted but does not block (clean FP is the hard gate)."""
    train = [Sample("vuln()", "h1"), Sample("vuln()", "h2")]
    test = [Sample("vuln()", "h3")]
    splits = [(train, test)]
    neg = [Sample("vuln()", "n1", is_negative=True), Sample("safe()", "n2", is_negative=True)]
    vr = validate_pattern(
        pattern=r"vuln\(",
        splits=splits,
        negatives=neg,
        clean_project_files=[])
    assert vr.passed is True   # TP ≥ 80%, no clean FP
    assert vr.fp_on_negatives == 1  # One negative matched — signal, not block


# ═══════════════════════════════════════════════════════════════════════════════
# Pattern generation tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_generate_pattern_extracts_function_call():
    train = [
        Sample("unsafe_func(user_input)", "h1"),
        Sample("unsafe_func(data)", "h2"),
        Sample("unsafe_func(x)", "h3"),
    ]
    pattern = generate_pattern(train, "CWE-88", "python")
    assert "unsafe_func" in pattern
    assert "(" in pattern


def test_generate_pattern_rejects_empty_train():
    with pytest.raises(PatternValidationError, match="no code"):
        generate_pattern([], "CWE-79", "python")


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: LOO validation
# ═══════════════════════════════════════════════════════════════════════════════

def test_loo_validation_synthetic():
    """Simulate 5 positive examples with a shared pattern → LOO should pass."""
    pos = [
        Sample("check_unsafe(options, unsafe)", f"h{i}")
        for i in range(5)
    ]
    splits = split_for_validation(pos)
    assert len(splits) == 5  # LOO

    # Generate pattern from first train set
    train0 = splits[0][0]
    pattern = generate_pattern(train0, "CWE-88", "python")

    vr = validate_pattern(pattern, splits, negatives=[], clean_project_files=[])
    assert vr.passed is True
    assert vr.method == "leave-one-out"
    assert vr.tp_rate >= 0.80


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
