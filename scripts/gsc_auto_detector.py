#!/usr/bin/env python3
"""
GSC Detector Auto-Generator v3 — creates YAML rules from bounty examples.

Validation gate (v3):
  1. Split by pattern_hash (not individual examples — prevents train/test leakage)
  2. Leave-one-out at N<10, 80/20 at N≥10
  3. Generate patterns from train set (with ReDoS-guard from NL Policy)
  4. TP-check: held-out ≥80% (averaged across leave-one-out folds when N<10)
  5. FP-check: 0 CRITICAL on clean (aligned with existing invariant)
  6. fixed_code from bounty examples = negatives (best source, already in DB)
  7. If passes → GSAUTO-xxx SHADOW candidate → COMPLIANCE_MAP → ≥10 verdicts → full

Rule ID schema: GSAUTO-{CWE_NUM} (e.g. GSAUTO-79 for CWE-79 on JS)

Usage:
    python3 scripts/gsc_auto_detector.py --check      # Check what's ready
    python3 scripts/gsc_auto_detector.py --validate    # Validate with leave-one-out / 80/20
    python3 scripts/gsc_auto_detector.py --generate    # Full pipeline: validate + activate shadow
"""
import os, sys, json, hashlib, sqlite3, re
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent))
from gsc_nlpolicy import MAX_POLICY_PATTERN_LEN, BAD_RE

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
YAML_DIR = Path(__file__).parent.parent / "gsc_detectors" / "yaml_rules"
MIN_EXAMPLES = 5
LOO_THRESHOLD = 10  # Use leave-one-out for N < 10, 80/20 for N ≥ 10

CWE_NAME_MAP = {
    "CWE-22": "Path Traversal", "CWE-59": "Symlink Following",
    "CWE-73": "External Control of File Name or Path",
    "CWE-79": "Cross-Site Scripting (XSS)", "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection", "CWE-94": "Code Injection",
    "CWE-133": "String Formatting", "CWE-200": "Information Disclosure",
    "CWE-331": "Insufficient Entropy", "CWE-352": "CSRF",
    "CWE-384": "Session Fixation", "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-407": "Algorithmic Complexity",
    "CWE-488": "Exposure of Data to Wrong Session",
    "CWE-798": "Hardcoded Credentials", "CWE-834": "Excessive Iteration",
    "CWE-918": "SSRF", "CWE-1333": "ReDoS",
}


# ── ReDoS Guard (from NL Policy) ──────────────────────────────────────────────

def validate_pattern(pattern: str) -> bool:
    """ReDoS guard for auto-generated patterns. Returns True if safe."""
    if not pattern or len(pattern) < 3:
        return False
    if len(pattern) > MAX_POLICY_PATTERN_LEN:
        print(f"    🛑 ReDoS-guard: pattern too long ({len(pattern)} > {MAX_POLICY_PATTERN_LEN})")
        return False
    if BAD_RE.search(pattern):
        print(f"    🛑 ReDoS-guard: nested quantifiers in '{pattern[:60]}'")
        return False
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        print(f"    🛑 Regex compile error: {e}")
        return False


# ── Check ─────────────────────────────────────────────────────────────────────

def check_ready_combos():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    combos = db.execute("""
        SELECT cwe_id, language, COUNT(*) as cnt,
               SUM(CASE WHEN fix_quality='fix' THEN 1 ELSE 0 END) as fixes,
               SUM(CASE WHEN fix_quality='workaround' THEN 1 ELSE 0 END) as wa,
               GROUP_CONCAT(ghsa_id, ', ') as ghsa_ids
        FROM bounty_examples
        WHERE cwe_id != '' AND language IN ('python','javascript','go','rust') AND vulnerable_code != ''
        GROUP BY cwe_id, language HAVING cnt >= ? ORDER BY cnt DESC
    """, (MIN_EXAMPLES,)).fetchall()
    db.close()

    if not combos:
        print(f"❌ No combos with {MIN_EXAMPLES}+ examples.")
        return []

    print(f"📊 Combos ≥{MIN_EXAMPLES} examples:\n")
    for c in combos:
        name = CWE_NAME_MAP.get(c["cwe_id"], c["cwe_id"])
        print(f"  {c['cwe_id']} ({name}) | {c['language']:<10} | {c['cnt']} ex | {c['fixes']} fixes | {c['wa']} wa")
    return combos


# ── Pattern Extraction ────────────────────────────────────────────────────────

def extract_patterns(examples: list, language: str) -> list:
    """Extract regex patterns from vulnerable code with ReDoS-guard."""
    all_lines = []
    for ex in examples:
        vuln = ex.get("vulnerable_code", ex[0] if isinstance(ex, tuple) else "")
        for line in vuln.split("\n"):
            s = line.strip()
            if s and len(s) > 5 and not s.startswith("#"):
                all_lines.append(s)

    if not all_lines:
        return [("Generic", r"(?i)(TODO|FIXME|HACK)")]

    func_calls = Counter()
    for line in all_lines:
        m = re.search(r'(\w+\.\w+|\w+)\s*\(', line)
        if m:
            func_calls[m.group(1)] += 1

    assignments = Counter()
    for line in all_lines:
        if "=" in line and "==" not in line:
            k = line.split("=")[0].strip().split()[-1] if line.split("=")[0].strip() else "?"
            if len(k) > 2:
                assignments[k] += 1

    patterns = []
    for func, count in func_calls.most_common(8):
        if count >= 2:
            pat = re.escape(func) + r"\s*\("
            if validate_pattern(pat):
                patterns.append(
                    (f"{_cwe_name(examples)}: {func}() called unsafely ({count}/{len(examples)} ex)", pat))

    for key, count in assignments.most_common(5):
        if count >= 2 and key != "?":
            pat = re.escape(key) + r"\s*="
            if validate_pattern(pat):
                patterns.append(
                    (f"Dangerous assignment: {key} ({count}/{len(examples)} times)", pat))

    if not patterns:
        sample = all_lines[0][:80]
        cleaned = re.sub(r'[^a-zA-Z0-9_\\s]', '.', sample)
        pat = cleaned[:60]
        if validate_pattern(pat):
            patterns.append((f"Pattern from bounty example: {sample[:50]}", pat))

    return patterns[:10]


def _cwe_name(examples) -> str:
    e = examples[0]
    return (e.get("summary", "") if isinstance(e, dict) else "vulnerability")[:60]


# ── Split by pattern_hash (no train/test leakage) ─────────────────────────────

def _split_by_pattern(examples: list, ratio: float = 0.8):
    """Group examples by pattern_hash, split groups into train/test."""
    groups = defaultdict(list)
    for ex in examples:
        ph = ex.get("pattern_hash", ex[4] if isinstance(ex, tuple) and len(ex) > 4 else "unknown")
        groups[ph or "unknown"].append(ex)

    group_list = list(groups.values())

    if len(group_list) < 3:
        # Too few distinct patterns — fall back to random split
        split = max(1, int(len(examples) * (1 - ratio)))
        return examples[split:], examples[:split]

    split = max(1, int(len(group_list) * (1 - ratio)))
    train_groups, test_groups = group_list[split:], group_list[:split]

    train = [e for g in train_groups for e in g]
    test = [e for g in test_groups for e in g]
    return train, test


# ── Negative loading (fixed_code + negative_examples) ─────────────────────────

def _load_negatives(cwe_id: str, language: str):
    """Load ALL negative examples: fixed_code from bounty + NegativeCollector."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    # Source 1: fixed_code = safe version of the same bug (best negatives!)
    fixes = db.execute("""
        SELECT fixed_code FROM bounty_examples
        WHERE cwe_id = ? AND language = ? AND fix_quality = 'fix' AND fixed_code != ''
    """, (cwe_id, language)).fetchall()

    # Source 2: explicit negative examples from NegativeCollector
    explicit = db.execute("""
        SELECT clean_code FROM negative_examples
        WHERE cwe_id = ? AND language = ?
    """, (cwe_id, language)).fetchall()

    db.close()

    negatives = []
    for f in fixes:
        negatives.append(f["fixed_code"])
    for e in explicit:
        negatives.append(e["clean_code"])

    return negatives


# ── Validation ────────────────────────────────────────────────────────────────

def validate_combos(quiet=False):
    """Validate combos: leave-one-out at N<10, split-by-pattern at N≥10."""
    combos = check_ready_combos()
    if not combos:
        return []

    if not quiet:
        print("\n🔬 Validation Phase\n")

    validated = []
    for combo in combos:
        cwe_id = combo["cwe_id"]
        language = combo["language"]

        db = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
        examples = db.execute("""
            SELECT vulnerable_code, fixed_code, ghsa_id, pattern_hash, fix_quality
            FROM bounty_examples
            WHERE cwe_id = ? AND language = ? AND vulnerable_code != ''
        """, (cwe_id, language)).fetchall()
        db.close()

        total = len(examples)
        if total < MIN_EXAMPLES:
            continue

        negatives = _load_negatives(cwe_id, language)

        if total < LOO_THRESHOLD:
            # ── Leave-one-out ──
            results = _validate_leave_one_out(examples, language, negatives)
        else:
            # ── Split by pattern_hash ──
            train, test = _split_by_pattern([dict(e) for e in examples])
            patterns = extract_patterns(train, language)
            results = _evaluate_patterns(patterns, train, test, negatives)

        if not quiet:
            _print_validation_results(cwe_id, language, results)

        if results["passed"]:
            validated.append((cwe_id, language, results))

    if not quiet and validated:
        print(f"\n🎯 {len(validated)} combos passed → ready for --generate")

    return validated


def _validate_leave_one_out(examples, language, negatives):
    """Leave-one-out cross-validation: each example is held-out once."""
    n = len(examples)
    all_heldout_tp = 0
    all_train_tp = 0

    for i in range(n):
        heldout = [examples[i]]
        train = [examples[j] for j in range(n) if j != i]

        patterns = extract_patterns(train, language)
        tr, ho, fp = _evaluate_patterns(patterns,
                                         [dict(e) for e in train],
                                         [dict(e) for e in heldout],
                                         negatives)
        all_heldout_tp += ho["tp"]
        all_train_tp += tr["tp"]

    avg_heldout_rate = all_heldout_tp / n if n > 0 else 0
    fp_count = _count_fp_on_negatives(
        extract_patterns([dict(e) for e in examples], language), negatives)

    passed = avg_heldout_rate >= 0.80 and fp_count == 0
    return {
        "method": "leave-one-out",
        "train_tp": all_train_tp, "train_total": n * (n - 1),
        "heldout_tp": all_heldout_tp, "heldout_total": n,
        "heldout_rate": avg_heldout_rate,
        "fp_count": fp_count, "neg_total": len(negatives),
        "passed": passed,
    }


def _evaluate_patterns(patterns, train_examples, test_examples, negatives):
    """Evaluate generated patterns on train, test, and negatives."""

    def count_matches(ex_list, key="vulnerable_code"):
        tp = 0
        for ex in ex_list:
            text = ex.get(key, ex[0] if isinstance(ex, tuple) else "")
            for _, pat in patterns:
                try:
                    if re.search(pat, text):
                        tp += 1
                        break
                except re.error:
                    continue
        return tp

    train_tp = count_matches(train_examples)
    heldout_tp = count_matches(test_examples)
    fp = _count_fp_on_negatives(patterns, negatives)

    return (
        {"tp": train_tp, "total": len(train_examples)},
        {"tp": heldout_tp, "total": len(test_examples)},
        fp,
    )


def _count_fp_on_negatives(patterns, negatives):
    """Count FP on negatives — but only CRITICAL-severity matches matter."""
    fp = 0
    for clean_text in negatives:
        for _, pat in patterns:
            try:
                if re.search(pat, clean_text):
                    fp += 1
                    break
            except re.error:
                continue
    return fp


def _print_validation_results(cwe_id, language, results):
    method = results.get("method", "split-by-pattern")
    print(f"  {cwe_id} | {language} ({method})")
    if method == "leave-one-out":
        print(f"    Avg held-out TP: {results['heldout_tp']}/{results['heldout_total']} ({results['heldout_rate']:.0%})")
    else:
        ht, htotal = results["heldout_tp"], results["heldout_total"]
        rate = ht / htotal if htotal > 0 else 0
        print(f"    Held-out TP: {ht}/{htotal} ({rate:.0%})")
    print(f"    FP on {results['neg_total']} negatives: {results['fp_count']}")
    status = "✅ PASS" if results["passed"] else "❌ FAIL"
    print(f"    → {status}")


# ── Generate Rule ─────────────────────────────────────────────────────────────

def generate_rule(cwe_id: str, language: str):
    """Generate YAML detector rule with GSAUTO-xxx rule_id schema."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    examples = db.execute("""
        SELECT vulnerable_code, fixed_code, summary, ghsa_id, fix_quality
        FROM bounty_examples WHERE cwe_id=? AND language=? AND vulnerable_code!=''
        ORDER BY severity, collected_at DESC LIMIT 10
    """, (cwe_id, language)).fetchall()
    db.close()

    if len(examples) < MIN_EXAMPLES:
        return None

    patterns = extract_patterns(examples, language)
    if not patterns:
        return None

    cwe_name = CWE_NAME_MAP.get(cwe_id, cwe_id)
    cwe_num = cwe_id.replace("CWE-", "")

    # GSAUTO rule_id schema (avoids conflict with GS000-031)
    rule_id = f"GSAUTO-{cwe_num}"
    safe_rule_id = f"gsauto_{cwe_num}"

    severities = [e["severity"] for e in examples]
    severity = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM"

    sources = ', '.join(e['ghsa_id'] for e in examples[:5])

    rule_py = f'''# {rule_id} — {cwe_name} ({cwe_id})
# Auto-generated from {len(examples)} labelled bounty examples (v3 validated)
# Sources: {sources}
# Generated: {datetime.now().isoformat()}
# Rule ID schema: GSAUTO-xxx (avoids GS000-031 conflict)

from gsc_detectors.base import RegexDetector

RULE_ID = "{rule_id}"
ECHELON = 2
# SHADOW MODE: candidate detector — collects verdicts, doesn't block
# Auto-promote after ≥10 verdicts + TP ≥70%
SHADOW = True
NOISE_TIER = "precise"
description = (
    "{cwe_name} ({cwe_id}): auto-detected from {len(examples)} real-world "
    "vulnerability examples in {language} code"
)

patterns = [
'''

    for pat_title, pat_regex in patterns:
        rule_py += f'    [r"{pat_regex}",\n     "{pat_title}"],\n\n'

    rule_py += f''']

detector = RegexDetector(
    rule_id=RULE_ID,
    name="{safe_rule_id}",
    patterns=patterns,
    severity="{severity}",
    confidence=0.85,
    languages=('{language}',),
)


def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
'''

    return rule_py, rule_id, safe_rule_id


# ── Save + Register ───────────────────────────────────────────────────────────

def save_rule(rule_py: str, safe_rule_id: str):
    YAML_DIR.mkdir(parents=True, exist_ok=True)
    filepath = YAML_DIR / f"{safe_rule_id}.py"
    filepath.write_text(rule_py)
    print(f"  ✅ Rule: {filepath}")

    init_path = YAML_DIR / "__init__.py"
    if not init_path.exists():
        init_path.write_text("# YAML rules registry\n\n")
    init_content = init_path.read_text()
    import_line = f"from .{safe_rule_id} import detect"
    if import_line not in init_content:
        with open(init_path, "a") as f:
            f.write(f"{import_line}  # GSAUTO {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"  ✅ Registered in __init__.py")


def _register_compliance_mapping(rule_id: str, cwe_id: str, language: str, severity: str):
    """Register GSAUTO rule in COMPLIANCE_MAP (gsc_compliance.py)."""
    try:
        from gsc_compliance import COMPLIANCE_MAP
        cwe_num = cwe_id.replace("CWE-", "")
        COMPLIANCE_MAP[rule_id] = {
            "cwe": cwe_id,
            "owasp": _cwe_to_owasp(cwe_id),
            "pci": False,
            "severity": severity,
        }
        print(f"  ✅ COMPLIANCE_MAP: {rule_id} → {cwe_id}")
    except ImportError:
        print(f"  ⚠️ gsc_compliance not importable — COMPLIANCE_MAP not updated")


def _cwe_to_owasp(cwe_id: str) -> str:
    mapping = {
        "CWE-79": "A03:2021-Injection", "CWE-89": "A03:2021-Injection",
        "CWE-88": "A03:2021-Injection", "CWE-22": "A01:2021-Broken Access Control",
        "CWE-918": "A10:2021-SSRF", "CWE-200": "A01:2021-Broken Access Control",
        "CWE-1333": "A04:2021-Insecure Design",
    }
    return mapping.get(cwe_id, f"A03:2021-Injection")


def _register_shadow(rule_id: str, cwe_id: str, language: str):
    db = sqlite3.connect(DB)
    try:
        db.execute("""INSERT OR REPLACE INTO federated_deactivated
            (rule_id, reason, deactivated_at) VALUES (?,?,datetime('now'))""",
                   (rule_id, f"SHADOW_CANDIDATE|{cwe_id}|{language}|verdicts=0"))
        db.commit()
    except sqlite3.OperationalError:
        pass
    db.close()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("--check", "--validate", "--generate"):
        print("Usage: gsc_auto_detector.py --check|--validate|--generate")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "--check":
        combos = check_ready_combos()
        if combos:
            print(f"\n💡 --validate to test, --generate to activate.")
        return

    if mode == "--validate":
        validate_combos()
        return

    # --generate
    print("🔧 GSC Auto-Detector v3\n")

    combos = check_ready_combos()
    if not combos:
        return

    validated = validate_combos(quiet=True)
    if not validated:
        print("\n❌ No combos passed. Need more data / better patterns.")
        return

    generated = 0
    for cwe_id, language, results in validated:
        print(f"\n{'='*60}")
        print(f"  SHADOW: {cwe_id} | {language}")
        print(f"  Method: {results.get('method','split')} | Held-out: {results.get('heldout_rate',0):.0%} | FP: {results['fp_count']}")

        result = generate_rule(cwe_id, language)
        if not result:
            continue

        rule_py, rule_id, safe_rule_id = result

        if (YAML_DIR / f"{safe_rule_id}.py").exists():
            print(f"  ⚠️ Exists: {safe_rule_id}.py")
            continue

        # Validate ALL generated patterns (ReDoS-guard)
        patterns = re.findall(r'\[r"(.*?)",', rule_py)
        unsafe = [p for p in patterns if not validate_pattern(p)]
        if unsafe:
            print(f"  ❌ ReDoS-unsafe patterns: {unsafe}")
            continue

        save_rule(rule_py, safe_rule_id)
        _register_compliance_mapping(rule_id, cwe_id, language, "MEDIUM")
        _register_shadow(rule_id, cwe_id, language)
        generated += 1

    print(f"\n{'='*60}")
    print(f"✅ {generated} SHADOW detectors activated")
    print(f"   Collecting verdicts (non-blocking)")
    print(f"   ≥10 verdicts + TP≥70% → FULL detector")


if __name__ == "__main__":
    main()
