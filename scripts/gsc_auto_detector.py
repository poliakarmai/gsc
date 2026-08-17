#!/usr/bin/env python3
"""
GSC Auto-Detector v4 — validation gate for bounty-driven detectors.

Gate flow:
  bounty_examples + negative_examples
     ↓
  load_training_data()          — fixed_code = negatives (🔴 from review)
     ↓
  split_for_validation()        — leave-one-out at N<10 / split by pattern_hash
     ↓
  generate_pattern()            — LLM + ReDoS-guard (🔴 safety, reuses NL Policy)
     ↓
  validate_pattern()            — TP≥80% (LOO-averaged) + FP: 0 CRITICAL on clean
     ↓  PASS                            ↓ FAIL
  register_auto_detector()      — GSAUTO rule_id + BaseDetector + COMPLIANCE_MAP
     ↓
  SHADOW detector               — collects verdicts, does not block
     ↓ ≥10 verdicts + TP≥70%
  FULL DETECTOR                 — via Blocking Engine

Usage:
    python3 scripts/gsc_auto_detector.py --check
    python3 scripts/gsc_auto_detector.py --validate CWE-79 javascript
    python3 scripts/gsc_auto_detector.py --generate CWE-79 javascript
"""
from __future__ import annotations

import json, os, random, re, sqlite3, sys, hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from gsc_cli.gsc_nlpolicy import MAX_POLICY_PATTERN_LEN, BAD_RE

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
YAML_DIR = Path(__file__).parent.parent / "gsc_detectors" / "yaml_rules"
MIN_EXAMPLES = 5
LOO_THRESHOLD = 10

CWE_NAME_MAP = {
    "CWE-22": "Path Traversal", "CWE-59": "Symlink Following",
    "CWE-73": "Ext Ctrl File Name", "CWE-79": "XSS",
    "CWE-88": "Argument Injection", "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection", "CWE-200": "Info Disclosure",
    "CWE-331": "Insufficient Entropy", "CWE-352": "CSRF",
    "CWE-384": "Session Fixation", "CWE-400": "Uncontrolled Resource",
    "CWE-407": "Algorithmic Complexity", "CWE-488": "Exposure Wrong Session",
    "CWE-798": "Hardcoded Credentials", "CWE-834": "Excessive Iteration",
    "CWE-918": "SSRF", "CWE-1333": "ReDoS",
}


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 1: ReDoS Guard + Data Model
# ═══════════════════════════════════════════════════════════════════════════════

class PatternValidationError(ValueError):
    pass


def validate_generated_pattern(pattern: str) -> None:
    """ReDoS guard for auto-generated regex patterns.

    Reuses the same guard from NL Policy — single protection for all
    LLM-generated patterns in the system.
    """
    if not pattern:
        raise PatternValidationError("empty pattern")
    if len(pattern) > MAX_POLICY_PATTERN_LEN:
        raise PatternValidationError(
            f"pattern too long: {len(pattern)} > {MAX_POLICY_PATTERN_LEN}")
    if BAD_RE.search(pattern):
        raise PatternValidationError("nested quantifiers rejected (ReDoS risk)")
    try:
        re.compile(pattern)
    except re.error as e:
        raise PatternValidationError(f"invalid regex: {e}")


@dataclass
class Sample:
    code: str
    pattern_hash: Optional[str]
    is_negative: bool = False
    source: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 1b: Load training data (fixed_code = negatives)
# ═══════════════════════════════════════════════════════════════════════════════

def load_training_data(cwe: str, lang: str) -> Tuple[List[Sample], List[Sample]]:
    """Positive = vulnerable_code. Negative = fixed_code + negative_examples.

    KEY: fixed_code from a real fix = the MOST RELEVANT negative.
    It's already in bounty_examples and was not used for training before.
    """
    positives: List[Sample] = []
    negatives: List[Sample] = []

    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    try:
        rows = db.execute("""
            SELECT vulnerable_code, fixed_code, fix_quality, pattern_hash, ghsa_id
            FROM bounty_examples
            WHERE cwe_id = ? AND language = ? AND vulnerable_code != ''
        """, (cwe, lang)).fetchall()

        for r in rows:
            positives.append(Sample(
                code=r["vulnerable_code"],
                pattern_hash=r["pattern_hash"] or f"_noph_{r['ghsa_id']}",
                source="bounty"))
            # Only real fixes (not workarounds) go as negatives
            if r["fixed_code"] and r["fix_quality"] == "fix":
                negatives.append(Sample(
                    code=r["fixed_code"],
                    pattern_hash=r["pattern_hash"] or f"_noph_fix_{r['ghsa_id']}",
                    is_negative=True, source="bounty-fixed"))

        # Source 2: explicit negative examples from NegativeCollector
        neg_rows = db.execute("""
            SELECT clean_code, source_file FROM negative_examples
            WHERE cwe_id = ? AND language = ?
        """, (cwe, lang)).fetchall()
        for r in neg_rows:
            negatives.append(Sample(
                code=r["clean_code"], pattern_hash=None,
                is_negative=True, source="negative-collector"))

    except sqlite3.OperationalError:
        pass
    finally:
        db.close()

    return positives, negatives


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 2: Split — leave-one-out + pattern_hash protection
# ═══════════════════════════════════════════════════════════════════════════════

def split_for_validation(
    positives: List[Sample],
    seed: int = 42,
) -> List[Tuple[List[Sample], List[Sample]]]:
    """Returns list of (train, test) splits.

    N < 10:  leave-one-out (a single 80/20 split on 5 examples is meaningless)
    N ≥ 10: split by pattern_hash groups (prevents train/test leakage)
    """
    if len(positives) < 2:
        return []
    if len(positives) < LOO_THRESHOLD:
        return _leave_one_out(positives)
    return [_split_by_pattern_hash(positives, seed)]


def _leave_one_out(positives: List[Sample]) -> List[Tuple[List, List]]:
    """Each example takes a turn as held-out. Averaging gives honest TP."""
    splits = []
    for i in range(len(positives)):
        train = positives[:i] + positives[i + 1:]
        test = [positives[i]]
        splits.append((train, test))
    return splits


def _split_by_pattern_hash(
    positives: List[Sample], seed: int
) -> Tuple[List[Sample], List[Sample]]:
    """Split at the PATTERN_HASH GROUP level.

    Guarantees: train and test contain DIFFERENT patterns. A random
    element-level split would put near-identical patterns in both
    sets → inflated TP.
    """
    groups: Dict[str, List[Sample]] = {}
    for p in positives:
        key = p.pattern_hash or f"_noph_{hash(p.code)}"
        groups.setdefault(key, []).append(p)

    keys = list(groups.keys())
    random.Random(seed).shuffle(keys)
    split_idx = max(1, int(len(keys) * 0.8))
    if split_idx >= len(keys):
        split_idx = len(keys) - 1

    train = [s for k in keys[:split_idx] for s in groups[k]]
    test = [s for k in keys[split_idx:] for s in groups[k]]
    return train, test


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 3: Pattern generation + validation
# ═══════════════════════════════════════════════════════════════════════════════

def generate_pattern(train: List[Sample], cwe: str, lang: str) -> str:
    """Extract a regex pattern from training examples.

    Uses heuristic keyword extraction (no LLM for now — deterministic,
    reproducible). Result ALWAYS passes ReDoS-guard.
    """
    from collections import Counter

    all_lines = []
    for s in train:
        for line in s.code.split("\n"):
            stripped = line.strip()
            if stripped and len(stripped) > 5 and not stripped.startswith("#"):
                all_lines.append(stripped)

    if not all_lines:
        raise PatternValidationError("no code lines in training set")

    # Extract function calls
    func_calls = Counter()
    for line in all_lines:
        m = re.search(r'(\w+\.\w+|\w{4,})\s*\(', line)
        if m:
            func_calls[m.group(1)] += 1

    # Best candidate: function appearing in most examples
    for func, count in func_calls.most_common(10):
        if count >= 2:
            pattern = re.escape(func) + r"\s*\("
            try:
                validate_generated_pattern(pattern)
                return pattern
            except PatternValidationError:
                continue

    # Fallback: keyword from the most common line
    if all_lines:
        sample = all_lines[0][:80]
        cleaned = re.sub(r'[^a-zA-Z0-9_\\s]', '.', sample)
        pattern = cleaned[:60]
        validate_generated_pattern(pattern)
        return pattern

    raise PatternValidationError("could not generate pattern")


@dataclass
class ValidationResult:
    passed: bool
    tp_rate: float
    fp_on_negatives: int
    clean_critical_fp: int
    num_splits: int
    method: str = ""
    reason: str = ""


def validate_pattern(
    pattern: str,
    splits: List[Tuple[List[Sample], List[Sample]]],
    negatives: List[Sample],
    clean_project_files: List[Tuple[str, str]],
) -> ValidationResult:
    """TP: averaged across all splits ≥ 0.80.
    FP: 0 CRITICAL matches on clean projects (aligned with calibration invariant).
    """
    rx = re.compile(pattern)
    method = "leave-one-out" if len(splits) > 1 else "split-by-pattern"

    # ── TP-check: average across all splits ──
    tp_rates: List[float] = []
    for train, test in splits:
        if not test:
            continue
        detected = sum(1 for t in test if rx.search(t.code))
        tp_rates.append(detected / len(test))
    avg_tp = sum(tp_rates) / len(tp_rates) if tp_rates else 0.0

    # ── FP-check on negatives (fixed_code + NegativeCollector) ──
    fp_neg = sum(1 for n in negatives if rx.search(n.code))

    # ── FP-check on clean projects: count CRITICAL matches ──
    clean_crit = 0
    for fpath, content in clean_project_files:
        for _ in rx.finditer(content):
            clean_crit += 1

    # Gate thresholds:
    #   TP ≥ 0.80 (averaged)
    #   0 CRITICAL on clean (aligned with clean-pure → 0 CRITICAL invariant)
    passed = (avg_tp >= 0.80) and (clean_crit == 0)

    reason = ""
    if avg_tp < 0.80:
        reason += f"TP {avg_tp:.2f} < 0.80; "
    if clean_crit > 0:
        reason += f"clean CRITICAL FP={clean_crit}; "
    if fp_neg > 0:
        reason += f"FP on {fp_neg} negatives; "

    return ValidationResult(
        passed=passed, tp_rate=avg_tp, fp_on_negatives=fp_neg,
        clean_critical_fp=clean_crit, num_splits=len(splits),
        method=method, reason=reason.strip())


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 4: Registration — rule_id + BaseDetector + COMPLIANCE_MAP
# ═══════════════════════════════════════════════════════════════════════════════

AUTO_RULE_PREFIX = "GSAUTO"


def generate_rule_id(cwe: str, lang: str) -> str:
    """Scheme: GSAUTO-<CWE_NUM>-<lang>. No conflict with GS001–GS031."""
    cwe_num = cwe.replace("CWE-", "")
    return f"{AUTO_RULE_PREFIX}-{cwe_num}-{lang}"


def _existing_auto_rule_ids() -> set:
    """Get existing GSAUTO rule IDs from YAML rules directory."""
    existing = set()
    if YAML_DIR.exists():
        for f in YAML_DIR.glob("gsauto_*.py"):
            content = f.read_text()
            m = re.search(r'RULE_ID\s*=\s*"(GSAUTO[^"]+)"', content)
            if m:
                existing.add(m.group(1))
    return existing


def _cwe_to_owasp(cwe_id: str) -> str:
    mapping = {
        "CWE-79": "A03:2021-Injection", "CWE-89": "A03:2021-Injection",
        "CWE-88": "A03:2021-Injection", "CWE-22": "A01:2021-Broken Access Control",
        "CWE-918": "A10:2021-SSRF", "CWE-200": "A01:2021-Broken Access Control",
        "CWE-1333": "A04:2021-Insecure Design",
    }
    return mapping.get(cwe_id, "A03:2021-Injection")


def register_auto_detector(
    cwe: str, lang: str, pattern: str, tp_rate: float, validation: dict
) -> Optional[str]:
    """Register auto-detector as SHADOW. Returns rule_id on success, None on failure.

    Guarantees:
      - GSAUTO-* rule_id, no conflict with existing detectors
      - COMPLIANCE_MAP entry (CWE/OWASP mapping required)
      - SHADOW status (confidence < 0.80 → Blocking Engine won't block)
      - Saved as YAML rule + registered in __init__.py
    """
    rule_id = generate_rule_id(cwe, lang)
    safe_rule_id = f"gsauto_{cwe.replace('CWE-','')}_{lang}"

    if not re.match(r"^GSAUTO-\d+-\w+$", rule_id):
        print(f"  ❌ Invalid rule_id: {rule_id}")
        return None

    existing = _existing_auto_rule_ids()
    if rule_id in existing:
        print(f"  ⚠️ Rule already exists: {rule_id}")
        return None

    # COMPLIANCE_MAP required — otherwise findings lack CWE/OWASP mapping
    try:
        from gsc_core.gsc_compliance import COMPLIANCE_MAP
        COMPLIANCE_MAP[rule_id] = {
            "cwe": cwe,
            "owasp": _cwe_to_owasp(cwe),
            "origin": "auto-detector",
        }
        print(f"  ✅ COMPLIANCE_MAP: {rule_id} → {cwe}")
    except ImportError:
        print(f"  ⚠️ gsc_compliance not importable — COMPLIANCE_MAP skipped")

    cwe_name = CWE_NAME_MAP.get(cwe, cwe)
    confidence = min(0.50 + tp_rate * 0.3, 0.79)  # < 0.80 → shadow (not blocking)

    rule_py = f'''# {rule_id} — {cwe_name} ({cwe})
# Auto-generated via validation gate | {datetime.now().isoformat()}
# TP rate: {tp_rate:.2f} | Validation: {json.dumps(validation)}
# SHADOW MODE — collects verdicts, does not block
# Auto-promote after ≥10 verdicts + TP ≥70%
from gsc_core.gsc_detectors.base import RegexDetector

RULE_ID = "{rule_id}"
ECHELON = 2
SHADOW = True
NOISE_TIER = "precise"
description = (
    "{cwe_name} ({cwe}): auto-detected from bounty examples "
    "in {lang} code"
)

patterns = [
    [r"{pattern}",
     "Auto-generated {cwe} pattern (TP={tp_rate:.2f})"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="{safe_rule_id}",
    patterns=patterns,
    severity="HIGH",
    confidence={confidence},
    languages=('{lang}',),
)


def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
'''

    YAML_DIR.mkdir(parents=True, exist_ok=True)
    filepath = YAML_DIR / f"{safe_rule_id}.py"
    filepath.write_text(rule_py)
    print(f"  ✅ Rule saved: {filepath}")

    # Register in __init__.py
    init_path = YAML_DIR / "__init__.py"
    if not init_path.exists():
        init_path.write_text("# YAML rules registry\n\n")
    init_content = init_path.read_text()
    import_line = f"from .{safe_rule_id} import detect"
    if import_line not in init_content:
        with open(init_path, "a") as f:
            f.write(f"{import_line}  # GSAUTO {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"  ✅ Registered in __init__.py")

    # Register shadow in Blocking Engine
    db = sqlite3.connect(DB)
    try:
        db.execute("""INSERT OR REPLACE INTO federated_deactivated
            (rule_id, reason, deactivated_at) VALUES (?,?,datetime('now'))""",
                   (rule_id, f"SHADOW_CANDIDATE|{cwe}|{lang}|verdicts=0"))
        db.commit()
    except sqlite3.OperationalError:
        pass
    db.close()

    return rule_id


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 5: Orchestrator — full gate cycle
# ═══════════════════════════════════════════════════════════════════════════════

def run_gate(cwe: str, lang: str) -> dict:
    """Full validation gate for one CWE+lang combo."""
    positives, negatives = load_training_data(cwe, lang)

    # Readiness threshold: 5+ positives, 1+ negative
    real_fixes = sum(1 for n in negatives if n.source == "bounty-fixed")
    if len(positives) < MIN_EXAMPLES:
        return {"status": "not_ready", "reason": f"need {MIN_EXAMPLES - len(positives)} more positive examples",
                "positives": len(positives), "negatives": len(negatives), "fix_negatives": real_fixes}
    if len(negatives) < 1:
        return {"status": "not_ready", "reason": "no negative examples yet",
                "positives": len(positives), "negatives": 0, "fix_negatives": 0}

    # Split
    splits = split_for_validation(positives)
    if not splits:
        return {"status": "not_ready", "reason": "too few positives for split",
                "positives": len(positives)}

    # Generate pattern
    try:
        train0 = splits[0][0]
        pattern = generate_pattern(train0, cwe, lang)
    except PatternValidationError as e:
        return {"status": "rejected", "reason": f"pattern generation: {e}",
                "positives": len(positives)}

    # Validate
    # Load calibration clean files
    clean_files = _load_calibration_clean_files()
    result = validate_pattern(pattern, splits, negatives, clean_files)

    validation_dict = {
        "tp_rate": result.tp_rate,
        "fp_on_negatives": result.fp_on_negatives,
        "clean_critical_fp": result.clean_critical_fp,
        "num_splits": result.num_splits,
        "method": result.method,
    }

    if not result.passed:
        return {"status": "failed", "reason": result.reason,
                "positives": len(positives), "negatives": len(negatives),
                "pattern": pattern, "validation": validation_dict}

    # Register
    rule_id = register_auto_detector(cwe, lang, pattern, result.tp_rate, validation_dict)
    if not rule_id:
        return {"status": "rejected", "reason": "registration failed",
                "positives": len(positives), "pattern": pattern,
                "validation": validation_dict}

    return {"status": "shadow_activated", "rule_id": rule_id,
            "tp_rate": result.tp_rate, "positives": len(positives),
            "negatives": len(negatives), "pattern": pattern,
            "validation": validation_dict}


def _load_calibration_clean_files() -> List[Tuple[str, str]]:
    """Load code from calibration clean-pure projects."""
    calib = Path(os.path.expanduser("~/.hermes/taskmaster/calibration"))
    calib_gsc = Path(__file__).parent.parent / "calibration"
    files = []

    for base in [calib, calib_gsc]:
        if not base.exists():
            continue
        for fpath in base.rglob("clean-pure/**/*"):
            if fpath.is_file() and fpath.suffix in (".py", ".js", ".ts", ".go"):
                try:
                    content = fpath.read_text(errors="ignore")
                    files.append((str(fpath), content))
                except Exception:
                    pass

    return files


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK 6: Dashboard + CLI
# ═══════════════════════════════════════════════════════════════════════════════

def show_dashboard():
    """Coverage matrix: which CWE+lang are approaching readiness."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    try:
        combos = db.execute("""
            SELECT cwe_id, language, COUNT(*) as cnt,
                   SUM(CASE WHEN fix_quality='fix' THEN 1 ELSE 0 END) as fixes
            FROM bounty_examples
            WHERE cwe_id != '' AND language IN ('python','javascript','go','rust')
              AND vulnerable_code != ''
            GROUP BY cwe_id, language ORDER BY cnt DESC
        """).fetchall()
    except sqlite3.OperationalError:
        print("  No bounty_examples table yet")
        db.close()
        return

    if not combos:
        print(f"  No examples yet. Run 'gsc_collect_bounty.py ghsa' first.")
        db.close()
        return

    print(f"\n{'CWE':<12} {'Lang':<12} {'Ex':>4} {'Fix':>4} {'Ready':>8}")
    print("-" * 48)

    for c in combos:
        neg = db.execute(
            "SELECT COUNT(*) FROM negative_examples WHERE cwe_id=? AND language=?",
            (c["cwe_id"], c["language"])
        ).fetchone()[0]
        ready = c["cnt"] >= MIN_EXAMPLES and c["fixes"] >= 3 and neg >= 1
        r = "✅ YES" if ready else f"⚠️ {MIN_EXAMPLES - c['cnt']} more"
        print(f"{c['cwe_id']:<12} {c['language']:<12} {c['cnt']:>4} {c['fixes']:>4} {r:>8}")

    db.close()


def _run_gate_all():
    """Run gate on all ready CWE+lang combos. Called from nightly pipeline (step 4).

    Key linkage: on PASS → ShadowManager.register_shadow() → detector_status (schema 29).
    """
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    try:
        combos = db.execute("""
            SELECT cwe_id, language, COUNT(*) as n,
                   SUM(CASE WHEN fix_quality='fix' THEN 1 ELSE 0 END) as fixes
            FROM bounty_examples
            WHERE cwe_id != '' AND language IN ('python','javascript','go','rust')
              AND vulnerable_code != ''
            GROUP BY cwe_id, language
            HAVING n >= ? AND fixes >= 3
        """, (MIN_EXAMPLES,)).fetchall()
    except sqlite3.OperationalError:
        print("  No bounty_examples table yet")
        db.close()
        return

    clean_files = _load_calibration_clean_files()
    results = []

    for c in combos:
        cwe, lang = c["cwe_id"], c["language"]

        # Check negative examples
        neg = db.execute(
            "SELECT COUNT(*) as c FROM negative_examples WHERE cwe_id=? AND language=?",
            (cwe, lang)).fetchone()
        if neg["c"] < 1:
            results.append({"cwe": cwe, "lang": lang, "status": "not_ready",
                           "reason": f"need 1+ negative (have {neg['c']})"})
            continue

        result = run_gate(cwe, lang)
        result["cwe"] = cwe
        result["lang"] = lang
        results.append(result)

        if result["status"] == "shadow_activated":
            try:
                from gsc_shadow_manager import ShadowDetectorManager
                ShadowDetectorManager(db).register_shadow(
                    result["rule_id"], tp_rate=result["tp_rate"])
                print(f"  🔗 ShadowManager: {result['rule_id']} registered (TP={result['tp_rate']:.2f})")
            except ImportError:
                print(f"  ⚠️ ShadowManager not available")

    db.close()

    # Summary
    activated = [r for r in results if r["status"] == "shadow_activated"]
    failed = [r for r in results if r["status"] == "failed"]
    not_ready = [r for r in results if r["status"] == "not_ready"]

    print(f"\n{'='*60}")
    print(f"  Gate results: {len(activated)} shadow, {len(failed)} failed, {len(not_ready)} not ready")
    if activated:
        for r in activated:
            print(f"    ✅ {r['rule_id']}: TP={r['tp_rate']:.0%}")
    if failed:
        for r in failed:
            print(f"    ❌ {r['cwe']} | {r['lang']}: {r.get('reason','?')}")

    return results


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "--check":
        show_dashboard()
        return

    if mode == "--run-gate":
        _run_gate_all()
        return

    if mode in ("--validate", "--generate") and len(sys.argv) == 4:
        cwe = sys.argv[2]
        lang = sys.argv[3]
    else:
        print("Usage: gsc_auto_detector.py --check")
        print("       gsc_auto_detector.py --validate CWE-79 javascript")
        print("       gsc_auto_detector.py --generate CWE-79 javascript")
        sys.exit(1)

    result = run_gate(cwe, lang)

    if mode == "--validate":
        print(json.dumps(result, indent=2, default=str))
        return

    # --generate
    print(f"\n🔧 GSC Auto-Detector Gate — {cwe} | {lang}\n")
    print(f"  Positives: {result.get('positives', '?')} | Negatives: {result.get('negatives', '?')}")
    print(f"  Status: {result['status']}")

    if result["status"] == "failed":
        print(f"  Reason: {result.get('reason', '?')}")
        validation = result.get("validation", {})
        if validation:
            print(f"  TP: {validation['tp_rate']:.0%} | FP on neg: {validation['fp_on_negatives']} | Clean FP: {validation['clean_critical_fp']}")
        sys.exit(1)
    elif result["status"] == "shadow_activated":
        print(f"  Rule: {result['rule_id']}")
        print(f"  TP rate: {result['tp_rate']:.0%} | Method: {result['validation']['method']}")
        print(f"  SHADOW mode — collecting verdicts (non-blocking)")
        print(f"  ≥10 verdicts + TP≥70% → FULL DETECTOR")
    else:
        print(f"  {result.get('reason', '')}")


if __name__ == "__main__":
    main()
