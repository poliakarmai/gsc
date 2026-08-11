#!/usr/bin/env python3
"""GHSA-based snippet benchmark for GSC.

Ground truth = bounty_examples:
  vulnerable_code -> positive (detector MUST fire -> TP/FN)
  fixed_code      -> negative (detector MUST NOT fire -> FP/TN)
"""
import sys, json, time, sqlite3, os, tempfile
from pathlib import Path
from collections import defaultdict

GSC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GSC))

from gsc_compliance import COMPLIANCE_MAP
from gsc_detectors.registry import get_detectors

DB = Path(os.path.expanduser("~/.hermes/state/gsc_audit.db"))
MIN_EXAMPLES = 30  # minimum per rule for reliable metrics


def cwe_to_rules() -> dict[str, list[str]]:
    """Reverse COMPLIANCE_MAP: CWE-89 -> ['GS005']."""
    m: dict[str, list[str]] = {}
    for rule_id, comp in COMPLIANCE_MAP.items():
        cwe = comp.get("cwe")
        if cwe:
            m.setdefault(cwe, []).append(rule_id.split("-")[0])
    return m


def build_cases() -> list[dict]:
    """Each bounty_example -> 2 cases (positive + negative)."""
    db = sqlite3.connect(str(DB))
    db.row_factory = sqlite3.Row
    rows = db.execute(
        "SELECT cwe_id, language, vulnerable_code, fixed_code, pattern_hash "
        "FROM bounty_examples WHERE fix_quality='fix'"
    ).fetchall()
    db.close()

    cases = []
    for r in rows:
        for code, expected in [(r["vulnerable_code"], "vulnerable"),
                               (r["fixed_code"], "safe")]:
            if not code or not code.strip():
                continue
            cases.append({
                "cwe": r["cwe_id"],
                "lang": r["language"],
                "code": code,
                "expected": expected,
                "pattern_hash": r["pattern_hash"],
            })
    return cases


def _ext(lang: str) -> str:
    return {"python": ".py", "javascript": ".js", "go": ".go",
            "typescript": ".ts", "java": ".java", "ruby": ".rb",
            "php": ".php", "rust": ".rs", "csharp": ".cs"}.get(lang, ".txt")


def run_detector_on_case(detector, case: dict) -> list[dict]:
    """Run one detector on one code snippet. Returns matched findings."""
    try:
        tmpdir = tempfile.mkdtemp()
        fpath = Path(tmpdir) / f"snippet{_ext(case['lang'])}"
        fpath.write_text(case["code"], encoding="utf-8")
        content = case["code"]

        # Most detectors use detect(ctx), some use detect(file, content, lang)
        if hasattr(detector, 'detect') and 'ctx' in str(type(detector).detect.__code__.co_varnames[:3]):
            from gsc_detectors import AuditContext
            ctx = AuditContext(project="benchmark", path=tmpdir)
            ctx.files = [fpath]
            ctx.file_contents[str(fpath)] = content
            findings = detector.detect(ctx)
        else:
            findings = detector.detect(str(fpath), content, case["lang"])

        return [f for f in (findings or []) if f is not None]
    except Exception:
        return []


def run_benchmark(rule_filter: str | None = None) -> dict:
    """TP/FP/FN/TN per rule -> TPR/FPR/Score."""
    cases = build_cases()
    cmap = cwe_to_rules()
    all_detectors = {d.rule_id: d for d in get_detectors()}

    counts: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    unmatched = 0

    for case in cases:
        rules = cmap.get(case["cwe"], [])
        if not rules:
            unmatched += 1
            continue
        for rule in rules:
            if rule_filter and rule != rule_filter:
                continue
            det = all_detectors.get(rule)
            if det is None:
                continue
            found = run_detector_on_case(det, case)
            c = counts[rule]
            if case["expected"] == "vulnerable":
                c["tp" if found else "fn"] += 1
            else:
                c["fp" if found else "tn"] += 1

    # Compute metrics
    metrics: dict = {"per_rule": {}, "overall": None, "cases": len(cases),
                     "unmatched_cwe": unmatched}
    reliable_scores = []

    for rule, c in sorted(counts.items()):
        tp, fn, fp, tn = c["tp"], c["fn"], c["fp"], c["tn"]
        total = tp + fn + fp + tn
        tpr = tp / (tp + fn) if (tp + fn) else None
        fpr = fp / (fp + tn) if (fp + tn) else None
        score = (tpr - fpr) if (tpr is not None and fpr is not None) else None
        reliable = total >= MIN_EXAMPLES

        metrics["per_rule"][rule] = {
            **c,
            "tpr": round(tpr, 3) if tpr is not None else None,
            "fpr": round(fpr, 3) if fpr is not None else None,
            "score": round(score, 3) if score is not None else None,
            "reliable": reliable,
            "total": total,
        }
        if reliable and score is not None:
            reliable_scores.append(score)

    if reliable_scores:
        metrics["overall"] = round(sum(reliable_scores) / len(reliable_scores), 3)

    return metrics


def print_report(metrics: dict):
    """Formatted table: Rule | TP FN FP TN | TPR FPR | Score."""
    hdr = f"{'Rule':8} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4}  {'TPR':>6} {'FPR':>6}  {'Score':>7}  {'N':>4}"
    print(hdr)
    print("-" * len(hdr))

    for rule, m in sorted(metrics["per_rule"].items()):
        tpr_s = f"{m['tpr']:.3f}" if m["tpr"] is not None else "   -  "
        fpr_s = f"{m['fpr']:.3f}" if m["fpr"] is not None else "   -  "
        sc_s = f"{m['score']:+.3f}" if m["score"] is not None else "    -   "
        rel = " ✓" if m["reliable"] else " ⚠"
        print(f"{rule:8} {m['tp']:>4} {m['fn']:>4} {m['fp']:>4} {m['tn']:>4}"
              f"  {tpr_s:>6} {fpr_s:>6}  {sc_s:>7}  {m['total']:>3}{rel}")

    ov = metrics["overall"]
    print(f"\nOverall GHSA Score: {ov:+.3f}" if ov is not None
          else "\nOverall: insufficient data (< MIN_EXAMPLES reliable rules)")
    print(f"Total cases: {metrics['cases']}, unmatched CWE: {metrics['unmatched_cwe']}")


def main():
    import argparse
    p = argparse.ArgumentParser(description="GHSA-based snippet benchmark")
    p.add_argument("--rule", help="Filter to single rule (e.g. GS005)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    t0 = time.time()
    print("Loading cases...")
    metrics = run_benchmark(rule_filter=args.rule)

    if args.json:
        print(json.dumps(metrics, indent=2, default=str))
    else:
        print_report(metrics)

    print(f"Time: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
