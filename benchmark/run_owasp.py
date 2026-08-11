#!/usr/bin/env python3
"""OWASP Benchmark — end-to-end. Usage: python3 benchmark/run_owasp.py [--limit N]"""
import sys, json, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmark.adapter import parse_owasp_benchmark
from benchmark.scorer import run_benchmark, overall_score
from benchmark.cwe_map import build_cwe_to_rules, coverage_report
from gsc_detectors.registry import get_detectors

BENCHMARK_ROOT = "/tmp/OWASP-Benchmark"
EXPECTED_CSV = f"{BENCHMARK_ROOT}/expectedresults-1.2.csv"

def main():
    limit = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--limit" else 0

    t0 = time.time()
    print("Loading test cases...")
    test_cases = parse_owasp_benchmark(BENCHMARK_ROOT, EXPECTED_CSV)
    if limit:
        test_cases = test_cases[:limit]
    print(f"  {len(test_cases)} test cases loaded")
    vuln = sum(1 for t in test_cases if t.is_vulnerable)
    safe = sum(1 for t in test_cases if not t.is_vulnerable)
    print(f"  {vuln} vulnerable, {safe} safe")

    print("Loading detectors...")
    # Only CWE-relevant detectors for OWASP Benchmark (GS004 CWE-78, GS005 CWE-89, GS020 CWE-79)
    all_detectors = get_detectors()
    relevant = {"GS004", "GS005", "GS020"}
    detectors = [d for d in all_detectors
                 if getattr(d, "rule_id", "") in relevant
                 and not getattr(d, "requires_llm", False)]
    print(f"  {len(detectors)} CWE-relevant detectors ({relevant})")

    print("Running benchmark...")
    scores = run_benchmark(test_cases, detectors)
    print(f"  {len(scores)} CWEs with results")

    for cwe, s in sorted(scores.items()):
        print(f"  {cwe}: TPR={s.tpr:.3f} FPR={s.fpr:.3f} P={s.precision:.3f} "
              f"(TP={s.tp} FP={s.fp} FN={s.fn} TN={s.tn})")

    owasp_avg = overall_score(scores)
    print(f"\nOWASP Score (avg TPR-FPR): {owasp_avg:.3f}")

    # Coverage
    cwe_map = build_cwe_to_rules()
    cov = coverage_report(cwe_map)
    print(f"\nCoverage: {cov['coverage_pct']}% of OWASP Top 10 CWEs")
    print(f"Covered: {', '.join(c['cwe'] for c in cov['covered'])}")
    print(f"Uncovered: {', '.join(c['cwe'] for c in cov['uncovered'])}")

    elapsed = time.time() - t0
    print(f"\nTotal: {elapsed:.1f}s")

    # Save results
    out = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "test_cases": len(test_cases),
        "cwe_scores": {cwe: s.to_dict() for cwe, s in scores.items()},
        "owasp_score": owasp_avg,
        "coverage": cov,
        "elapsed_s": round(elapsed, 1),
    }
    outpath = Path(__file__).resolve().parent / "owasp_results.json"
    json.dump(out, open(outpath, "w"), indent=2)
    print(f"Saved: {outpath}")


if __name__ == "__main__":
    main()
