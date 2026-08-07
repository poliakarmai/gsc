#!/usr/bin/env python3
"""OWASP Benchmark scorer — confusion matrix per CWE (v0.31)."""
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from benchmark.adapter import TestCase
from benchmark.cwe_map import build_cwe_to_rules
from benchmark.runner import scan_test_case, is_detected


@dataclass
class CweScore:
    cwe: str = ""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def tpr(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d > 0 else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d > 0 else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d > 0 else 0.0

    @property
    def accuracy(self) -> float:
        t = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / t if t > 0 else 0.0

    @property
    def owasp_score(self) -> float:
        return self.tpr - self.fpr

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    def to_dict(self) -> dict:
        return {"cwe": self.cwe, "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
                "tpr": round(self.tpr, 3), "fpr": round(self.fpr, 3),
                "precision": round(self.precision, 3), "accuracy": round(self.accuracy, 3),
                "owasp_score": round(self.owasp_score, 3), "total": self.total}


def run_benchmark(test_cases: List[TestCase], detectors, cwe_map: Dict[str, List[str]] = None) -> Dict[str, CweScore]:
    """Run all test cases → confusion matrix per CWE."""
    if cwe_map is None:
        cwe_map = build_cwe_to_rules()
    scores: Dict[str, CweScore] = defaultdict(CweScore)

    for tc in test_cases:
        rules = cwe_map.get(tc.cwe, [])
        if not rules:
            continue
        score = scores[tc.cwe]
        if not score.cwe:
            score.cwe = tc.cwe
        findings = scan_test_case(detectors, tc)
        detected = is_detected(findings, rules)
        if tc.is_vulnerable:
            if detected: score.tp += 1
            else:        score.fn += 1
        else:
            if detected: score.fp += 1
            else:        score.tn += 1
    return dict(scores)


def overall_score(scores: Dict[str, CweScore]) -> float:
    vals = [s.owasp_score for s in scores.values() if s.total > 0]
    return round(sum(vals) / len(vals), 3) if vals else 0.0
