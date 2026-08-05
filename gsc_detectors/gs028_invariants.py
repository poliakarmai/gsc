"""
GS028 — Security Invariant Engine (v0.20).

Deterministic verification of invariants from the scanned repo's
.gsc-audit.yml. No LLM required. Instantiated per-scan (config is
repo-specific), NOT in the global DETECTORS registry.

Confidence = 0.90 (confirmed band) — invariants are the team's own
policy-as-code rules, so violations are high-confidence by design.
"""
from gsc_invariant_engine import InvariantEngine

INVARIANT_CONFIDENCE = 0.90


class GS028Detector:
    rule_id = "GS028"
    name = "Security Invariant Engine"
    requires_llm = False

    def __init__(self, engine: InvariantEngine):
        self.engine = engine

    def detect(self, file_path: str, content: str, language: str = "auto"):
        findings = []
        for v in self.engine.verify_file(file_path, content):
            findings.append({
                "rule_id": f"GS028-{v.invariant_id}",
                "title": v.message,
                "severity": v.severity,
                "confidence": INVARIANT_CONFIDENCE,
                "file": file_path,
                "line": v.line,
                "snippet": v.snippet,
                "language": language,
                "metadata": {
                    "invariant_id": v.invariant_id,
                    "invariant_type": v.invariant_type,
                },
            })
        return findings
