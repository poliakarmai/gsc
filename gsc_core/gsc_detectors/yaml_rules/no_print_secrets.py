# Auto-generated from gsc-rules/sample.yml
# Rule: no-print-secrets — Printing potentially sensitive data to stdout

from ..base import RegexDetector

RULE_ID = "YAML-B39DC08C"
ECHELON = 2
NOISE_TIER = "custom"
description = """Printing potentially sensitive data to stdout"""

patterns = [["\\bprint\\s*\\(.*(?:password|secret|token|key|api_key)", "print() with sensitive variable"], ["\\blogging\\.\\w+\\(.*(?:password|secret|token|key|api_key)", "logging sensitive data"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-print-secrets",
    patterns=patterns,
    severity="HIGH",
    confidence=0.75,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
