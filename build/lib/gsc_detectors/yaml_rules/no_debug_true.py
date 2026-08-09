# Auto-generated from gsc-rules/sample.yml
# Rule: no-debug-true — DEBUG=True in production Django/Flask config

from gsc_detectors.base import RegexDetector

RULE_ID = "YAML-ECB85AD8"
ECHELON = 2
NOISE_TIER = "custom"
description = """DEBUG=True in production Django/Flask config"""

patterns = [["\\bDEBUG\\s*=\\s*True\\b", "DEBUG=True — should be False in production"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-debug-true",
    patterns=patterns,
    severity="MEDIUM",
    confidence=0.85,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
