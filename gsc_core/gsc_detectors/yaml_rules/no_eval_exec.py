# Auto-generated from gsc-rules/sample.yml
# Rule: no-eval-exec — Use of eval() or exec() with dynamic input can lead to code injection

from ..base import RegexDetector

RULE_ID = "YAML-36ACF0AD"
ECHELON = 2
NOISE_TIER = "custom"
description = """Use of eval() or exec() with dynamic input can lead to code injection"""

patterns = [["\\beval\\s*\\(", "eval() call — potential code injection"], ["\\bexec\\s*\\(", "exec() call — potential code injection"], ["\\bcompile\\s*\\([^,]+,\\s*['\\\"](eval|exec|single)['\\\"]", "compile() in exec/eval mode"]]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="no-eval-exec",
    patterns=patterns,
    severity="LOW",    # bare eval()/exec() without taint — duplicated by GS036/GS037 taint-guard
    confidence=0.6,    # pattern-only, no taint analysis
    languages=('python', 'javascript'),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
