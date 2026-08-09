# SSTI-001 — Server-Side Template Injection
# Based on: OWASP SSTI, PortSwigger SSTI labs, pentesting cheatsheet

from gsc_detectors.base import RegexDetector

RULE_ID = "YAML-SSTI001"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "Server-Side Template Injection (SSTI): user input flowing into "
    "template render without sanitization — can lead to RCE"
)

patterns = [
    # Flask/Jinja2: render_template_string with request data
    [r"render_template_string\s*\(\s*(?:request\.(?:args|form|values|data|json|get_json))",
     "Flask SSTI: render_template_string with user input — RCE risk"],

    # Flask/Jinja2: render_template with user-controlled template name
    [r"render_template\s*\(\s*(?:request\.(?:args|form|values)\.get)",
     "Flask SSTI: user-controlled template name — potential SSTI"],

    # Jinja2: direct template compilation from user input
    [r"jinja2\.(?:Template|Environment)\s*\(\s*(?:request\.|user_input|input_data)",
     "Jinja2 SSTI: Template/Environment from user input — RCE risk"],

    # Jinja2: env.from_string with request data
    [r"\.from_string\s*\(\s*(?:request\.(?:args|form|values|data))",
     "Jinja2 SSTI: from_string() with user input — RCE risk"],

    # Django: Template() with request.GET/POST
    [r"Template\s*\(\s*request\.(?:GET|POST)\b",
     "Django SSTI: Template() with request data — code execution risk"],

    # Generic: template rendering with string formatting of user input
    [r"\.render\s*\(\s*\*\*\s*(?:request\.(?:args|form|values))",
     "SSTI: .render(**request data) — template context injection"],

    # SSTI exploit payloads in code (pentest tools/debug endpoints)
    [r"\{\{\s*(?:config|self\._TemplateReference__context|''\.__class__\.__mro__)",
     "SSTI exploit payload: {{ config }} or MRO traversal — backdoor indicator"],

    # f-string in render_template_string (double injection)
    [r"render_template_string\s*\(\s*f['\"]",
     "SSTI + f-string: template rendered from Python f-string — critical"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="ssti-injection",
    patterns=patterns,
    severity="CRITICAL",
    confidence=0.92,
    languages=('python',),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
