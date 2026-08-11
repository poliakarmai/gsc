#!/usr/bin/env python3
"""
GSC Detector Auto-Generator — creates YAML rules from bounty examples.

When 5+ bounty examples exist for the same CWE+language combo,
extracts common patterns and generates a YAML detector rule.

Usage:
    python3 scripts/gsc_auto_detector.py --check     # Check what can be generated
    python3 scripts/gsc_auto_detector.py --generate   # Generate rules for ready combos
"""
import os, sys, json, hashlib, sqlite3, re, requests
from datetime import datetime
from pathlib import Path

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
YAML_DIR = Path(__file__).parent.parent / "gsc_detectors" / "yaml_rules"
MIN_EXAMPLES = 5

CWE_NAME_MAP = {
    "CWE-22": "Path Traversal",
    "CWE-59": "Symlink Following",
    "CWE-73": "External Control of File Name or Path",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-133": "String Formatting",
    "CWE-200": "Information Disclosure",
    "CWE-201": "Information Exposure Through Sent Data",
    "CWE-331": "Insufficient Entropy",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-407": "Algorithmic Complexity",
    "CWE-488": "Exposure of Data Element to Wrong Session",
    "CWE-798": "Hardcoded Credentials",
    "CWE-834": "Excessive Iteration",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}


def check_ready_combos():
    """Find CWE+language combos with enough examples to generate a rule."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    combos = db.execute("""
        SELECT cwe_id, language, severity, COUNT(*) as cnt,
               GROUP_CONCAT(ghsa_id, ', ') as ghsa_ids
        FROM bounty_examples
        WHERE cwe_id != ''
          AND language IN ('python', 'javascript', 'go', 'rust')
          AND vulnerable_code != ''
        GROUP BY cwe_id, language
        HAVING cnt >= ?
        ORDER BY cnt DESC
    """, (MIN_EXAMPLES,)).fetchall()
    db.close()

    if not combos:
        print(f"❌ No CWE+language combos with {MIN_EXAMPLES}+ examples yet.")
        return []

    print(f"📊 Combos ready for detector generation ({MIN_EXAMPLES}+ examples each):\n")
    for c in combos:
        cwe_name = CWE_NAME_MAP.get(c["cwe_id"], c["cwe_id"])
        print(f"  {c['cwe_id']} ({cwe_name}) | {c['language']} | {c['cnt']} examples | {c['severity']}")
        print(f"    GHSA: {c['ghsa_ids']}")

    return combos


def generate_rule(cwe_id: str, language: str):
    """Generate a YAML detector rule from bounty examples."""
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row

    examples = db.execute("""
        SELECT vulnerable_code, fixed_code, summary, ghsa_id
        FROM bounty_examples
        WHERE cwe_id = ? AND language = ? AND vulnerable_code != ''
        ORDER BY severity, collected_at DESC
        LIMIT 10
    """, (cwe_id, language)).fetchall()
    db.close()

    if len(examples) < MIN_EXAMPLES:
        return None

    # Extract common patterns from vulnerable code
    patterns = extract_patterns(examples, language)

    cwe_name = CWE_NAME_MAP.get(cwe_id, cwe_id)
    rule_id = f"YAML-BOUNTY-{cwe_id.replace('CWE-','')}"
    safe_rule_id = rule_id.replace("-", "_").lower()

    # Determine severity from examples
    severities = [e["severity"] for e in examples]
    severity = "CRITICAL" if "CRITICAL" in severities else "HIGH" if "HIGH" in severities else "MEDIUM"

    rule_py = f'''# {rule_id} — {cwe_name}
# Auto-generated from {len(examples)} labelled bounty examples
# Sources: {', '.join(e['ghsa_id'] for e in examples[:5])}
# Generated: {datetime.now().isoformat()}

from gsc_detectors.base import RegexDetector

RULE_ID = "{rule_id}"
ECHELON = 2
NOISE_TIER = "precise"
description = (
    "{cwe_name} ({cwe_id}): auto-detected from {len(examples)} real-world "
    "vulnerability examples in {language} code"
)

patterns = [
'''

    for pat_title, pat_regex in patterns:
        rule_py += f'    [r"{pat_regex}",\n'
        rule_py += f'     "{pat_title}"],\n\n'

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


def extract_patterns(examples: list, language: str) -> list:
    """Extract common regex patterns from vulnerable code examples."""
    # Collect all removed lines from vulnerable code
    all_lines = []
    for ex in examples:
        vuln = ex["vulnerable_code"]
        for line in vuln.split("\n"):
            stripped = line.strip()
            if stripped and len(stripped) > 5 and not stripped.startswith("#"):
                all_lines.append(stripped)

    if not all_lines:
        return [("Generic vulnerability pattern", r"(?i)(TODO|FIXME|HACK|XXX)")]

    # Strategy: find function calls and keywords that appear in multiple examples
    from collections import Counter

    # Extract function call patterns
    func_calls = Counter()
    for line in all_lines:
        match = re.search(r'(\w+\.\w+|\w+)\s*\(', line)
        if match:
            func_calls[match.group(1)] += 1

    # Extract assignment patterns
    assignments = Counter()
    for line in all_lines:
        if "=" in line and "==" not in line:
            key = line.split("=")[0].strip().split()[-1] if line.split("=")[0].strip() else "?"
            if len(key) > 2:
                assignments[key] += 1

    patterns = []

    # Pattern 1: Repeated function calls (appears in 2+ examples)
    for func, count in func_calls.most_common(8):
        if count >= 2:
            escaped_func = re.escape(func)
            patterns.append(
                (f"{cwe_name_from_examples(examples)}: {func}() called unsafely (found in {count}/{len(examples)} examples)",
                 f"{escaped_func}\\s*\\(")
            )

    # Pattern 2: Common dangerous assignments
    for key, count in assignments.most_common(5):
        if count >= 2 and key != "?":
            escaped_key = re.escape(key)
            patterns.append(
                (f"Dangerous assignment pattern: {key} (found {count}/{len(examples)} times)",
                 f"{escaped_key}\\s*=")
            )

    # Fallback: generic pattern from first example
    if not patterns:
        sample_line = all_lines[0][:80]
        cleaned = re.sub(r'[^a-zA-Z0-9_\\s]', '.', sample_line)
        patterns.append(
            (f"{cwe_name_from_examples(examples)}: pattern from bounty example",
             f"{cleaned[:60]}"))

    return patterns[:10]


def cwe_name_from_examples(examples) -> str:
    cwe = examples[0]["summary"] if examples else "vulnerability"
    return cwe[:60]


def save_rule(rule_py: str, safe_rule_id: str):
    """Save generated rule to yaml_rules directory and register in __init__.py."""
    YAML_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"{safe_rule_id}.py"
    filepath = YAML_DIR / filename

    filepath.write_text(rule_py)
    print(f"  ✅ Rule saved: {filepath}")

    # Register in __init__.py
    init_path = YAML_DIR / "__init__.py"
    if not init_path.exists():
        init_path.write_text("# Auto-generated YAML rules registry\n\n")
        return

    init_content = init_path.read_text()
    import_line = f"from .{safe_rule_id} import detect"
    if import_line not in init_content:
        with open(init_path, "a") as f:
            f.write(f"{import_line}  # auto-generated {datetime.now().strftime('%Y-%m-%d')}\n")
        print(f"  ✅ Registered in __init__.py")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("--check", "--generate"):
        print("Usage: gsc_auto_detector.py --check    # Check ready combos")
        print("       gsc_auto_detector.py --generate # Generate YAML rules")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "--check":
        combos = check_ready_combos()
        if combos:
            print(f"\n💡 Run with --generate to create YAML rules.")
        return

    # Generate mode
    print("🔧 GSC Detector Auto-Generator\n")

    combos = check_ready_combos()
    if not combos:
        return

    generated = 0
    for combo in combos:
        cwe_id = combo["cwe_id"]
        language = combo["language"]
        count = combo["cnt"]

        print(f"\n{'='*60}")
        print(f"  Generating: {cwe_id} | {language} | {count} examples")

        result = generate_rule(cwe_id, language)
        if result is None:
            print(f"  ⚠️ Skipped — not enough patterns extracted")
            continue

        rule_py, rule_id, safe_rule_id = result

        # Check if rule already exists
        if (YAML_DIR / f"{safe_rule_id}.py").exists():
            print(f"  ⚠️ Rule already exists: {safe_rule_id}.py")
            continue

        save_rule(rule_py, safe_rule_id)
        generated += 1

    print(f"\n{'='*60}")
    print(f"✅ {generated} YAML detector rules generated")


if __name__ == "__main__":
    main()
