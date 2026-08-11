#!/usr/bin/env python3
"""
GSC Rejudge Integration — multi-model revalidation for findings, PoC, and detectors.

Три режима:
  1. findings — pipe CRITICAL/HIGH через Rejudge для вердикта (TP/FP)
  2. poc      — валидация exploit path через 3-модельную панель
  3. detector — валидация новых паттернов на тестовых фикстурах

Использование:
  python3 gsc_rejudge.py findings scan.json
  python3 gsc_rejudge.py poc "<poC>"
  python3 gsc_rejudge.py detector patterns.json test_fixtures/
"""

import json, os, subprocess, sys, tempfile, shutil
from pathlib import Path
from typing import Optional

REJUDGE_PATH = shutil.which("rejudge")

def _get_api_key() -> str:
    """Load DEEPSEEK_API_KEY from Hermes .env for Rejudge."""
    for p in [Path(os.path.expanduser("~/.hermes/.env")),
              Path(os.path.expanduser("~/.hermes/env")),
              Path(".env")]:
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("DEEPSEEK_API_KEY="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    return os.environ.get("DEEPSEEK_API_KEY", "")


def rejudge(prompt: str, timeout: int = 120) -> tuple[bool, str]:
    """Run Rejudge panel. Returns (passed, output)."""
    if not REJUDGE_PATH:
        return False, "Rejudge not installed"
    try:
        env = {**os.environ, "DEEPSEEK_API_KEY": _get_api_key()}
        result = subprocess.run(
            [REJUDGE_PATH, prompt],
            capture_output=True, text=True, timeout=timeout,
            env=env
        )
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def revalidate_findings(scan_json: str) -> dict:
    """Pipe CRITICAL/HIGH findings through Rejudge for consensus verdict."""
    with open(scan_json) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

    if not critical_high:
        return {"status": "ok", "revalidated": 0, "message": "No CRITICAL/HIGH findings"}

    # Build prompt
    lines = ["Review these security findings and classify each as TP (true positive) or FP (false positive):\n"]
    for i, f in enumerate(critical_high[:10], 1):  # max 10 per batch
        lines.append(f"{i}. {f.get('rule_id','?')} {f.get('title','?')}")
        lines.append(f"   File: {f.get('file','?')}:{f.get('line','?')}")
        lines.append(f"   Snippet: {f.get('snippet','?')[:100]}")
        lines.append("")

    prompt = "\n".join(lines)
    passed, output = rejudge(prompt, timeout=180)

    return {
        "status": "ok" if passed else "error",
        "revalidated": len(critical_high[:10]),
        "verdict": output[:1000]
    }


def validate_poc(poc_text: str) -> dict:
    """Validate exploit PoC through Rejudge multi-model panel.
    
    Returns EXPLOITABLE when all 3 models agree it's a real vulnerability.
    Returns FALSE_POSITIVE when all 3 agree it's not exploitable.
    Returns NEEDS_REVIEW when models disagree.
    """
    prompt = f"""Review this security exploit proof-of-concept. Is it:

1. Actually exploitable (not a false positive)?
2. Complete (all steps are present and correct)?
3. Safe (doesn't contain destructive commands)?

PoC:
{poc_text}

Answer with: verdict (EXPLOITABLE / FALSE_POSITIVE / INCOMPLETE), confidence (0-100), and reasoning."""

    passed, output = rejudge(prompt, timeout=120)
    
    output_upper = output.upper()
    exploitable_count = output_upper.count("EXPLOITABLE")
    fp_count = output_upper.count("FALSE_POSITIVE")
    incomplete_count = output_upper.count("INCOMPLETE")
    
    # Multi-model consensus
    if fp_count >= 2 and exploitable_count == 0:
        verdict = "FALSE_POSITIVE"
    elif exploitable_count >= 2 and fp_count == 0:
        verdict = "EXPLOITABLE"
    elif exploitable_count == 3:
        verdict = "EXPLOITABLE"  # Unanimous
    elif fp_count == 3:
        verdict = "FALSE_POSITIVE"  # Unanimous
    else:
        verdict = "NEEDS_REVIEW"
    
    confidence = _extract_confidence(output)
    
    return {
        "verdict": verdict,
        "confidence": confidence,
        "models_agree": (exploitable_count == 3 or fp_count == 3),
        "exploitable_votes": exploitable_count,
        "fp_votes": fp_count,
        "output": output[:500]
    }


def validate_detector(pattern_file: str, fixtures_dir: str = None) -> dict:
    """Validate new GSC detector patterns through Rejudge."""
    with open(pattern_file) as f:
        patterns = json.load(f)

    # Build test cases from fixtures
    test_cases = []
    if fixtures_dir and os.path.isdir(fixtures_dir):
        for fname in os.listdir(fixtures_dir):
            fpath = os.path.join(fixtures_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, errors='ignore') as f:
                    test_cases.append(f"File: {fname}\n```\n{f.read()[:500]}\n```")

    lines = ["Validate these GSC security detector patterns for:", ""]
    lines.append("1. False positives — would they trigger on safe code?")
    lines.append("2. False negatives — would they miss real vulnerabilities?")
    lines.append("3. Regex robustness — are the patterns well-formed and efficient?")
    lines.append("")
    lines.append("Patterns:")
    for p in patterns:
        lines.append(f"- {p.get('title','?')}: `{p.get('search_pattern','?')}`")
    
    if test_cases:
        lines.append("\nTest fixtures:")
        lines.extend(test_cases)

    prompt = "\n".join(lines)
    passed, output = rejudge(prompt, timeout=180)

    return {
        "status": "ok" if passed else "error",
        "patterns": len(patterns),
        "fixtures": len(test_cases),
        "output": output[:1000]
    }


def _extract_confidence(text: str) -> int:
    """Extract confidence percentage from text."""
    import re
    m = re.search(r'(?:confidence|conf)[:\s]*(\d+)', text, re.IGNORECASE)
    return int(m.group(1)) if m else 50


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["findings", "poc", "detector"])
    ap.add_argument("target", help="scan.json, PoC text, or patterns.json")
    ap.add_argument("--fixtures", help="Test fixtures dir (detector mode)")
    args = ap.parse_args()

    DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
    if not DEEPSEEK_KEY:
        # Try to load from .env
        try:
            with open(os.path.expanduser("~/.hermes/.env")) as f:
                for line in f:
                    if line.startswith("DEEPSEEK_API_KEY="):
                        os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1].strip()
                        break
        except:
            pass

    if args.mode == "findings":
        result = revalidate_findings(args.target)
    elif args.mode == "poc":
        result = validate_poc(args.target)
    elif args.mode == "detector":
        result = validate_detector(args.target, args.fixtures)

    print(json.dumps(result, indent=2, ensure_ascii=False))
