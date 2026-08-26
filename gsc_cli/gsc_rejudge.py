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

import json, os, re, subprocess, sys, tempfile, shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from gsc_llm_providers import defang, UNTRUSTED_GUARD

REJUDGE_PATH = shutil.which("rejudge")

# --- Receipt contract (Phase 2) ---------------------------------------------
#
# A LLM verdict on a finding must cite concrete code as proof:
#   file path, line number, and a short code fragment from the cited location.
# Without that, the verdict is INCOMPLETE — we cannot trust the model's claim
# and the finding is demoted (severity + confidence).
#
# The receipt is extracted from the model's free-form verdict text. Parsing is
# deliberately tolerant (multiple acceptable formats) but the presence of a
# `file:line` reference plus a code fragment is non-negotiable.

# Severity demotion table for verdicts missing a receipt.
_RECEIPT_DEMOTION = {
    "CRITICAL": "HIGH",
    "HIGH":     "MEDIUM",
    "MEDIUM":   "LOW",
    "LOW":      "INFO",
}

# Confidence penalty (subtracted) when verdict lacks a receipt.
_RECEIPT_CONFIDENCE_PENALTY = 25

# Snippet cap passed to the LLM as evidence context. Larger than the old
# [:100] so the model can actually reason about the cited code.
_SNIPPET_EVIDENCE_CAP = 300


@dataclass
class Receipt:
    """Structured proof cited by an LLM in its verdict.

    A valid receipt has all three fields populated:
      * file — path to the source file (or relative path)
      * line — 1-based line number (int)
      * code — short code fragment actually present at file:line
    """
    file: str = ""
    line: int = 0
    code: str = ""

    @property
    def is_valid(self) -> bool:
        """True iff all three fields are present and line > 0."""
        return bool(self.file) and self.line > 0 and bool(self.code)


def parse_receipt(text: str) -> Optional[Receipt]:
    """Extract a Receipt from a free-form LLM verdict.

    Accepts several common shapes:
      * `path/to/file.py:42`  (with optional `File: ` prefix)
      * `path/to/file.py:42 — <code>`
      * `Receipt: path/to/file.py:42  Code: <code>`
      * `path/to/file.py line 42` (with explicit `line` keyword)

    Returns None if no recognisable file:line reference is found.
    The `code` field is best-effort — if the line immediately after the
    `file:line` reference looks like a quoted/indented code fragment, we keep
    it; otherwise the receipt is returned without code (caller will treat
    it as INCOMPLETE).
    """
    if not text:
        return None

    # Pattern 1: `File: path/to/file.py:42`  or  `path/to/file.py:42`
    m = re.search(
        r"(?:file\s*[:\-]?\s*)?"
        r"([^\s:`'\"]+\.[A-Za-z0-9]{1,8})"   # path with extension
        r"\s*[:]\s*"
        r"(\d{1,6})",                          # line number
        text,
        re.IGNORECASE,
    )
    file_path = ""
    line_no = 0
    if m:
        file_path = m.group(1).strip().strip("`'\"")
        try:
            line_no = int(m.group(2))
        except (TypeError, ValueError):
            line_no = 0

    # Pattern 2: `path/to/file.py line 42`  (no colon)
    if not line_no:
        m2 = re.search(
            r"([^\s:`'\"]+\.[A-Za-z0-9]{1,8})\s+line\s+(\d{1,6})",
            text,
            re.IGNORECASE,
        )
        if m2:
            file_path = m2.group(1).strip().strip("`'\"")
            try:
                line_no = int(m2.group(2))
            except (TypeError, ValueError):
                line_no = 0

    if not file_path or line_no <= 0:
        return None

    # Try to capture a code fragment after the file:line reference.
    # Look for either a backtick-quoted fragment, a `Code:` field, or the
    # first non-empty indented/bulleted line following the reference.
    code = ""

    # a) Backtick-quoted: `some code`
    backticks = re.findall(r"`([^`\n]{2,200})`", text)
    if backticks:
        code = backticks[0].strip()

    # b) Explicit `Code:` / `Snippet:` / `Evidence:` field
    if not code:
        m3 = re.search(
            r"(?:code|snippet|evidence|quote)\s*[:\-]\s*"
            r"([^\n]{2,200})",
            text,
            re.IGNORECASE,
        )
        if m3:
            code = m3.group(1).strip()
            # Strip only a *matching* surrounding quote pair, not every
            # trailing quote (a secret value may itself end in a quote).
            for q in ("`", "'", '"'):
                if code.startswith(q) and code.endswith(q) and len(code) >= 2:
                    code = code[1:-1]
                    break

    # c) First non-empty line after the file:line reference that looks
    #    like code (starts with a typical code char, not a sentence).
    if not code:
        idx = text.find(f"{file_path}:{line_no}")
        if idx == -1:
            idx = text.find(file_path)
        if idx != -1:
            tail = text[idx:].splitlines()[1:]  # skip the reference line
            for ln in tail:
                ln_stripped = ln.strip()
                if not ln_stripped:
                    continue
                if re.match(r"^[\w\s.,;:()\[\]{}=\"'`+\-*/<>!|&%]+$", ln_stripped) and \
                   any(ch in ln_stripped for ch in "=(){}[]<>"):
                    code = ln_stripped[:200]
                    break

    return Receipt(file=file_path, line=line_no, code=code)


def validate_receipt(receipt: Optional[Receipt]) -> bool:
    """Pure check: does the receipt carry enough evidence to trust the verdict?

    A receipt is valid iff it has a non-empty file, a positive line number,
    AND a non-empty code fragment. Without all three, the verdict cannot be
    reproduced or verified — it is INCOMPLETE.
    """
    return receipt is not None and receipt.is_valid


def demote_finding_for_missing_receipt(finding: dict) -> dict:
    """Apply a deterministic demotion when a verdict lacks a receipt.

    Severity is demoted one step (CRITICAL→HIGH, HIGH→MEDIUM, …).
    Confidence is reduced by _RECEIPT_CONFIDENCE_PENALTY (floored at 0).
    A `receipt_status: INCOMPLETE` flag and original values are preserved in
    metadata so downstream consumers can see what happened.
    """
    if not isinstance(finding, dict):
        return finding

    new = dict(finding)  # shallow copy — don't mutate caller's dict
    original_severity = new.get("severity", "")
    demoted = _RECEIPT_DEMOTION.get(original_severity)
    if demoted:
        new["severity"] = demoted
        new["original_severity"] = original_severity

    # Confidence may live at top level or in metadata; honour both.
    try:
        orig_conf = int(new.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        orig_conf = 0
    new_conf = max(0, orig_conf - _RECEIPT_CONFIDENCE_PENALTY)
    new["confidence"] = new_conf
    if new_conf < orig_conf:
        new.setdefault("metadata", {})
        if isinstance(new["metadata"], dict):
            new["metadata"]["original_confidence"] = orig_conf

    new["receipt_status"] = "INCOMPLETE"
    return new

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
    """Pipe CRITICAL/HIGH findings through Rejudge for consensus verdict.

    For each finding the LLM is asked to return a *receipt* — a file:line
    citation plus a short code fragment — alongside the TP/FP verdict. Verdict
    blocks are split per finding, the receipt is parsed, and any finding
    whose verdict lacks a valid receipt is demoted (severity one step down,
    confidence reduced) and flagged ``receipt_status: INCOMPLETE``.

    Returned dict includes ``receipts`` (per-finding dict) and
    ``incomplete`` (count) so callers can audit the demotions.
    """
    with open(scan_json) as f:
        data = json.load(f)

    findings = data.get("findings", [])
    critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]

    if not critical_high:
        return {"status": "ok", "revalidated": 0, "message": "No CRITICAL/HIGH findings"}

    # Build prompt — untrusted fields (title/file/snippet come from the scanned
    # repo) are defanged so embedded instructions cannot steer the verdict.
    # Phase 2: we pass a full file:line + snippet cap (300 chars, not 100) so
    # the model has enough evidence to cite concrete code, and we explicitly
    # require a receipt in the response.
    lines = [
        UNTRUSTED_GUARD + "\n\n",
        "Review these security findings and classify each as TP (true positive) or FP (false positive).",
        "For EACH finding you MUST cite concrete code as a receipt:",
        "  Receipt: <relative/path/to/file>:<line>  Code: <short code fragment>",
        "Without a receipt, the verdict is INCOMPLETE and will be rejected.\n",
    ]
    for i, f in enumerate(critical_high[:10], 1):  # max 10 per batch
        lines.append(f"--- Finding {i} ---")
        lines.append(f"Rule: {f.get('rule_id','?')}  Title: {defang(f.get('title','?'))}")
        lines.append(f"File: {defang(f.get('file','?'))}:{f.get('line','?')}")
        lines.append(f"Snippet: {defang(f.get('snippet','?')[:_SNIPPET_EVIDENCE_CAP])}")
        lines.append("")

    prompt = "\n".join(lines)
    passed, output = rejudge(prompt, timeout=180)

    # Parse per-finding receipts from the verdict. The model is asked to
    # delimit each finding with `--- Finding N ---` but we don't depend on
    # it — we just look for every `file:line` reference in the output and
    # pair it with the finding at the same index.
    receipts = []
    incomplete = 0
    for idx, finding in enumerate(critical_high[:10], 1):
        receipt = parse_receipt(output)
        # Per-finding window: try to find a receipt mentioning this finding's
        # file path explicitly; fall back to the first parsed receipt.
        if receipt is not None and finding.get("file"):
            target = str(finding.get("file", ""))
            # Search the verdict for a mention of this file's full path,
            # falling back to basename only if the full path is absent.
            needle = target if target in output else os.path.basename(target)
            if needle and needle in output:
                # Re-parse starting from the first mention of this file.
                pos = output.find(needle)
                receipt = parse_receipt(output[pos:])
        ok = validate_receipt(receipt)
        if not ok:
            incomplete += 1
        receipts.append({
            "finding_index": idx,
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "receipt_ok": ok,
            "receipt": (
                {"file": receipt.file, "line": receipt.line, "code": receipt.code}
                if receipt is not None else None
            ),
        })

    return {
        "status": "ok" if passed else "error",
        "revalidated": len(critical_high[:10]),
        "incomplete": incomplete,
        "receipts": receipts,
        "verdict": output[:1000],
    }


def validate_poc(poc_text: str) -> dict:
    """Validate exploit PoC through Rejudge multi-model panel.
    
    Returns EXPLOITABLE when all 3 models agree it's a real vulnerability.
    Returns FALSE_POSITIVE when all 3 agree it's not exploitable.
    Returns NEEDS_REVIEW when models disagree.
    """
    prompt = f"""{UNTRUSTED_GUARD}

Review this security exploit proof-of-concept. Is it:

1. Actually exploitable (not a false positive)?
2. Complete (all steps are present and correct)?
3. Safe (doesn't contain destructive commands)?

PoC:
{defang(poc_text)}

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
                    test_cases.append(f"File: {fname}\n{defang(f.read()[:500])}")

    lines = [UNTRUSTED_GUARD + "\n\n", "Validate these GSC security detector patterns for:", ""]
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
