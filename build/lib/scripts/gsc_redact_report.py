#!/usr/bin/env python3
"""Redact scan reports before uploading to artifacts. Reuses v0.15 patterns."""
import json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from gsc_github_adapter import REDACTION_PATTERNS
except ImportError:
    REDACTION_PATTERNS = [
        (r'sk-[a-zA-Z0-9]{20,}', '[REDACTED:API_KEY]'),
        (r'AKIA[A-Z0-9]{16}', '[REDACTED:AWS_KEY]'),
        (r'ghp_[a-zA-Z0-9]{36}', '[REDACTED:GH_TOKEN]'),
        (r'-----BEGIN.*?PRIVATE KEY-----.*?-----END.*?PRIVATE KEY-----', '[REDACTED:PRIVATE_KEY]'),
        (r'(?:password|passwd|secret)\s*[=:]\s*["\'][^\s"\']{6,}["\']', '[REDACTED:CREDENTIAL]'),
    ]


def redact_text(text: str) -> str:
    for pattern, replacement in REDACTION_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL | re.IGNORECASE)
    return text


def main():
    scan_path, md_path = sys.argv[1], sys.argv[2]
    with open(scan_path, encoding="utf-8") as f:
        scan = json.load(f)
    for finding in scan.get("findings", []):
        if "snippet" in finding:
            finding["snippet"] = redact_text(finding["snippet"])
        poc = finding.get("metadata", {}).get("poc")
        if poc:
            finding["metadata"]["poc"] = redact_text(poc)
    for chain in scan.get("chains", []):
        chain["narrative"] = redact_text(chain.get("narrative", ""))
    with open(scan_path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)
    with open(md_path, encoding="utf-8") as f:
        md = f.read()
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(redact_text(md))
    print("Redaction applied", file=sys.stderr)


if __name__ == "__main__":
    main()
