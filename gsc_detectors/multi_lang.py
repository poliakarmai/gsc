# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Алексей Поляков
# Licensed under BSL 1.1 — see LICENSE

#!/usr/bin/env python3
"""
GSC Multi-Language Detectors — Go, TypeScript, Rust, Java.
v0.16 — basic regex patterns for secrets, injection, unsafe operations.
"""
import re, os, json
from pathlib import Path
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# Language patterns
# ═══════════════════════════════════════════════════════════════════════════════

GO_PATTERNS = {
    "secrets": [
        (r'(?:apiKey|api_key|API_KEY|secretKey|secret_key|SECRET_KEY|token|password)\s*[:=]\s*["\'][^\s"\']{8,}["\']',
         "GS001", "CRITICAL", "Hardcoded secret in Go"),
        (r'os\.Getenv\("([^"]+)"\)\s*==\s*""', "GS002", "HIGH", "Missing env var fallback check"),
    ],
    "injection": [
        (r'db\.(?:Query|Exec|QueryRow)\(\s*fmt\.Sprintf', "GS005", "CRITICAL", "SQL injection via fmt.Sprintf in Go"),
        (r'db\.(?:Query|Exec|QueryRow)\(\s*"[^"]*"\+', "GS005", "CRITICAL", "SQL injection via string concat in Go"),
        (r'os\.Exec|exec\.Command\(\s*"[^"]*"\+|exec\.Command\(\s*fmt\.Sprintf',
         "GS004", "CRITICAL", "Command injection in Go"),
    ],
    "crypto": [
        (r'crypto/md5|"crypto/sha1"', "GS002", "HIGH", "Weak crypto in Go"),
        (r'math/rand[^/]', "GS015", "MEDIUM", "Insecure random in Go (use crypto/rand)"),
    ],
}

TS_PATTERNS = {
    "secrets": [
        (r'(?:apiKey|api_key|API_KEY|secretKey|secret_key|SECRET_KEY|token|password)\s*[:=]\s*["\'`][^\s"\'`]{8,}["\'`]',
         "GS001", "CRITICAL", "Hardcoded secret in TypeScript"),
        (r'process\.env\.\w+\s*=\s*["\'`][^\s"\'`]{8,}["\'`]',
         "GS001", "HIGH", "Hardcoded secret assigned to env in TS"),
    ],
    "injection": [
        (r'eval\(|new Function\(', "GS017", "CRITICAL", "Dynamic code execution in TS"),
        (r'document\.write\(|innerHTML\s*=|dangerouslySetInnerHTML',
         "GS020", "CRITICAL", "XSS via innerHTML/dangerouslySetInnerHTML"),
        (r'child_process\.exec\(|\.execSync\(', "GS004", "CRITICAL", "Command injection in Node.js"),
        (r'(?:\.query|\.execute)\(\s*["\'`].*\$\{', "GS005", "CRITICAL", "SQL injection via template literal"),
    ],
    "config": [
        (r'ssl:\s*{\s*rejectUnauthorized:\s*false', "GS018", "HIGH", "SSL verification disabled in TS"),
        (r'cors:\s*{\s*origin:\s*["\']\*["\']', "GS019", "MEDIUM", "Permissive CORS in TS"),
    ],
}

RUST_PATTERNS = {
    "secrets": [
        (r'(?:api_key|API_KEY|secret_key|SECRET_KEY|token|password)\s*[:=]\s*["\'][^\s"\']{8,}["\']',
         "GS001", "CRITICAL", "Hardcoded secret in Rust"),
    ],
    "unsafe": [
        (r'unsafe\s*\{', "GS004", "HIGH", "Unsafe block in Rust"),
        (r'std::process::Command::new\([^)]*\+',
         "GS004", "CRITICAL", "Command injection in Rust"),
        (r'\.execute\(\s*format!', "GS005", "CRITICAL", "SQL injection via format! in Rust"),
    ],
    "crypto": [
        (r'extern\s+crate\s+md5|extern\s+crate\s+sha1', "GS002", "HIGH", "Weak crypto in Rust"),
        (r'rand::thread_rng\(\)', "GS015", "MEDIUM", "Non-cryptographic RNG in Rust"),
    ],
}

JAVA_PATTERNS = {
    "secrets": [
        (r'(?:apiKey|api_key|API_KEY|secretKey|secret_key|SECRET_KEY|token|password)\s*=\s*"[^\s"]{8,}"',
         "GS001", "CRITICAL", "Hardcoded secret in Java"),
    ],
    "injection": [
        (r'Statement.*\.execute(?:Query|Update)?\(\s*"[^"]*"\s*\+',
         "GS005", "CRITICAL", "SQL injection via string concat in Java"),
        (r'\.createStatement\(\)\.execute\(\s*"[^"]*"\s*\+',
         "GS005", "CRITICAL", "SQL injection in Java Statement"),
        (r'Runtime\.getRuntime\(\)\.exec\(', "GS004", "CRITICAL", "Command injection in Java"),
        (r'ProcessBuilder\([^)]*\+', "GS004", "HIGH", "Command injection via ProcessBuilder"),
    ],
    "deser": [
        (r'ObjectInputStream|readObject\(\)|readUnshared\(\)',
         "GS008", "CRITICAL", "Unsafe deserialization in Java"),
    ],
    "config": [
        (r'\.disable\(\)|\.all\(\)|\.anonymous\(\)', "GS019", "HIGH", "Permissive security config in Java"),
    ],
}

# Language → detector patterns
LANG_PATTERNS = {
    "go": GO_PATTERNS,
    "golang": GO_PATTERNS,
    "typescript": TS_PATTERNS,
    "javascript": TS_PATTERNS,
    "rust": RUST_PATTERNS,
    "java": JAVA_PATTERNS,
}

# Language → extensions
LANG_EXTENSIONS = {
    "go": {".go"},
    "typescript": {".ts", ".tsx"},
    "javascript": {".js", ".jsx", ".mjs"},
    "rust": {".rs"},
    "java": {".java"},
    "python": {".py", ".pyi"},
}


def detect_language(file_path: str | Path) -> Optional[str]:
    """Detect language from file extension."""
    suffix = Path(file_path).suffix.lower()
    for lang, exts in LANG_EXTENSIONS.items():
        if suffix in exts:
            return lang
    return None


def scan_multilang(repo_path: Path, languages: list[str] = None) -> list[dict]:
    """
    Scan a repo for multi-language vulnerabilities.
    Returns list of finding dicts compatible with GSC format.
    """
    findings = []
    if languages is None:
        languages = list(LANG_PATTERNS.keys())

    for lang in languages:
        patterns = LANG_PATTERNS.get(lang)
        if not patterns:
            continue
        exts = LANG_EXTENSIONS.get(lang, set())

        for fpath in repo_path.rglob("*"):
            if not fpath.is_file() or fpath.suffix.lower() not in exts:
                continue
            try:
                content = fpath.read_text(errors="replace")
            except Exception:
                continue

            for category, rules in patterns.items():
                for pattern, rule_id, severity, title in rules:
                    for m in re.finditer(pattern, content, re.MULTILINE):
                        line_no = content[:m.start()].count("\n") + 1
                        line_content = content.split("\n")[line_no - 1].strip()[:200]
                        rel_path = str(fpath.relative_to(repo_path)) if repo_path in fpath.parents else str(fpath)
                        findings.append({
                            "rule_id": rule_id,
                            "category": severity,
                            "severity": severity,
                            "title": title,
                            "file_path": rel_path,
                            "line_number": line_no,
                            "line": line_no,
                            "detail": line_content,
                            "noise_tier": "normal",
                            "echelon": 2,
                            "source": f"multi-lang:{lang}",
                            "pattern_title": f"{rule_id} ({lang})",
                        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="GSC Multi-Language Detectors")
    p.add_argument("path", help="Path to scan")
    p.add_argument("--lang", help="Comma-separated languages (default: all)")
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args()

    languages = args.lang.split(",") if args.lang else None
    findings = scan_multilang(Path(args.path), languages)

    if args.json:
        print(json.dumps(findings, indent=2, default=str))
    else:
        by_lang = {}
        for f in findings:
            by_lang.setdefault(f["source"], []).append(f)
        total = len(findings)
        print(f"Multi-language scan: {total} findings")
        for lang, items in sorted(by_lang.items()):
            print(f"  {lang}: {len(items)}")
        if findings:
            print()
            for f in findings[:10]:
                print(f"  [{f['category']}] {f['file_path']}:{f['line_number']} — {f['title']}")


if __name__ == "__main__":
    main()
