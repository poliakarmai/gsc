#!/usr/bin/env python3
"""GSC XSS PoC Validator — Playwright headless browser.

For reflected XSS findings: inject <script> payload, verify execution.
Supports both Playwright (headless browser, full verification) and
curl (lightweight, checks response body without execution).
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

XSS_PAYLOADS = [
    # (payload, marker, description)
    ("<script data-gsc-poc>document.title='VULNERABLE'</script>",
     "VULNERABLE",
     "Script execution via document.title change"),
    ("<img src=x data-gsc-poc onerror=document.title='VULNERABLE'>",
     "VULNERABLE",
     "Script execution via img onerror"),
    ('"><script data-gsc-poc>document.title="VULNERABLE"</script>',
     "VULNERABLE",
     "Tag breakout + script injection"),
    ("<svg data-gsc-poc onload=document.title='VULNERABLE'>",
     "VULNERABLE",
     "SVG onload — bypasses some filters"),
    ("<body data-gsc-poc onload=document.title='VULNERABLE'>",
     "VULNERABLE",
     "Body onload event"),
]


@dataclass
class XssPoCResult:
    vulnerable: bool
    payload: str
    marker: str
    method: str  # "playwright" | "curl" | "dry-run"
    detail: str = ""
    evidence: str = ""


def validate_xss_curl(url_template: str, param: str, payload: str, marker: str,
                      timeout: int = 10) -> XssPoCResult:
    """Validate reflected XSS via curl — checks response body for marker."""
    import subprocess

    encoded = urllib.parse.quote(payload)
    url = url_template.replace("{param}", param).replace("{payload}", encoded)
    if "{param}" not in url_template:
        url = f"{url_template}?{param}={encoded}"

    try:
        result = subprocess.run(
            ["curl", "-s", "-L", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        body = result.stdout
        if marker in body:
            return XssPoCResult(
                vulnerable=True, payload=payload, marker=marker,
                method="curl",
                detail="Payload reflected in response — potential XSS (not verified as executed)",
                evidence=body[:500]
            )
        elif payload in body:
            return XssPoCResult(
                vulnerable=True, payload=payload, marker=marker,
                method="curl",
                detail="Payload reflected but not executed — potential XSS",
                evidence=body[:500]
            )
        else:
            return XssPoCResult(
                vulnerable=False, payload=payload, marker=marker,
                method="curl",
                detail="Payload not reflected in response",
                evidence=f"Response size: {len(body)} bytes"
            )
    except Exception as e:
        return XssPoCResult(
            vulnerable=False, payload=payload, marker=marker,
            method="curl",
            detail=f"Curl failed: {e}"
        )


def validate_xss_playwright(url_template: str, param: str, payload: str, marker: str,
                            timeout: int = 15) -> XssPoCResult:
    """Validate reflected XSS via Playwright headless browser — verifies JS execution."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return XssPoCResult(
            vulnerable=False, payload=payload, marker=marker,
            method="dry-run",
            detail="Playwright not installed. Run: pip install playwright && playwright install chromium"
        )

    encoded = urllib.parse.quote(payload)
    url = url_template.replace("{param}", param).replace("{payload}", encoded)
    if "{param}" not in url_template:
        url = f"{url_template}?{param}={encoded}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")

                # Check for evidence of script execution BEFORE closing browser
                title = page.title()
                poc_element = page.query_selector("[data-gsc-poc]")
            finally:
                browser.close()

            if marker in title:
                return XssPoCResult(
                    vulnerable=True, payload=payload, marker=marker,
                    method="playwright",
                    detail=f"Script executed — document.title changed to '{title}'",
                    evidence=f"Title: {title}"
                )
            elif poc_element:
                return XssPoCResult(
                    vulnerable=True, payload=payload, marker=marker,
                    method="playwright",
                    detail="PoC element found in DOM but script may not have executed",
                    evidence=f"Title: {title} (unchanged)"
                )
            else:
                return XssPoCResult(
                    vulnerable=False, payload=payload, marker=marker,
                    method="playwright",
                    detail="Script did not execute — page may be safe",
                    evidence=f"Title: {title}"
                )
    except Exception as e:
        return XssPoCResult(
            vulnerable=False, payload=payload, marker=marker,
            method="playwright",
            detail=f"Playwright error: {e}"
        )


def generate_xss_poc(finding: dict) -> XssPoCResult | None:
    """Generate XSS PoC for a reflected XSS finding.

    Extracts endpoint URL + parameter from finding context.
    Falls back to curl if Playwright unavailable.
    """
    title = finding.get("title", "").lower()
    snippet = finding.get("snippet", finding.get("detail", ""))
    file_path = finding.get("file_path", "")

    # Only for reflected XSS
    if not any(kw in title or kw in snippet.lower()
               for kw in ("xss", "innerhtml", "document.write", "reflected", "echo")):
        return None

    # Pick best payload
    payload, marker, desc = XSS_PAYLOADS[0]

    # Try Playwright first, fall back to curl
    url_template = finding.get("metadata", {}).get("xss_url", "")
    param = finding.get("metadata", {}).get("xss_param", "q")

    if not url_template and "localhost" in snippet:
        # Extract localhost URL from snippet
        m = re.search(r'(https?://[^\s"\']+)', snippet)
        if m:
            url_template = m.group(1)

    if not url_template:
        return XssPoCResult(
            vulnerable=False, payload=payload, marker=marker,
            method="dry-run",
            detail="No target URL — add metadata.xss_url to finding"
        )

    result = validate_xss_playwright(url_template, param, payload, marker)
    # Fall back to curl if Playwright fails or unavailable
    if not result.vulnerable or result.method == "dry-run":
        result = validate_xss_curl(url_template, param, payload, marker)

    return result


def attach_xss_pocs(findings: list[dict]) -> int:
    """Attach XSS PoC results to findings. Returns count of validated XSS."""
    count = 0
    for f in findings:
        rule_id = f.get("rule_id", "")
        title = f.get("title", "").lower()
        if not any(kw in rule_id or kw in title
                   for kw in ("GS020", "xss", "innerHTML", "document.write")):
            continue

        result = generate_xss_poc(f)
        if result:
            f.setdefault("metadata", {})["xss_poc"] = {
                "vulnerable": result.vulnerable,
                "method": result.method,
                "payload": result.payload,
                "detail": result.detail,
                "evidence": result.evidence[:200],
            }
            if result.vulnerable:
                count += 1
    return count


# ── Test ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("XSS PoC Validator — test mode")
    print(f"{len(XSS_PAYLOADS)} payloads available")

    # Test curl validation on a safe target
    result = validate_xss_curl(
        "https://httpbin.org/get", "q",
        XSS_PAYLOADS[0][0], XSS_PAYLOADS[0][1],
        timeout=5
    )
    print("\nCurl test (httpbin — safe):")
    print(f"  vulnerable={result.vulnerable}, method={result.method}")
    print(f"  detail={result.detail}")

    # Test attachment
    findings = [
        {"rule_id": "GS020", "title": "Reflected XSS: Flask request parameter",
         "file_path": "app.py", "snippet": "print(request.args.get('name'))",
         "metadata": {"xss_url": "https://httpbin.org/get", "xss_param": "name"}},
    ]
    attached = attach_xss_pocs(findings)
    print(f"\nAttached XSS PoCs: {attached}")
    if findings[0].get("metadata", {}).get("xss_poc"):
        print(f"  result: {findings[0]['metadata']['xss_poc']}")
