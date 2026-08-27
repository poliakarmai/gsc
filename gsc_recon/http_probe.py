#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""
GSC HTTP Probing v1.0 (v0.32) — HTTP status/headers/redirects/server banner.

Part of the new Recon front for GSC (bug bounty surface mapping). Probes a list
of hosts/domains via HTTP HEAD/GET requests, collecting signals like status code,
headers, redirects, and server banner. Tolerant by design: any network or
parsing error results in a ProbeResult with valid=False and an error description,
never raising an exception.

Source:
  - Direct HTTP(S) probing using stdlib urllib.request.

The module is stdlib-only (urllib.request, urllib.parse, http.client, ssl,
dataclasses, typing) and follows the RECON_CONTRACT.md for robustness and
layer separation.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Data class ────────────────────────────────────────────────────────────────
@dataclass
class ProbeResult:
    """Result of an HTTP probe against a single URL."""

    url: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    server: str = ""
    redirects: List[str] = field(default_factory=list)
    valid: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "server": self.server,
            "redirects": self.redirects,
            "valid": self.valid,
            "error": self.error,
        }


# ── Pure functions (no network) ───────────────────────────────────────────────
def normalize_url(host: str, scheme: str = "https") -> str:
    """Normalize a host string into a full URL with a scheme.

    - If `host` already has a scheme (http:// or https://), it's preserved.
    - Otherwise, `scheme` is prepended (default: "https").
    - Trailing slashes are stripped.
    - Empty or non-string input returns an empty string.
    """
    if not isinstance(host, str) or not host.strip():
        return ""
    
    host = host.strip()
    parsed = urllib.parse.urlparse(host)
    if parsed.scheme not in ("http", "https"):
        parsed = urllib.parse.urlparse(f"{scheme}://{host}")

    normalized = parsed.geturl().rstrip("/")
    return normalized

def extract_server(headers: Dict[str, str]) -> str:
    """Extract the 'Server' header value (case-insensitive).

    Returns an empty string if the header is not found or input is invalid.
    """
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if key.lower() == "server":
            if value is None: # Handle cases where header value is None
                return ""
            return value
    return ""

def is_reachable(status_code: int) -> bool:
    """Determines if a given HTTP status code indicates reachability.

    Considered reachable if status code is between 200 and 399 (inclusive),
    meaning success or a redirect.

    Tolerant: any input that is not an integer (e.g. None, str) is treated as
    unreachable and returns False instead of raising TypeError.
    """
    if not isinstance(status_code, int):
        return False
    return 200 <= status_code <= 399

# ── HTTP Client (network) ─────────────────────────────────────────────────────
class HttpClient:
    def __init__(self, timeout: int = 10, verify_ssl: bool = True, method: str = "HEAD") -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.method = method
        self.context = ssl.create_default_context()
        if not verify_ssl:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def _make_request(self, url: str, method: str) -> Optional[urllib.request.HTTPResponse]:
        req = urllib.request.Request(url, method=method)
        try:
            return urllib.request.urlopen(req, timeout=self.timeout, context=self.context)
        except urllib.error.HTTPError as e:
            # For HTTP errors, we still get a response object.
            # We want to capture the status and headers for these.
            return e
        except Exception:
            return None

    def probe(self, url: str) -> ProbeResult:
        """Perform an HTTP probe (HEAD with GET fallback) on a single URL."""
        result = ProbeResult(url=url)
        final_url = url
        redirect_chain: List[str] = []
        current_method = self.method

        try:
            while True:
                response: Optional[urllib.request.HTTPResponse] = self._make_request(final_url, current_method)
                if not response:
                    result.error = "network error or timeout"
                    return result

                status_code = response.getcode()
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # HEAD fallback to GET logic
                if current_method == "HEAD" and status_code in (403, 405):
                    response = self._make_request(final_url, "GET")
                    if not response:
                        result.error = "network error or timeout on GET fallback"
                        return result
                    status_code = response.getcode()
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    current_method = "GET" # Ensure subsequent redirects also use GET

                result.status_code = status_code
                result.headers = headers
                result.server = extract_server(headers)
                
                if 300 <= status_code <= 399:
                    location = headers.get("location")
                    if location:
                        redirect_chain.append(final_url)
                        final_url = urllib.parse.urljoin(final_url, location)
                        # Prevent redirect loops
                        if final_url in redirect_chain:
                            result.error = "redirect loop detected"
                            return result
                        continue # Follow redirect
                    else:
                        result.error = "redirect status but no Location header"
                        return result
                
                # If we got a final response, populate the result
                result.redirects = redirect_chain
                result.valid = True
                return result

        except Exception as e:
            result.error = str(e)[:200]  # cap long tracebacks in the report
            return result

    def probe_hosts(self, hosts: List[str], scheme: str = "https") -> List[ProbeResult]:
        """Probe a list of hosts/domains and return their ProbeResults."""
        results: List[ProbeResult] = []
        if not isinstance(hosts, list):
            return []
        
        for host in hosts:
            if not isinstance(host, str):
                results.append(ProbeResult(url=str(host), valid=False, error="invalid host type"))
                continue
            
            normalized_h = normalize_url(host, scheme)
            if not normalized_h:
                results.append(ProbeResult(url=host, valid=False, error="could not normalize URL"))
                continue

            results.append(self.probe(normalized_h))
        return results
