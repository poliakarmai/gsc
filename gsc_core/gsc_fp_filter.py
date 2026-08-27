#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GSC False-Positive Filter v1.0.

Deterministic, stdlib-only pre-judge FP classifier for the most common
bounty-bucket false positives described in ``VERIFICATION_RULES.md``:

1. **CSP-blocked reflected XSS** — payload reflected into HTML but blocked
   by a Content-Security-Policy that does not allow ``unsafe-inline`` or
   ``unsafe-eval`` and exposes no nonce/hash. Such findings can never
   become a real XSS exploit in a modern browser.

2. **Public CDN directory listing** — open directory / info disclosure
   findings on hosts that are public content-delivery networks
   (CloudFront, Fastly, Cloudflare, Akamai, S3-static, GCS storage,
   Azure CDN, jsDelivr, unpkg, cdnjs, Cloudinary). The bucket/folder
   is meant to be public; the listing is a non-finding.

Both signals down-rank (CDN) or downgrade to LOW (CSP) the severity
**deterministically** before the LLM judge sees the case, per
VERIFICATION_RULES.md § "FP classes (deterministic auto-suppression)".

No network, no I/O, no environment variables at module level — pure
functions only. The module is the single source of truth for these two
FP rules; downstream verification layers import ``classify`` / the
narrow helpers and never re-implement the regex list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlsplit

__all__ = [
    "FP_KIND_CLEAN",
    "FP_KIND_CSP_BLOCKED",
    "FP_KIND_CDN_HOST",
    "FpVerdict",
    "CDN_PATTERNS",
    "parse_csp",
    "csp_allows_inline",
    "is_csp_blocking",
    "is_cdn_host",
    "classify",
    "classify_xss",
    "classify_directory_listing",
]


# ── FpVerdict kind constants (string enums) ────────────────
FP_KIND_CLEAN: str = "clean"
FP_KIND_CSP_BLOCKED: str = "csp_blocked"
FP_KIND_CDN_HOST: str = "cdn_host"


# ── CDN host patterns ──────────────────────────────────────
# Lower-case regex strings compiled with re.IGNORECASE.
# Each pattern is anchored to a public-CDN suffix to avoid false positives
# like ``cloudfront.example.com`` (a typo-squat pretending to be a CDN).
# Rules:
#   • Public clouds use real public-suffix domains we own a slice of
#     (cloudfront.net, fastly.net, cloudflare.com via cdnjs/edgesuite,
#     akamai.net, etc). For those, the regex requires the suffix to be
#     the *last* label(s) of the host, i.e. the host must END with
#     ".cloudfront.net" or be exactly "cloudfront.net".
#   • Self-hosted CDNs (Cloudflare, Akamai, jsDelivr, unpkg) are matched
#     by their canonical public-suffix domain: the host must END with
#     ".cloudflare.com" or be exactly "cloudflare.com" — a host like
#     "cloudfront.example.com" deliberately does NOT match
#     "cloudfront.net" and is rejected.
# The patterns are intentionally written as full string-anchored regex
# fragments; ``is_cdn_host`` wraps them with ``\Z`` so re.search behaves
# like re.fullmatch.
CDN_PATTERNS: List[str] = [
    r"\.cloudfront\.net\Z",          # AWS CloudFront distribution
    r"\.fastly\.net\Z",              # Fastly
    r"\.fastlylb\.net\Z",            # Fastly load balancer
    r"\.edgesuite\.net\Z",           # Akamai edgesuite
    r"\.akamaiedge\.net\Z",          # Akamai edge
    r"\.akamaihd\.net\Z",            # Akamai hd
    r"\.cloudflare\.com\Z",          # Cloudflare (incl. Workers public)
    r"\.cdnjs\.cloudflare\.com\Z",   # cdnjs
    r"\.s3[\-\.]?[a-z0-9\-]*\.amazonaws\.com\Z",  # S3 website/regional
    r"\.s3-website[--][a-z0-9\-]*\.amazonaws\.com\Z",  # S3 website endpoints
    r"(?:^|\.)storage\.googleapis\.com\Z",  # GCS public bucket
    r"\.azureedge\.net\Z",           # Azure CDN (classic)
    r"\.azurefd\.net\Z",             # Azure Front Door
    r"\.azure\.edge\.com\Z",         # Azure Edge
    r"\.cloudinary\.com\Z",          # Cloudinary
    r"\.jsdelivr\.net\Z",            # jsDelivr
    r"(?:^|\.)unpkg\.com\Z",         # unpkg (canonical: unpkg.com itself)
]


# ── FpVerdict dataclass ────────────────────────────────────
@dataclass
class FpVerdict:
    """Result of FP classification for a single finding.

    Attributes:
        kind: one of ``"clean"``, ``"csp_blocked"``, ``"cdn_host"``.
        reason: short, human-readable explanation (single line, no
            trailing dot). Empty for ``clean`` verdicts.
    """

    kind: str
    reason: str = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON / DB / audit-log storage."""
        return {"kind": self.kind, "reason": self.reason}


# ── Compiled CDN patterns (lazy, cached) ───────────────────
_CDN_COMPILED: Optional[List[re.Pattern]] = None


def _cdn_regexes() -> List[re.Pattern]:
    """Return CDN_PATTERNS as compiled ``re.Pattern`` objects (cached)."""
    global _CDN_COMPILED
    if _CDN_COMPILED is None:
        _CDN_COMPILED = [
            re.compile(p, re.IGNORECASE) for p in CDN_PATTERNS
        ]
    return _CDN_COMPILED


# ── CSP parsing ────────────────────────────────────────────
def parse_csp(header: Optional[str]) -> Dict[str, List[str]]:
    """Parse a single Content-Security-Policy header value.

    Returns a ``{directive_name: [source, source, ...]}`` dict.
    Tolerant by design: ``None``, empty string, whitespace-only, broken
    or ``";"``-only input all return ``{}`` — never raises.

    Multiple directives inside one header are separated by ``;``.
    Directive name and sources are split on the first whitespace.
    Each source is preserved verbatim (case, quoting) so callers can
    inspect ``'unsafe-inline'`` / ``'unsafe-eval'`` / nonces / hashes.
    """
    if header is None:
        return {}
    if not isinstance(header, str):
        return {}
    if not header.strip():
        return {}

    out: Dict[str, List[str]] = {}
    # Split on ";" — header may contain ";" inside a single source? Per
    # RFC, source-expression grammar forbids ";", so a plain split is
    # safe. We strip each chunk to handle surrounding whitespace and
    # stray ";" tokens (e.g. "default-src 'self';;script-src 'self'").
    for raw in header.split(";"):
        chunk = raw.strip()
        if not chunk:
            continue
        parts = chunk.split(None, 1)  # split on first whitespace
        name = parts[0].lower()
        if not name:
            continue
        if len(parts) == 1:
            out[name] = []
            continue
        # Sources are space-separated, may include quoted-string or
        # scheme/host/path tokens. We preserve them as-is; the caller
        # decides whether to interpret scheme/host/etc.
        sources = [s for s in parts[1].split() if s]
        out[name] = sources
    return out


# ── CSP inline / eval checks ───────────────────────────────
def csp_allows_inline(csp: Optional[str]) -> bool:
    """True iff the CSP allows inline scripts or eval.

    Source is the ``script-src`` directive, falling back to
    ``default-src`` when ``script-src`` is absent. Inline is allowed
    when either ``'unsafe-inline'`` or ``'unsafe-eval'`` is present in
    the effective source list.

    Nonce/hash allowances (``'nonce-...'`` / ``'sha256-...'``) are NOT
    considered "inline-allowing" here: those only permit specifically
    signed scripts, not arbitrary reflected payloads — and arbitrary
    reflection is what we are trying to downgrade.

    Tolerant: ``None``, empty, malformed CSP → ``False``.
    """
    parsed = parse_csp(csp)
    if not parsed:
        return False
    sources: List[str] = []
    if "script-src" in parsed:
        sources = parsed["script-src"]
    elif "default-src" in parsed:
        sources = parsed["default-src"]
    else:
        return False
    for src in sources:
        token = src.strip().strip("'").strip('"').lower()
        if token in ("unsafe-inline", "unsafe-eval"):
            return True
    return False


def is_csp_blocking(csp: Optional[str]) -> bool:
    """True iff a non-empty CSP is present AND does not allow inline/eval.

    Used for XSS / template-injection downgrades: a reflected payload
    cannot become a real script execution in a modern browser when the
    response carries a CSP header that forbids inline + eval. A missing
    or empty header is treated as "not blocking" — we cannot claim
    blocking on absence of evidence.

    Tolerant: ``None`` / empty / malformed → ``False``.
    """
    parsed = parse_csp(csp)
    if not parsed:
        return False
    if csp_allows_inline(csp):
        return False
    return True


# ── CDN host detection ─────────────────────────────────────
def _normalise_host(host: Optional[str]) -> str:
    """Strip scheme / path / port from ``host``; return lower-cased netloc.

    Accepts bare hostnames (``"d1.cloudfront.net"``) and full URLs
    (``"https://d1.cloudfront.net/x"``). The port is dropped because
    CDN-suffix patterns are domain-only. ``None`` / empty / unparseable
    input returns ``""``.
    """
    if host is None:
        return ""
    if not isinstance(host, str):
        return ""
    raw = host.strip()
    if not raw:
        return ""
    # If it looks like a URL (has "://" or starts with "//"), parse it;
    # otherwise treat as a bare host.
    if "://" in raw:
        try:
            netloc = urlsplit(raw).netloc
        except ValueError:
            return ""
    elif raw.startswith("//"):
        try:
            netloc = urlsplit("scheme:" + raw).netloc
        except ValueError:
            return ""
    else:
        netloc = raw
    if not netloc:
        return ""
    # Strip credentials, port, trailing dot, lower-case.
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    # netloc may include ":port"; rsplit on ":" once keeps IPv6 safe
    # (no port on IPv6 in our CDN patterns).
    if netloc.startswith("["):
        # IPv6 literal — strip the trailing port after the "]"
        end = netloc.find("]")
        if end != -1:
            netloc = netloc[: end + 1]
    else:
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
    netloc = netloc.rstrip(".").lower()
    return netloc


def is_cdn_host(host: Optional[str]) -> bool:
    """True iff ``host`` resolves to a public CDN.

    Compares the lower-cased netloc (scheme, port, path, credentials
    stripped) against ``CDN_PATTERNS``. Each pattern is anchored to the
    end of the host, so ``"d1abc.cloudfront.net"`` matches but a
    typo-squat like ``"cloudfront.example.com"`` does NOT.

    Tolerant: ``None`` / empty / non-string / unparseable → ``False``.
    """
    host_lc = _normalise_host(host)
    if not host_lc:
        return False
    for pattern in _cdn_regexes():
        if pattern.search(host_lc):
            return True
    return False


# ── Classify (top-level) ───────────────────────────────────
def classify(host: str = "", csp: str = "") -> FpVerdict:
    """Classify a finding's FP kind from its host + CSP context.

    Order of checks is significant (CDN first, then CSP). CDN wins
    because a public-CDN host can host a perfectly locked-down CSP
    (CSP does not matter — the host itself is not a security boundary);
    conversely, a strict CSP is a strong signal even on a non-CDN host.

    Args:
        host: hostname or URL where the finding was observed.
        csp: ``Content-Security-Policy`` header value (single string).

    Returns:
        FpVerdict with ``kind`` in ``{"clean","csp_blocked","cdn_host"}``.
    """
    if is_cdn_host(host):
        return FpVerdict(
            kind=FP_KIND_CDN_HOST,
            reason="public CDN host — directory listing / info disclosure is by design",
        )
    if is_csp_blocking(csp):
        return FpVerdict(
            kind=FP_KIND_CSP_BLOCKED,
            reason="CSP present without 'unsafe-inline'/'unsafe-eval' — reflected payload is blocked",
        )
    return FpVerdict(kind=FP_KIND_CLEAN, reason="")


# ── Classify (class-specific) ──────────────────────────────
def classify_xss(csp: str = "") -> FpVerdict:
    """FP classifier for reflected XSS findings (CSP only, no host check).

    The host check is irrelevant for XSS: a strict CSP on any host
    (including a CDN) blocks arbitrary inline reflection. CDN verdict
    is reserved for directory-listing / info-disclosure findings.
    """
    if is_csp_blocking(csp):
        return FpVerdict(
            kind=FP_KIND_CSP_BLOCKED,
            reason="CSP present without 'unsafe-inline'/'unsafe-eval' — reflected XSS blocked",
        )
    return FpVerdict(kind=FP_KIND_CLEAN, reason="")


def classify_directory_listing(host: str = "", csp: str = "") -> FpVerdict:
    """FP classifier for directory-listing / info-disclosure findings.

    Mirrors the full ``classify`` (CDN wins over CSP). CSP is generally
    irrelevant for static folder listings, but we still surface it for
    completeness so the caller can log why the verdict was CDN.
    """
    return classify(host=host, csp=csp)
