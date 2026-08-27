# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Tech-Stack Detection (Wappalyzer-lite) v1.0.

Recon-front: identify web technologies (server, language, JS framework, CMS,
analytics, reverse proxy) from HTTP response headers and HTML content. The
output feeds the GSC bounty recon pipeline — knowing the stack drives
targeted detector selection (e.g. WP plugin vulns only matter for WordPress
sites, IIS-specific rules only for IIS, etc.).

Four detection channels:
  1. HTTP headers        — ``Server``, ``X-Powered-By``, ``Set-Cookie``,
                           ``CF-Ray``, ``X-Varnish``, ``Via`` ...
  2. HTML body           — JS framework markers (``data-reactroot``,
                           ``ng-app``, ``data-v-``, ``_next/static``,
                           ``__nuxt`` ...).
  3. <meta> tags         — generator strings (``WordPress``, ``Joomla``,
                           ``Drupal`` ...).
  4. Cookies             — session-cookie names (``PHPSESSID``,
                           ``JSESSIONID``, ``ASP.NET_SessionId``,
                           ``_session`` ...). Cookies may be passed in
                           the ``Set-Cookie`` header value or as a
                           ``Cookie`` header on outbound recon.

Pure / stdlib-only / no network. The detector is a list of compiled
``TechSignature`` records; the public API is ``detect_tech(headers, html)``
and ``classify_stack(matches)``.

Design notes
------------
* One tech → one ``TechMatch`` (first channel that fires wins; subsequent
  matches on the same tech are skipped). This keeps the recon output
  stable and avoids noise from redundant evidence.
* Header matching is case-insensitive on the header *name* but case-
  sensitive on the regex (most server banners are lowercase; PHP/ASP
  banners are case-sensitive by convention).
* Patterns are pre-compiled at module import — ``detect_tech`` is hot
  in the recon loop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TechMatch:
    """A single technology match produced by ``detect_tech``.

    Attributes:
        name: Canonical technology name (e.g. ``"WordPress"``,
              ``"PHP"``, ``"Cloudflare"``).
        category: One of ``"server" | "language" | "framework" | "cms" |
                  "analytics" | "proxy" | "other"``. Drives
                  ``classify_stack`` grouping.
        evidence: Human-readable string showing the first signal that
                  fired — e.g. ``"header:Server=nginx/1.25.1"``,
                  ``"html:wp-content/"``, ``"cookie:PHPSESSID"``.
    """
    name: str
    category: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "evidence": self.evidence,
        }


@dataclass
class TechSignature:
    """A single technology signature (the internal recipe).

    A signature fires when *any* of its four channels matches:

      * ``header_patterns``  — dict of header name (lower) → regex on the
                               header value. Case-insensitive header-name
                               lookup; regex matched case-insensitively.
      * ``html_patterns``    — list of regexes searched in the HTML body.
      * ``meta_patterns``    — list of regexes matched against the
                               ``<meta name="generator" content="...">``
                               tag (and similar generator-style metas).
      * ``cookie_patterns``  — list of regexes matched against every
                               ``Set-Cookie`` value found in the headers
                               AND the optional ``Cookie`` header.

    First match wins per signature (channel priority: header > html > meta
    > cookie). Once a signature fires, the remaining channels are not
    consulted for the same technology.
    """
    name: str
    category: str
    header_patterns: Dict[str, str] = field(default_factory=dict)
    html_patterns: List[str] = field(default_factory=list)
    meta_patterns: List[str] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Pre-compile patterns so detect_tech() stays hot-path friendly.
        self._header_re: Dict[str, Pattern[str]] = {
            k.lower(): re.compile(v, re.IGNORECASE)
            for k, v in self.header_patterns.items()
        }
        self._html_re: List[Pattern[str]] = [re.compile(p) for p in self.html_patterns]
        self._meta_re: List[Pattern[str]] = [re.compile(p) for p in self.meta_patterns]
        self._cookie_re: List[Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in self.cookie_patterns
        ]


# ── Signature database ────────────────────────────────────────────────────────

TECH_SIGNATURES: List[TechSignature] = [
    # ── Web servers ───────────────────────────────────────────────────────────
    TechSignature(
        name="nginx",
        category="server",
        header_patterns={
            "Server": r"nginx(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="Apache",
        category="server",
        header_patterns={
            "Server": r"Apache(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="Cloudflare",
        category="server",
        header_patterns={
            "Server": r"cloudflare",
            "CF-Ray": r".+",
        },
        cookie_patterns=[
            r"__cfduid=",
            r"__cf_bm=",
            r"cf_clearance=",
        ],
    ),
    TechSignature(
        name="IIS",
        category="server",
        header_patterns={
            "Server": r"Microsoft-IIS(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="Gunicorn",
        category="server",
        header_patterns={
            "Server": r"gunicorn(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="Caddy",
        category="server",
        header_patterns={
            "Server": r"Caddy(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="LiteSpeed",
        category="server",
        header_patterns={
            "Server": r"LiteSpeed(?:/[\w.]+)?",
        },
    ),
    TechSignature(
        name="Tomcat",
        category="server",
        header_patterns={
            "Server": r"Apache-Coyote(?:/[\w.]+)?",
        },
    ),

    # ── Languages / runtimes ──────────────────────────────────────────────────
    TechSignature(
        name="PHP",
        category="language",
        header_patterns={
            "X-Powered-By": r"PHP(?:/[\w.]+)?",
        },
        cookie_patterns=[
            r"PHPSESSID=",
        ],
    ),
    TechSignature(
        name="ASP.NET",
        category="language",
        header_patterns={
            "X-Powered-By": r"ASP\.NET",
            "X-AspNet-Version": r".+",
            "X-AspNetMvc-Version": r".+",
        },
        cookie_patterns=[
            r"ASP\.NET_SessionId=",
        ],
    ),
    TechSignature(
        name="Java",
        category="language",
        header_patterns={
            "X-Powered-By": r"(?:Servlet|JSP|JBoss|Tomcat|TomEE)",
        },
        cookie_patterns=[
            r"JSESSIONID=",
        ],
    ),
    TechSignature(
        name="Python",
        category="language",
        # Werkzeug / gunicorn already covered by the server channel; this
        # signature catches plain Python frameworks (Flask/Django/FastAPI
        # when the server banner is hidden).
        cookie_patterns=[
            r"(?:^|;\s*)sessionid=",
        ],
    ),
    TechSignature(
        name="Ruby",
        category="language",
        cookie_patterns=[
            r"(?:^|;\s*)_session(?:_id)?=",
        ],
    ),
    TechSignature(
        name="Node.js",
        category="language",
        header_patterns={
            "X-Powered-By": r"Express",
        },
    ),
    TechSignature(
        name="Go",
        category="language",
        # Go stdlib net/http doesn't set a default Server banner; many Go
        # frameworks (Caddy, Traefik) already covered. Catch a few tell-
        # tales: gin/echo/go-chi custom Server headers.
        header_patterns={
            "Server": r"(?:^|\s)(?:go-http-server|echo|gin|traefik)(?:/[\w.\-]+)?",
        },
    ),

    # ── JS frameworks (HTML-only detection) ───────────────────────────────────
    TechSignature(
        name="Next.js",
        category="framework",
        html_patterns=[
            r"_next/static",
            r"__NEXT_DATA__",
            r"/_next/",
        ],
    ),
    TechSignature(
        name="React",
        category="framework",
        html_patterns=[
            r"data-reactroot",
            r"data-reactid",
            r"react\.production\.min\.js",
            r"react-dom",
        ],
    ),
    TechSignature(
        name="Vue.js",
        category="framework",
        html_patterns=[
            r"data-v-[a-f0-9]+",
            r"__vue__",
            r"v-cloak",
        ],
    ),
    TechSignature(
        name="Angular",
        category="framework",
        html_patterns=[
            r"\bng-app\b",
            r"\bng-version=\"[^\"]+\"",
            r"\bng-controller=\"[^\"]+\"",
            r"angular\.min\.js",
        ],
    ),
    TechSignature(
        name="Nuxt.js",
        category="framework",
        html_patterns=[
            r"__nuxt",
            r"/_nuxt/",
            r"window\.__NUXT__",
        ],
    ),
    TechSignature(
        name="jQuery",
        category="framework",
        html_patterns=[
            r"jquery(?:-\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js",
        ],
    ),
    TechSignature(
        name="Svelte",
        category="framework",
        html_patterns=[
            r"sveltekit",
            r"data-svelte",
        ],
    ),

    # ── CMS ───────────────────────────────────────────────────────────────────
    TechSignature(
        name="WordPress",
        category="cms",
        html_patterns=[
            r"wp-content/",
            r"wp-includes/",
            r"wp-json/",
        ],
        meta_patterns=[
            r"WordPress\s*[\d.]*",
        ],
    ),
    TechSignature(
        name="Drupal",
        category="cms",
        html_patterns=[
            r"Drupal\.settings",
            r"/sites/default/files",
            r"/sites/all/",
        ],
        meta_patterns=[
            r"Drupal\s*[\d.]*",
        ],
    ),
    TechSignature(
        name="Joomla",
        category="cms",
        html_patterns=[
            r"/media/jui/",
            r"Joomla!",
        ],
        meta_patterns=[
            r"Joomla!?\s*[\d.]*",
        ],
    ),
    TechSignature(
        name="Shopify",
        category="cms",
        html_patterns=[
            r"cdn\.shopify\.com",
            r"Shopify\.theme",
        ],
        header_patterns={
            "X-Shopify-Stage": r".+",
            "X-Shopid": r".+",
        },
    ),
    TechSignature(
        name="Magento",
        category="cms",
        html_patterns=[
            r"/skin/frontend/",
            r"Magento_",
            r"Mage\.cookies",
        ],
    ),
    TechSignature(
        name="Ghost",
        category="cms",
        meta_patterns=[
            r"Ghost\s*[\d.]*",
        ],
        html_patterns=[
            r"/ghost/api/",
        ],
    ),
    TechSignature(
        name="Hugo",
        category="cms",
        meta_patterns=[
            r"Hugo\s*[\d.]*",
        ],
    ),

    # ── Analytics / 3rd-party widgets ──────────────────────────────────────────
    TechSignature(
        name="Google Analytics",
        category="analytics",
        html_patterns=[
            r"google-analytics\.com/(?:analytics|ga|gtag)\.js",
            r"gtag\(\s*['\"]config['\"]",
            r"UA-\d{4,10}-\d{1,4}",
            r"G-[A-Z0-9]{4,12}",  # GA4 measurement id
        ],
    ),
    TechSignature(
        name="Google Tag Manager",
        category="analytics",
        html_patterns=[
            r"googletagmanager\.com/gtm\.js",
            r"GTM-[A-Z0-9]+",
        ],
    ),
    TechSignature(
        name="Segment",
        category="analytics",
        html_patterns=[
            r"cdn\.segment\.com/analytics\.js",
            r"analytics\.js\?v=[\d.]+",
        ],
    ),
    TechSignature(
        name="Hotjar",
        category="analytics",
        html_patterns=[
            r"static\.hotjar\.com",
            r"hjid=\d+",
        ],
    ),

    # ── Reverse proxies / CDNs ────────────────────────────────────────────────
    TechSignature(
        name="Varnish",
        category="proxy",
        header_patterns={
            "X-Varnish": r".+",
            "Via": r"varnish",
        },
    ),
    TechSignature(
        name="HAProxy",
        category="proxy",
        header_patterns={
            "Server": r"HAProxy",
        },
    ),
    TechSignature(
        name="Squid",
        category="proxy",
        header_patterns={
            "Server": r"squid(?:/[\w.]+)?",
            "Via": r"squid",
        },
    ),
]


# ── Cookie extraction ────────────────────────────────────────────────────────

def _extract_cookie_strings(headers: Optional[Dict[str, str]]) -> List[str]:
    """Pull every Set-Cookie value out of ``headers``.

    Most HTTP libraries collapse multi-valued ``Set-Cookie`` headers
    using one of three conventions:
      * a single string with multiple ``Set-Cookie`` lines joined by ``,``;
      * a list value (rare in plain dicts);
      * the first cookie only, with the rest in subsequent ``Set-Cookie``
        keys (e.g. ``requests``-style ``CaseInsensitiveDict``).

    We handle (1) and (3) by splitting on the ``Set-Cookie:`` marker
    and also on standalone ``,`` boundaries when the value doesn't
    contain ``Expires=`` (which is a common false-positive boundary).
    The ``Cookie`` header (outbound) is also included so callers can pass
    a single ``headers`` dict and still get cookie-name coverage.
    """
    if not headers:
        return []
    out: List[str] = []
    for raw_key, value in headers.items():
        if value is None:
            continue
        if not isinstance(value, str):
            value = str(value)
        key = raw_key.lower()
        if key in ("set-cookie", "cookie"):
            # Split on "Set-Cookie:" prefix (multi-cookie join) AND on
            # common separators. ``Set-Cookie`` may also appear repeated
            # as multiple dict keys, so the caller may have already split
            # them — that's fine, we just append each value.
            parts = re.split(r"(?i)set-cookie\s*:\s*", value)
            for part in parts:
                part = part.strip()
                if part:
                    out.append(part)
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def detect_tech(
    headers: Optional[Dict[str, str]],
    html: Optional[str] = "",
) -> List[TechMatch]:
    """Detect web technologies from response headers and HTML body.

    Args:
        headers: Response headers as a ``dict`` (or any ``Mapping``-like).
                 Header *names* are matched case-insensitively. ``None``
                 and empty dicts both yield an empty match list.
        html:    Raw HTML body (str). May be empty or ``None``.

    Returns:
        List of ``TechMatch`` records, one per detected technology.
        Order is the same as the order in ``TECH_SIGNATURES`` (stable
        and predictable). The same technology is never returned twice
        even if multiple channels fire.
    """
    # Tolerant input handling.
    if not headers and not html:
        return []
    headers_dict: Dict[str, str] = {}
    if headers:
        for k, v in headers.items():
            if v is None:
                continue
            headers_dict[str(k)] = v if isinstance(v, str) else str(v)
    html_str = html if isinstance(html, str) else ""

    cookies = _extract_cookie_strings(headers_dict)

    matches: List[TechMatch] = []
    for sig in TECH_SIGNATURES:
        fired = _try_match(sig, headers_dict, html_str, cookies)
        if fired is not None:
            matches.append(fired)
    return matches


def classify_stack(matches: List[TechMatch]) -> Dict[str, List[str]]:
    """Group ``TechMatch`` records by their ``category``.

    Args:
        matches: Output of ``detect_tech``. ``None`` or empty input
                 yields an empty dict.

    Returns:
        Dict ``{category: [name, ...]}``. Categories are returned in
        the order they first appear in the input list. The names
        within each category preserve the input order.
    """
    out: Dict[str, List[str]] = {}
    if not matches:
        return out
    for m in matches:
        if not isinstance(m, TechMatch):
            continue
        out.setdefault(m.category, []).append(m.name)
    return out


# ── Internal helpers ──────────────────────────────────────────────────────────

def _try_match(
    sig: TechSignature,
    headers: Dict[str, str],
    html: str,
    cookies: List[str],
) -> Optional[TechMatch]:
    """Try each channel of ``sig`` in priority order; return the first hit.

    Channel priority: headers > html > meta > cookies. Once a channel
    fires, lower-priority channels are not consulted (this is the source
    of the "one tech → one match" guarantee).
    """
    # 1) Headers
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for hname, pattern in sig._header_re.items():
        value = lower_headers.get(hname)
        if value is None:
            continue
        if pattern.search(value):
            evidence = f"header:{hname}={value[:200]}"
            return TechMatch(name=sig.name, category=sig.category, evidence=evidence)

    # 2) HTML body
    for pattern in sig._html_re:
        if pattern.search(html):
            evidence = f"html:{pattern.pattern[:80]}"
            return TechMatch(name=sig.name, category=sig.category, evidence=evidence)

    # 3) <meta> tags — pull generator-style meta out of the HTML once.
    if sig._meta_re:
        for meta_content in _extract_meta_generator(html):
            for pattern in sig._meta_re:
                if pattern.search(meta_content):
                    evidence = f"meta:{meta_content[:200]}"
                    return TechMatch(
                        name=sig.name, category=sig.category, evidence=evidence
                    )

    # 4) Cookies
    for cookie_value in cookies:
        for pattern in sig._cookie_re:
            if pattern.search(cookie_value):
                evidence = f"cookie:{cookie_value[:200]}"
                return TechMatch(
                    name=sig.name, category=sig.category, evidence=evidence
                )

    return None


_META_TAG_RE = re.compile(
    r'<meta\s+[^>]*?name\s*=\s*["\']?generator["\']?[^>]*?content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# Fallback: content may come before name (HTML allows flexible attribute order).
_META_TAG_RE_REV = re.compile(
    r'<meta\s+[^>]*?content\s*=\s*["\']([^"\']+)["\'][^>]*?name\s*=\s*["\']?generator["\']?',
    re.IGNORECASE,
)


def _extract_meta_generator(html: str) -> List[str]:
    """Return the ``content`` attribute of every ``<meta name="generator">``.

    Tolerant: handles either attribute order (``name`` before ``content``
    or vice-versa), single or double quotes, and missing tags.
    """
    if not html:
        return []
    out: List[str] = []
    for m in _META_TAG_RE.finditer(html):
        out.append(m.group(1))
    for m in _META_TAG_RE_REV.finditer(html):
        out.append(m.group(1))
    return out


__all__ = [
    "TechMatch",
    "TechSignature",
    "TECH_SIGNATURES",
    "detect_tech",
    "classify_stack",
]
