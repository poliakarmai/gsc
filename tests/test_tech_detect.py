"""tests/test_tech_detect.py — Tech-stack detection (Wappalyzer-lite).

Recon-front coverage: server banners, language runtimes, JS framework
markers in HTML, CMS generators, cookies, and the classify_stack()
grouping helper.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_recon.tech_detect import (
    TECH_SIGNATURES,
    TechMatch,
    classify_stack,
    detect_tech,
)


# ── detect_tech: header-driven ────────────────────────────────────────────────

def test_detect_nginx_and_php_from_headers():
    """Server + X-Powered-By → nginx (server) and PHP (language)."""
    matches = detect_tech(
        {"Server": "nginx/1.25.1", "X-Powered-By": "PHP/8.1"},
        "",
    )
    by_name = {m.name: m for m in matches}
    assert "nginx" in by_name
    assert "PHP" in by_name
    assert by_name["nginx"].category == "server"
    assert by_name["PHP"].category == "language"


def test_detect_cloudflare_via_server_and_cf_ray():
    """Cloudflare is identifiable by either Server or CF-Ray header."""
    matches = detect_tech(
        {"Server": "cloudflare", "CF-Ray": "abcdef12345-SJC"},
        "",
    )
    by_name = {m.name: m for m in matches}
    assert "Cloudflare" in by_name
    assert by_name["Cloudflare"].category == "server"


# ── detect_tech: HTML-driven (JS frameworks) ──────────────────────────────────

def test_detect_wordpress_from_html_and_meta():
    """WordPress fires on either wp-content/ HTML markers or the meta generator."""
    matches = detect_tech(
        {},
        '<html><head><meta name="generator" content="WordPress 6.4.2"></head>'
        '<body><script src="/wp-content/themes/foo.js"></script></body></html>',
    )
    by_name = {m.name: m for m in matches}
    assert "WordPress" in by_name
    assert by_name["WordPress"].category == "cms"


def test_detect_react_from_html():
    """data-reactroot attribute is a strong React marker."""
    matches = detect_tech({}, '<div data-reactroot="" class="app">hi</div>')
    by_name = {m.name: m for m in matches}
    assert "React" in by_name
    assert by_name["React"].category == "framework"


def test_detect_angular_from_html():
    """ng-app is a definitive Angular 1.x marker."""
    matches = detect_tech({}, '<div ng-app="myApp" ng-controller="MainCtrl"></div>')
    by_name = {m.name: m for m in matches}
    assert "Angular" in by_name


def test_detect_vue_from_data_v():
    """data-v-* scoped style attribute is a Vue.js marker."""
    matches = detect_tech({}, '<style scoped>.x[data-v-abc12345] {}</style>')
    by_name = {m.name: m for m in matches}
    assert "Vue.js" in by_name


# ── detect_tech: cookies ──────────────────────────────────────────────────────

def test_detect_php_from_set_cookie():
    """PHPSESSID in Set-Cookie identifies PHP even without X-Powered-By."""
    matches = detect_tech({"Set-Cookie": "PHPSESSID=abc123def; path=/"}, "")
    by_name = {m.name: m for m in matches}
    assert "PHP" in by_name
    assert "cookie:" in by_name["PHP"].evidence


# ── detect_tech: tolerance ────────────────────────────────────────────────────

def test_detect_empty_inputs_returns_empty_list():
    """Empty headers + empty html → empty match list, no exceptions."""
    assert detect_tech({}, "") == []
    assert detect_tech(None, None) == []
    assert detect_tech(None, "") == []
    assert detect_tech({}, None) == []


# ── detect_tech: case-insensitivity ──────────────────────────────────────────

def test_detect_case_insensitive_header_keys():
    """Lowercase 'server' header must still match the 'Server' signature."""
    matches = detect_tech({"server": "nginx"}, "")
    by_name = {m.name: m for m in matches}
    assert "nginx" in by_name


# ── detect_tech: dedup across multiple channels ───────────────────────────────

def test_no_duplicate_tech_when_multiple_channels_fire():
    """PHP fires on both X-Powered-By and PHPSESSID cookie — only one match."""
    matches = detect_tech(
        {"X-Powered-By": "PHP/8.2", "Set-Cookie": "PHPSESSID=abc; path=/"},
        "",
    )
    php_hits = [m for m in matches if m.name == "PHP"]
    assert len(php_hits) == 1
    # And the surviving evidence should be the header channel (priority
    # over cookie), not the cookie channel.
    assert "header:" in php_hits[0].evidence


# ── classify_stack ────────────────────────────────────────────────────────────

def test_classify_stack_groups_by_category():
    """classify_stack returns category → [names] grouping, order-preserving."""
    matches = [
        TechMatch(name="nginx", category="server", evidence="h"),
        TechMatch(name="PHP", category="language", evidence="h"),
        TechMatch(name="React", category="framework", evidence="h"),
        TechMatch(name="Apache", category="server", evidence="h"),
        TechMatch(name="WordPress", category="cms", evidence="h"),
    ]
    grouped = classify_stack(matches)
    assert grouped == {
        "server": ["nginx", "Apache"],
        "language": ["PHP"],
        "framework": ["React"],
        "cms": ["WordPress"],
    }


def test_classify_stack_empty_and_none():
    """classify_stack is tolerant: None / [] → {}."""
    assert classify_stack([]) == {}
    assert classify_stack(None) == {}


# ── TechMatch.to_dict ────────────────────────────────────────────────────────

def test_tech_match_to_dict_shape():
    """to_dict returns a plain dict with the three documented keys."""
    m = TechMatch(name="nginx", category="server", evidence="header:server=nginx/1.25")
    d = m.to_dict()
    assert isinstance(d, dict)
    assert set(d.keys()) == {"name", "category", "evidence"}
    assert d["name"] == "nginx"
    assert d["category"] == "server"
    assert d["evidence"] == "header:server=nginx/1.25"


# ── Signature database size ───────────────────────────────────────────────────

def test_tech_signatures_database_size():
    """The built-in signature database must cover at least 25 technologies."""
    assert len(TECH_SIGNATURES) >= 25


# ── Bonus coverage: Next.js, IIS, ASP.NET, JSESSIONID ────────────────────────

def test_detect_nextjs_html_marker():
    """_next/static in HTML identifies Next.js."""
    matches = detect_tech({}, '<script src="/_next/static/chunks/main.js"></script>')
    by_name = {m.name: m for m in matches}
    assert "Next.js" in by_name


def test_detect_iis_and_aspnet_combined():
    """Microsoft-IIS Server banner + ASP.NET_SessionId cookie → IIS + ASP.NET."""
    matches = detect_tech(
        {
            "Server": "Microsoft-IIS/10.0",
            "X-Powered-By": "ASP.NET",
            "Set-Cookie": "ASP.NET_SessionId=xyz; path=/; HttpOnly",
        },
        "",
    )
    by_name = {m.name: m for m in matches}
    assert "IIS" in by_name
    assert "ASP.NET" in by_name


def test_detect_java_via_jsessionid():
    """JSESSIONID cookie identifies a Java stack."""
    matches = detect_tech({"Set-Cookie": "JSESSIONID=ABCDEF; Path=/"}, "")
    by_name = {m.name: m for m in matches}
    assert "Java" in by_name


def test_case_insensitive_header_value():
    """Banner casing must not matter: Server: NGINX/1.25 → nginx."""
    matches = detect_tech({"Server": "NGINX/1.25"}, "")
    names = {m.name for m in matches}
    assert "nginx" in names


def test_case_insensitive_cookie_name():
    """Cookie matching is case-insensitive: phpsessid still → PHP."""
    matches = detect_tech({"Set-Cookie": "PHPSESSID=abc; Path=/"}, "")
    names = {m.name for m in matches}
    assert "PHP" in names
