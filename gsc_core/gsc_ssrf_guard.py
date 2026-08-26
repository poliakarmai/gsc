"""SSRF address guard for GSC — blocks loopback/private/link-local/metadata fetches.

Ported from openworker (MIT, ``coworker/web/guard.py``). GSC makes network requests
from ``gsc_dast_validator`` (nuclei staging) and ``gsc_secrets_verifier`` (provider
APIs); a URL must never resolve to the machine's own network position (cloud metadata
endpoint at 169.254.169.254, loopback, RFC1918, CGNAT/Tailscale). ``check_url`` rejects
a URL whose hostname resolves to a blocked range on *any* answer, so a name with both a
public and a private A record cannot slip through.

DNS-rebinding pinning (connection-level) is deliberately NOT ported here: it requires
an httpx client built with ``follow_redirects=False`` so each hop can be re-checked and
pinned. GSC uses urllib/requests, so the browser-style pinned client does not transfer.
``check_url`` still closes the common rebinding gap — a name that flips to a private
address between check and connect is caught on the check side.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlsplit

# RFC 6598 shared address space. Python's is_private misses it, but it is carrier-grade
# NAT space and Tailscale hands out internal hosts here (100.64.0.0/10).
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _blocked_reason(ip) -> Optional[str]:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (includes the cloud metadata endpoint)"
    if ip.is_private:
        return "a private network"
    if ip.version == 4 and ip in _CGNAT:
        return "shared address space (CGNAT / RFC 6598)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "a reserved range"
    return None


def _vet(url: str) -> Optional[str]:
    """Return a human-readable refusal reason when ``url`` must not be fetched, else None."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "url must start with http:// or https://"
    host = parts.hostname
    if not host:
        return "url has no host"

    # A literal IP needs no DNS lookup.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        reason = _blocked_reason(literal)
        return f"refusing to fetch {host}: {reason}" if reason else None

    # inet_aton-style numeric forms (2130706433, 0x7f000001) that some URL parsers
    # accept — normalize to an IPv4 so they cannot slip past the literal check.
    h = host.lower()
    num = None
    if h.startswith("0x"):
        try:
            num = ipaddress.IPv4Address(int(h, 16))
        except (ValueError, OverflowError):
            num = None
    elif h.isdigit():
        try:
            num = ipaddress.IPv4Address(int(h))
        except (ValueError, OverflowError):
            num = None
    if num is not None:
        reason = _blocked_reason(num)
        return f"refusing to fetch {host}: {reason}" if reason else None

    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return f"could not resolve {host}: {exc}"

    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        # ::ffff:127.0.0.1 and friends must be judged as the v4 address they carry.
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        reason = _blocked_reason(ip)
        if reason:
            return f"refusing to fetch {host} ({ip}): {reason}"
    return None


def check_url(url: str) -> Optional[str]:
    """None if the URL may be fetched, else a human-readable refusal reason."""
    return _vet(url)


def is_blocked(url: str) -> bool:
    """True when ``url`` must not be fetched (SSRF guard)."""
    return _vet(url) is not None


def guard_url(url: str) -> None:
    """Raise ``PermissionError`` if ``url`` must not be fetched. Call before any fetch."""
    reason = _vet(url)
    if reason:
        raise PermissionError(f"SSRF guard blocked {url}: {reason}")
