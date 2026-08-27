#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""
GSC DNS Enumeration v1.0 (v0.32) — passive DNS record discovery (A/AAAA/CNAME/MX/TXT/NS).

Part of the new Recon front for GSC (bug bounty surface mapping). Python's
stdlib does not expose MX/TXT/NS/CNAME through ``socket.getaddrinfo``, and the
dependency budget forbids ``dnspython``/``scapy``. This module therefore ships
a minimal raw-DNS client (RFC 1035) on top of ``socket.udp``:

  * Build a wire-format DNS query (header + question) for any qtype.
  * Send it to a UDP resolver (default 8.8.8.8:53).
  * Parse the response with tolerance — pointer compression, truncated
    payloads, RCODE != 0, empty/malformed input all collapse to ``[]``.

The module is stdlib-only (socket, struct, random, dataclasses) and
tolerant by design: any network/parse failure returns an empty list —
mirroring the SubdomainClient.fetch contract from
``gsc_recon.subdomain_enum``. No zone transfers, no port scanning —
passive reconnaissance only (UDP/53 outbound).
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

DEFAULT_RESOLVER = "8.8.8.8"
DEFAULT_PORT = 53
DEFAULT_TIMEOUT = 5

# QTYPE numeric codes (RFC 1035 + RFC 3596).
_QTYPE_A = 1
_QTYPE_NS = 2
_QTYPE_CNAME = 5
_QTYPE_MX = 15
_QTYPE_TXT = 16
_QTYPE_AAAA = 28

_QTYPE_NAME_TO_INT = {
    "A": _QTYPE_A,
    "NS": _QTYPE_NS,
    "CNAME": _QTYPE_CNAME,
    "MX": _QTYPE_MX,
    "TXT": _QTYPE_TXT,
    "AAAA": _QTYPE_AAAA,
}

# Reverse map for the dataclass ``type`` field.
_QTYPE_INT_TO_NAME = {v: k for k, v in _QTYPE_NAME_TO_INT.items()}

# DNS header flag bits (RFC 1035 §4.1.1).
_FLAG_RD = 0x0100  # recursion desired

# Pointer-compression marker: top two bits set + zero (0xC0).
_NAME_POINTER_MASK = 0xC0
_NAME_POINTER_BITS = 0xC0

# Maximum number of pointer jumps during name decoding (loop guard against
# malformed packets that loop pointers at each other).
_MAX_NAME_HOPS = 16

# Maximum QNAME length per RFC 1035 (253 bytes total).
_MAX_QNAME_LENGTH = 255


# ── Data class ────────────────────────────────────────────
@dataclass
class DnsRecord:
    """A single DNS resource record decoded from a response packet.

    ``type`` is one of the six human-readable record types we support
    (A, AAAA, CNAME, MX, TXT, NS). ``data`` is the *rendered* form of
    RDATA — not raw wire bytes — so the caller never has to re-parse
    length-prefixed MX/TXT payloads:

      * A    -> dotted IPv4 string ("1.2.3.4")
      * AAAA -> canonical IPv6 string ("::1")
      * CNAME / NS -> target hostname (lower-cased, trailing dot stripped)
      * MX   -> "<priority> <exchange>" ("10 mail.example.com")
      * TXT  -> concatenation of all character-strings (no quoting)
    """
    name: str
    type: str
    ttl: int
    data: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "ttl": self.ttl,
            "data": self.data,
        }


# ── Pure helpers (no network) ─────────────────────────────
def _encode_name(name: str) -> bytes:
    """Encode a domain name into DNS QNAME wire format.

    Strips a single trailing dot (FQDN canonical form) and lower-cases
    the result, then emits RFC 1035 length-prefixed labels followed by
    a terminating zero byte. An empty input produces just ``b"\\x00"`` —
    a valid root label, which matches the behaviour of real resolvers
    when asked about the apex.

    Any individual label longer than 63 bytes (the per-label RFC 1035
    limit) is silently truncated to 63 bytes — we'd rather emit a
    query that produces a clean NXDOMAIN than raise on the way out.
    """
    cleaned = name.strip().rstrip(".").lower()
    if not cleaned:
        return b"\x00"
    out = bytearray()
    for label in cleaned.split("."):
        if not label:
            continue
        chunk = label.encode("ascii", errors="ignore")[:63]
        if not chunk:
            continue
        out.append(len(chunk))
        out.extend(chunk)
    out.append(0)
    return bytes(out)


def _decode_name(payload: bytes, offset: int) -> Tuple[str, int]:
    """Decode a domain name starting at ``offset`` inside ``payload``.

    Handles RFC 1035 message compression: if the high two bits of the
    length byte are ``0b11`` the remaining 14 bits are an offset into
    ``payload`` from which the actual label sequence is read. A pointer
    consumes 2 bytes; a literal label sequence consumes ``1 + sum(label
    lengths)`` bytes and is terminated by a zero byte.

    On any structural error (truncated payload, bad offset, looped
    pointers) returns ``("", offset)`` so the caller can degrade
    gracefully to an empty result list.

    Returns a ``(name, next_offset)`` tuple where ``name`` is the
    lower-cased dot-joined form without a trailing dot, and
    ``next_offset`` is the byte index in ``payload`` immediately after
    the name field (i.e. ready to read QTYPE/QCLASS or the next record).
    """
    if payload is None or not isinstance(payload, (bytes, bytearray)):
        return ("", offset)
    if not isinstance(offset, int) or offset < 0 or offset >= len(payload):
        return ("", offset)

    labels: List[str] = []
    visited: set = set()
    original_offset = offset
    jumped = False
    cur = offset

    for _ in range(_MAX_NAME_HOPS):
        if cur >= len(payload):
            return ("", offset)
        length = payload[cur]
        if length == 0:
            # End-of-name. If we never jumped, the next_offset is cur+1.
            cur += 1
            break
        if (length & _NAME_POINTER_MASK) == _NAME_POINTER_BITS:
            # Compression pointer: 2 bytes, second byte is the low 8 bits.
            if cur + 1 >= len(payload):
                return ("", offset)
            target = ((length & 0x3F) << 8) | payload[cur + 1]
            if target >= original_offset and not jumped:
                # Pointers may only point backwards; otherwise the name
                # is a forward reference which is illegal in DNS.
                return ("", offset)
            if target in visited:
                # Looped pointer chain — malformed packet.
                return ("", offset)
            visited.add(target)
            if not jumped:
                original_offset = cur + 2  # remember the post-pointer offset
                jumped = True
            cur = target
            continue
        # Regular label: read ``length`` bytes.
        if cur + 1 + length > len(payload):
            return ("", offset)
        try:
            labels.append(payload[cur + 1:cur + 1 + length].decode("ascii"))
        except UnicodeDecodeError:
            return ("", offset)
        cur += 1 + length
    else:
        # Hop limit exhausted.
        return ("", offset)

    name = ".".join(labels).lower()
    next_offset = original_offset if jumped else cur
    return (name, next_offset)


def build_query(domain: str, qtype: int, tid: int = 0) -> bytes:
    """Build a wire-format DNS query for ``domain`` of type ``qtype``.

    Layout (RFC 1035):

      * Header (12 bytes): ID, FLAGS (RD set, QR=0), QDCOUNT=1,
        ANCOUNT=0, NSCOUNT=0, ARCOUNT=0.
      * Question: QNAME (labels), QTYPE (16-bit), QCLASS=1 (IN).

    ``tid`` is the transaction ID. It is masked to 16 bits so callers
    that pass a Python ``int`` with extra bits do not corrupt the
    header. The default of 0 is deterministic; the live ``DnsClient``
    overwrites it with a random value to avoid response collisions.
    """
    if not isinstance(domain, str):
        domain = ""
    if not isinstance(qtype, int):
        raise TypeError("qtype must be an int")
    if qtype < 0 or qtype > 0xFFFF:
        raise ValueError("qtype out of range")

    qname = _encode_name(domain)
    if len(qname) > _MAX_QNAME_LENGTH:
        # Refuse to emit an over-long query — the resolver would just
        # return FORMERR anyway. Treat it as a client-side error.
        raise ValueError("domain name too long")

    tid16 = tid & 0xFFFF
    # Header: ID, FLAGS (RD), QDCOUNT=1, AN/NS/AR=0.
    header = struct.pack("!HHHHHH", tid16, _FLAG_RD, 1, 0, 0, 0)
    # Question: QNAME + QTYPE + QCLASS(IN=1).
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_rdata(payload: bytes, rdata_offset: int, rdlength: int,
                 rtype: int) -> Optional[str]:
    """Render a single RR's RDATA into the human-friendly form for DnsRecord.data.

    ``rtype`` is the numeric QTYPE of the record (A=1, NS=2, CNAME=5, MX=15,
    TXT=16, AAAA=28). Returns ``None`` on any structural error so the
    caller can drop the record instead of emitting a partial one.
    """
    end = rdata_offset + rdlength
    if rdata_offset < 0 or end > len(payload) or rdlength < 0:
        return None

    if rtype == _QTYPE_A:
        if rdlength != 4:
            return None
        return ".".join(str(b) for b in payload[rdata_offset:end])

    if rtype == _QTYPE_AAAA:
        if rdlength != 16:
            return None
        try:
            # socket.inet_ntop with AF_INET6 is the stdlib way to format
            # 16 raw bytes as a canonical IPv6 string.
            return socket.inet_ntop(socket.AF_INET6, bytes(payload[rdata_offset:end]))
        except (OSError, ValueError):
            return None

    if rtype in (_QTYPE_NS, _QTYPE_CNAME):
        name, _ = _decode_name(payload, rdata_offset)
        if not name:
            return None
        return name

    if rtype == _QTYPE_MX:
        # RDATA = 2-byte preference + exchange name.
        if rdlength < 3:
            return None
        try:
            (preference,) = struct.unpack("!H", payload[rdata_offset:rdata_offset + 2])
        except struct.error:
            return None
        exchange, _ = _decode_name(payload, rdata_offset + 2)
        if not exchange:
            return None
        return f"{preference} {exchange}"

    if rtype == _QTYPE_TXT:
        # RDATA = one or more length-prefixed character strings.
        out_parts: List[str] = []
        cur = rdata_offset
        stop = end
        while cur < stop:
            if cur >= len(payload):
                return None
            seg_len = payload[cur]
            cur += 1
            if cur + seg_len > stop:
                return None
            try:
                out_parts.append(
                    payload[cur:cur + seg_len].decode("utf-8", errors="replace")
                )
            except Exception:
                return None
            cur += seg_len
        if not out_parts:
            return None
        return "".join(out_parts)

    # Unknown qtype — render the raw bytes as a hex blob so the caller
    # can still see the record exists without us silently dropping it.
    try:
        return payload[rdata_offset:end].hex()
    except Exception:
        return None


def parse_dns_response(payload: bytes) -> List[DnsRecord]:
    """Parse a DNS response packet into a list of DnsRecord.

    Tolerant by design: ``None``, empty bytes, truncated headers, RCODE
    != 0, malformed name compression, over-short RDATA — all return
    ``[]`` rather than raising. Only the Answer section is consumed;
    Authority and Additional sections are intentionally ignored to keep
    the surface small and predictable (a stub resolver only cares
    about the answer it asked for).
    """
    if payload is None or not isinstance(payload, (bytes, bytearray)):
        return []
    if len(payload) < 12:
        return []

    try:
        (_tid, flags, qdcount, ancount, _nscount, _arcount) = struct.unpack(
            "!HHHHHH", payload[:12]
        )
    except struct.error:
        return []

    # RCODE = low 4 bits of flags. Bit 0 (QR) must be set — otherwise
    # this is a query, not a response. Anything else: drop.
    rcode = flags & 0x000F
    qr = (flags >> 15) & 0x01
    if qr != 1 or rcode != 0:
        return []

    # Skip the question section (one QNAME + QTYPE + QCLASS=4 bytes).
    offset = 12
    for _ in range(qdcount):
        if offset >= len(payload):
            return []
        # Decode the QNAME but we don't actually need the value; the
        # side-effect we want is the post-name offset.
        _name, offset = _decode_name(payload, offset)
        if offset < 0 or offset + 4 > len(payload):
            return []
        offset += 4  # QTYPE + QCLASS

    if ancount == 0 or offset >= len(payload):
        return []

    records: List[DnsRecord] = []
    for _ in range(ancount):
        if offset + 12 > len(payload):
            # Header of the next record is incomplete.
            break
        name, offset = _decode_name(payload, offset)
        if offset + 10 > len(payload):
            break
        try:
            rtype, _rclass, ttl, rdlength = struct.unpack(
                "!HHIH", payload[offset:offset + 10]
            )
        except struct.error:
            break
        offset += 10
        if offset + rdlength > len(payload):
            break
        rendered = _parse_rdata(payload, offset, rdlength, rtype)
        offset += rdlength
        if rendered is None:
            continue
        type_name = _QTYPE_INT_TO_NAME.get(rtype)
        if type_name is None:
            # Unknown qtype — skip rather than mis-labelling.
            continue
        records.append(DnsRecord(name=name, type=type_name, ttl=ttl, data=rendered))

    return records


# ── DNS client (network) ──────────────────────────────────
class DnsClient:
    """Minimal RFC 1035 UDP DNS client.

    Sends one query per ``query()`` call and parses the response with
    :func:`parse_dns_response`. The default resolver is Google
    ``8.8.8.8:53``; pass any reachable resolver to ``__init__`` if you
    need to pin a different one. **Tolerant**: every network error
    (timeout, unreachable resolver, malformed response) collapses to
    ``[]`` — the caller never has to wrap this in try/except.
    """

    def __init__(
        self,
        resolver: str = DEFAULT_RESOLVER,
        port: int = DEFAULT_PORT,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.resolver = resolver
        self.port = int(port)
        self.timeout = int(timeout)

    def query(self, domain: str, qtype: str) -> List[DnsRecord]:
        """Send a single DNS query and return the answer records.

        ``qtype`` is the human-readable name (``"A"``, ``"AAAA"``,
        ``"CNAME"``, ``"MX"``, ``"TXT"``, ``"NS"``). Unknown qtype
        strings return ``[]`` rather than raising — the wrappers
        below already filter by name, so an unexpected value here is
        a programming error we want to surface as "no results" rather
        than a stack trace.
        """
        if not isinstance(domain, str) or not domain.strip():
            return []
        qtype_int = _QTYPE_NAME_TO_INT.get(qtype)
        if qtype_int is None:
            return []

        # Random 16-bit transaction ID so concurrent callers (or
        # pipelined resolvers) can disambiguate interleaved responses.
        tid = random.randint(0, 0xFFFF)
        try:
            wire = build_query(domain.strip().rstrip("."), qtype_int, tid=tid)
        except (ValueError, TypeError):
            return []

        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(wire, (self.resolver, self.port))
            data, _addr = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return []
        except Exception:
            return []
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        return parse_dns_response(data)


# ── Wrappers (use the client, tolerant) ────────────────────
def _default_client(client: Optional[DnsClient]) -> DnsClient:
    """Return ``client`` if provided, else build a one-shot default client."""
    return client if isinstance(client, DnsClient) else DnsClient()


def resolve_a(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return all IPv4 addresses for ``domain`` (may be empty)."""
    if not isinstance(domain, str) or not domain.strip():
        return []
    return [
        r.data for r in _default_client(client).query(domain, "A") if r.type == "A"
    ]


def resolve_aaaa(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return all IPv6 addresses for ``domain`` (may be empty)."""
    if not isinstance(domain, str) or not domain.strip():
        return []
    return [
        r.data for r in _default_client(client).query(domain, "AAAA") if r.type == "AAAA"
    ]


def resolve_cname(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return CNAME target host(s) for ``domain`` (may be empty)."""
    if not isinstance(domain, str) or not domain.strip():
        return []
    return [
        r.data for r in _default_client(client).query(domain, "CNAME") if r.type == "CNAME"
    ]


def resolve_mx(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return MX exchanges for ``domain``, sorted by ascending priority.

    Each entry is rendered as ``"<priority> <exchange>"`` (same shape
    as :class:`DnsRecord.data` for MX). Lowest priority value wins
    (per RFC 5321), so the first element of the returned list is the
    primary mail exchanger.
    """
    if not isinstance(domain, str) or not domain.strip():
        return []

    records = [r for r in _default_client(client).query(domain, "MX") if r.type == "MX"]
    # data is "<priority> <exchange>" — sort numerically on the priority
    # field so e.g. "5 host" beats "10 host" instead of "10 host"
    # beating "5 host" lexicographically.
    def _priority(rec: DnsRecord) -> int:
        try:
            return int(rec.data.split(" ", 1)[0])
        except (ValueError, AttributeError):
            return 1 << 30

    records.sort(key=_priority)
    return [r.data for r in records]


def resolve_txt(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return TXT record strings for ``domain`` (may be empty)."""
    if not isinstance(domain, str) or not domain.strip():
        return []
    return [
        r.data for r in _default_client(client).query(domain, "TXT") if r.type == "TXT"
    ]


def resolve_ns(domain: str, client: Optional[DnsClient] = None) -> List[str]:
    """Return NS (delegation) hostnames for ``domain`` (may be empty)."""
    if not isinstance(domain, str) or not domain.strip():
        return []
    return [
        r.data for r in _default_client(client).query(domain, "NS") if r.type == "NS"
    ]
