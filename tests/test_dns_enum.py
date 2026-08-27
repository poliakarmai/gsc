#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков

"""
Tests for ``gsc_recon.dns_enum`` — pure parsing only.

No network. ``build_query`` and ``parse_dns_response`` are the main
targets: we hand-craft wire-format DNS packets in memory and assert
that the parser extracts the right records. We also exercise
``_encode_name`` and ``_decode_name`` directly. The live ``DnsClient``
and the ``resolve_*`` wrappers are intentionally NOT exercised here —
they would need a stub UDP listener, which is overkill for the
contract these tests are meant to lock down.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

# Ensure the repo root is importable when pytest is run from any cwd.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from gsc_recon.dns_enum import (  # noqa: E402
    DnsRecord,
    build_query,
    _decode_name,
    _encode_name,
    parse_dns_response,
)


# ── Helpers: hand-craft wire-format DNS packets ───────────
def _make_header(
    tid: int = 0x1234,
    qr: int = 1,
    rcode: int = 0,
    qdcount: int = 0,
    ancount: int = 0,
    nscount: int = 0,
    arcount: int = 0,
    rd: int = 1,
) -> bytes:
    """Build a 12-byte DNS header. Default is a 0-record response with QR=1."""
    flags = (qr << 15) | (rd << 8) | rcode
    return struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)


def _make_question(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    """Build a question section: QNAME + QTYPE + QCLASS."""
    return _encode_name(name) + struct.pack("!HH", qtype, qclass)


def _make_answer_a(name: str, ip: str, ttl: int = 60, compress: bool = True) -> bytes:
    """Build a single A-record RR (NAME may be a pointer back to offset 12)."""
    try:
        name_field = (
            struct.pack("!H", 0xC00C) if compress else _encode_name(name)
        )
    except Exception:
        name_field = _encode_name(name)
    octets = bytes(int(p) for p in ip.split("."))
    rdata = octets
    return name_field + struct.pack("!HHIH", 1, 1, ttl, len(rdata)) + rdata


def _make_answer_aaaa(name: str, ip6: str, ttl: int = 60, compress: bool = True) -> bytes:
    """Build a single AAAA-record RR."""
    import socket as _s
    name_field = (
        struct.pack("!H", 0xC00C) if compress else _encode_name(name)
    )
    rdata = _s.inet_pton(_s.AF_INET6, ip6)
    return name_field + struct.pack("!HHIH", 28, 1, ttl, len(rdata)) + rdata


def _make_answer_cname(name: str, target: str, ttl: int = 60, compress_name: bool = True) -> bytes:
    """Build a single CNAME-record RR. RDATA itself uses labels (no pointer)."""
    name_field = (
        struct.pack("!H", 0xC00C) if compress_name else _encode_name(name)
    )
    rdata = _encode_name(target)
    return name_field + struct.pack("!HHIH", 5, 1, ttl, len(rdata)) + rdata


def _make_answer_mx(name: str, preference: int, exchange: str, ttl: int = 60, compress_name: bool = True) -> bytes:
    """Build a single MX-record RR: 2-byte preference + exchange name."""
    name_field = (
        struct.pack("!H", 0xC00C) if compress_name else _encode_name(name)
    )
    rdata = struct.pack("!H", preference) + _encode_name(exchange)
    return name_field + struct.pack("!HHIH", 15, 1, ttl, len(rdata)) + rdata


def _make_answer_txt(name: str, strings, ttl: int = 60, compress_name: bool = True) -> bytes:
    """Build a single TXT-record RR from a list of character strings."""
    name_field = (
        struct.pack("!H", 0xC00C) if compress_name else _encode_name(name)
    )
    body = b""
    for s in strings:
        b = s.encode("utf-8")
        body += bytes([len(b)]) + b
    return name_field + struct.pack("!HHIH", 16, 1, ttl, len(body)) + body


def _make_answer_ns(name: str, target: str, ttl: int = 60, compress_name: bool = True) -> bytes:
    """Build a single NS-record RR. TYPE=2, CLASS=1."""
    name_field = (
        struct.pack("!H", 0xC00C) if compress_name else _encode_name(name)
    )
    rdata = _encode_name(target)
    return name_field + struct.pack("!HHIH", 2, 1, ttl, len(rdata)) + rdata


# ── build_query ───────────────────────────────────────────
def test_build_query_sets_tid_in_first_two_bytes():
    """First 2 bytes of the query are the transaction ID (big-endian)."""
    q = build_query("example.com", 1, tid=0x1234)
    assert q[:2] == b"\x12\x34"


def test_build_query_qdcount_is_one():
    """QDCOUNT lives at bytes 4–5 (after ID + FLAGS) and must be 1."""
    q = build_query("example.com", 1, tid=0x1234)
    qdcount = struct.unpack("!H", q[4:6])[0]
    assert qdcount == 1


def test_build_query_qname_ends_with_zero_byte():
    """QNAME is length-prefixed labels terminated by a zero byte."""
    q = build_query("example.com", 1, tid=0x1234)
    # QNAME starts at offset 12 (after the 12-byte header). Find the
    # terminating 0x00 (the QTYPE/QCLASS bytes follow it).
    zero_idx = q.index(b"\x00", 12)
    qname = q[12:zero_idx + 1]
    # qname[0:1] = length of first label, qname[1:1+len] = "example", etc.
    assert qname[0:1] == b"\x07"
    assert qname[1:8] == b"example"
    assert qname[8:9] == b"\x03"
    assert qname[9:12] == b"com"
    assert qname[12:13] == b"\x00"


def test_build_query_qtype_and_qclass():
    """QTYPE at the right offset, QCLASS=1 (IN)."""
    q = build_query("example.com", 1, tid=0x1234)
    # Find where QNAME ends (the terminating 0x00).
    zero_idx = q.index(b"\x00", 12)
    qtype_off = zero_idx + 1
    qtype, qclass = struct.unpack("!HH", q[qtype_off:qtype_off + 4])
    assert qtype == 1
    assert qclass == 1


def test_build_query_default_tid_is_zero():
    """With tid=0, the first two bytes of the packet are 0x00 0x00."""
    q = build_query("example.com", 1)
    assert q[:2] == b"\x00\x00"


def test_build_query_length_is_reasonable():
    """12-byte header + (label lengths + dots + 0x00) + 4 bytes QTYPE/QCLASS."""
    q = build_query("example.com", 1, tid=0x1234)
    # 7 + 1 + 3 + 1 + 1 (QNAME+0x00) = 13, +4 (QTYPE+QCLASS) = 17, +12 header = 29.
    assert len(q) == 29


# ── _encode_name ──────────────────────────────────────────
def test_encode_name_simple():
    """RFC 1035 QNAME for 'example.com' = 7example3com0."""
    assert _encode_name("example.com") == b"\x07example\x03com\x00"


def test_encode_name_strips_trailing_dot():
    """FQDN with trailing dot is canonicalised before encoding."""
    assert _encode_name("example.com.") == _encode_name("example.com")


def test_encode_name_lowercases_input():
    """DNS is case-insensitive; encoder lower-cases before emitting labels."""
    assert _encode_name("Example.COM") == b"\x07example\x03com\x00"


def test_encode_name_root():
    """Empty / '.' input produces just the root terminator byte."""
    assert _encode_name("") == b"\x00"
    assert _encode_name(".") == b"\x00"


# ── _decode_name ──────────────────────────────────────────
def test_decode_name_simple_label_sequence():
    """Plain label sequence (no compression) decodes to dot-joined form."""
    payload = _encode_name("example.com")  # \x07example\x03com\x00
    name, new_offset = _decode_name(payload, 0)
    assert name == "example.com"
    # The next byte sits immediately after the terminating zero.
    assert new_offset == len(payload)


def test_decode_name_pointer_jump():
    """Pointer (0xC0 <offset>) decodes a name that lives earlier in the packet."""
    # Layout:
    #   offset 0..12:  \x07example\x03com\x00  (the name we want to point at)
    #   offset 13..14: \xC0\x00                (pointer -> offset 0)
    # The pointer at offset 13 jumps to offset 0 -> "example.com".
    name_section = _encode_name("example.com")  # 13 bytes, offsets 0..12
    payload = name_section + struct.pack("!H", 0xC000)
    name, new_offset = _decode_name(payload, 13)
    assert name == "example.com"
    # The pointer consumed 2 bytes (offsets 13..14), so the next field
    # is at offset 15.
    assert new_offset == 15


def test_decode_name_pointer_within_labels():
    """Pointer in the middle of a label sequence resolves correctly."""
    # Layout (backward pointer — the only legal direction per RFC 1035):
    #   offset 0..12:  \x07example\x03com\x00   (label sequence "example.com")
    #   offset 13..16: \x03foo                  (literal label "foo")
    #   offset 17..18: \xC0\x00                 (pointer -> offset 0, backwards)
    # Decoding the name at offset 13 reads "foo", then follows the pointer
    # back to "example.com" and concatenates the two label sequences.
    prefix = _encode_name("example.com")  # 13 bytes, offsets 0..12
    payload = prefix + b"\x03foo" + struct.pack("!H", 0xC000)
    name, new_offset = _decode_name(payload, 13)
    assert name == "foo.example.com"
    # The pointer consumed bytes 17..18, so the next field is at offset 19.
    assert new_offset == 19


def test_decode_name_truncated_payload():
    """Truncated payload returns empty name without raising."""
    payload = b"\x07exa"  # claims label of length 7, but only 3 bytes follow
    name, new_offset = _decode_name(payload, 0)
    assert name == ""
    assert new_offset == 0


def test_decode_name_none_input():
    """None / wrong type returns empty name without raising."""
    name, new_offset = _decode_name(None, 0)  # type: ignore[arg-type]
    assert name == ""
    assert new_offset == 0


# ── parse_dns_response: A ────────────────────────────────
def test_parse_a_record():
    """A single A-record 1.2.3.4 -> DnsRecord(type='A', data='1.2.3.4')."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=1)
    answer = _make_answer_a("example.com", "1.2.3.4", ttl=300)
    pkt = header + question + answer
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    r = recs[0]
    assert r.name == "example.com"
    assert r.type == "A"
    assert r.data == "1.2.3.4"
    assert r.ttl == 300


def test_parse_a_record_without_name_compression():
    """A-record whose NAME is emitted uncompressed (no pointer) is still parsed."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=1)
    # Same A-record but name is a full label sequence, not a pointer.
    name_field = _encode_name("example.com")
    rdata = bytes(int(p) for p in "5.6.7.8".split("."))
    rr = name_field + struct.pack("!HHIH", 1, 1, 120, len(rdata)) + rdata
    pkt = header + question + rr
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].name == "example.com"
    assert recs[0].data == "5.6.7.8"
    assert recs[0].ttl == 120


# ── parse_dns_response: AAAA ─────────────────────────────
def test_parse_aaaa_record():
    """AAAA-record '2001:db8::1' -> canonical IPv6 string."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=28)
    answer = _make_answer_aaaa("example.com", "2001:db8::1", ttl=120)
    pkt = header + question + answer
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].type == "AAAA"
    # Canonical IPv6 form is lower-cased; leading zeros are not preserved.
    assert recs[0].data == "2001:db8::1"


# ── parse_dns_response: MX ───────────────────────────────
def test_parse_mx_record():
    """MX priority=10, exchange=mail.example.com -> '10 mail.example.com'."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=15)
    answer = _make_answer_mx("example.com", 10, "mail.example.com", ttl=60)
    pkt = header + question + answer
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].type == "MX"
    assert recs[0].data == "10 mail.example.com"


# ── parse_dns_response: CNAME ────────────────────────────
def test_parse_cname_record_with_pointer_in_rdata():
    """CNAME RDATA that uses a pointer to the QNAME is decoded as the FQDN."""
    # Layout:
    #   header (12)
    #   question: _encode_name('alias.example.com') + QTYPE(5) + QCLASS(1)
    #   answer: pointer 0xC00C (12) + TYPE=5 + CLASS=1 + TTL + RDLENGTH + RDATA
    #     RDATA points back to offset 12 (the QNAME = alias.example.com).
    header = _make_header(qdcount=1, ancount=1)
    qname = _encode_name("alias.example.com")
    question = qname + struct.pack("!HH", 5, 1)  # QTYPE=CNAME
    # RDATA = pointer to offset 12 (back to the QNAME in the question).
    rdata = struct.pack("!H", 0xC00C)
    rr = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 5, 1, 300, len(rdata)) + rdata
    pkt = header + question + rr
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].type == "CNAME"
    assert recs[0].data == "alias.example.com"


# ── parse_dns_response: TXT ──────────────────────────────
def test_parse_txt_concatenates_strings():
    """TXT RDATA with two character-strings -> single concatenated string."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=16)
    answer = _make_answer_txt(
        "example.com", ["v=spf1 ", "include:_spf.example.com"], ttl=60
    )
    pkt = header + question + answer
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].type == "TXT"
    assert recs[0].data == "v=spf1 include:_spf.example.com"


# ── parse_dns_response: NS ───────────────────────────────
def test_parse_ns_record():
    """NS-record with target=ns1.example.com -> data='ns1.example.com'."""
    header = _make_header(qdcount=1, ancount=1)
    question = _make_question("example.com", qtype=2)
    answer = _make_answer_ns("example.com", "ns1.example.com", ttl=300)
    pkt = header + question + answer
    recs = parse_dns_response(pkt)
    assert len(recs) == 1
    assert recs[0].type == "NS"
    assert recs[0].data == "ns1.example.com"


# ── parse_dns_response: tolerance ─────────────────────────
@pytest.mark.parametrize(
    "bad_payload",
    [
        b"",
        b"\x00\x01\x02",  # only 3 bytes — header is 12
        b"\x00" * 12,      # valid header, but no question/anCount==0
        None,
        b"\xff" * 8,       # too short for a header
    ],
)
def test_parse_dns_response_tolerates_bad_payload(bad_payload):
    """Empty / None / truncated / too-short payloads all return []."""
    assert parse_dns_response(bad_payload) == []  # type: ignore[arg-type]


def test_parse_dns_response_rejects_query_packet():
    """A query (QR=0) is not a response — parse_dns_response must return []."""
    # Build a query-style header: QR=0, RD=1, QDCOUNT=0.
    flags = (0 << 15) | (1 << 8) | 0
    header = struct.pack("!HHHHHH", 0x1234, flags, 0, 0, 0, 0)
    assert parse_dns_response(header) == []


def test_parse_dns_response_rcode_nxdomain():
    """RCODE=3 (NXDOMAIN) and QR=1 -> return [] (no crash, no records)."""
    flags = (1 << 15) | (1 << 8) | 3  # QR=1, RD=1, RCODE=3
    header = struct.pack("!HHHHHH", 0x1234, flags, 0, 0, 0, 0)
    assert parse_dns_response(header) == []


def test_parse_dns_response_skips_truncated_rr():
    """If a record's RDLENGTH runs past the end of the packet, drop the trailing records."""
    # A perfectly valid first A record, then a second A whose RDLENGTH is wrong.
    header = _make_header(qdcount=1, ancount=2)
    question = _make_question("example.com", qtype=1)
    first = _make_answer_a("example.com", "1.1.1.1", ttl=10)
    # Second record: NAME=pointer, TYPE=1, CLASS=1, TTL=20, RDLENGTH=99 (lie)
    second = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 1, 1, 20, 99)
    pkt = header + question + first + second
    recs = parse_dns_response(pkt)
    # Only the first record should survive; the second is silently dropped.
    assert len(recs) == 1
    assert recs[0].data == "1.1.1.1"


# ── DnsRecord.to_dict ────────────────────────────────────
def test_dnsrecord_to_dict_shape():
    """to_dict returns a dict with exactly the four documented keys."""
    r = DnsRecord(name="example.com", type="A", ttl=42, data="9.9.9.9")
    d = r.to_dict()
    assert d == {
        "name": "example.com",
        "type": "A",
        "ttl": 42,
        "data": "9.9.9.9",
    }
    # The dataclass must remain a separate object — to_dict is a copy.
    assert d is not r.__dict__


# ── parse_dns_response: multi-record ─────────────────────
def test_parse_multiple_records_in_one_packet():
    """Two A-records in the same response are both returned."""
    header = _make_header(qdcount=1, ancount=2)
    question = _make_question("example.com", qtype=1)
    a1 = _make_answer_a("example.com", "1.1.1.1", ttl=10)
    # Second record: distinct RDATA, same compression pointer.
    name_field = struct.pack("!H", 0xC00C)
    rdata2 = bytes(int(p) for p in "2.2.2.2".split("."))
    a2 = name_field + struct.pack("!HHIH", 1, 1, 20, len(rdata2)) + rdata2
    pkt = header + question + a1 + a2
    recs = parse_dns_response(pkt)
    assert len(recs) == 2
    assert {r.data for r in recs} == {"1.1.1.1", "2.2.2.2"}
