# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GS041 — Crypto secrets detector.

Detects leaked Web3/cryptocurrency credentials in source code:
  - EVM private keys (0x-prefixed and bare 64-hex in key-assignment context)
  - BIP39 mnemonic seed phrases (12/24 words, checksum-validated)
  - Bitcoin WIF (base58check-validated)
  - Exchange API keys (Binance/Coinbase/OKX/Kraken/Bybit)
  - Hardhat / Foundry config private keys and mnemonics

No secret value is ever stored or displayed — only the fact of detection.
Values are validated (checksum / entropy / known-dev-key exclusion) to keep
the false-positive rate near zero.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from . import AuditContext, Finding

RULE_ID = "GS041"
ECHELON = 2
NOISE_TIER = "sensitive"
description = "Crypto secrets — EVM private keys, BIP39 mnemonics, WIF, exchange API keys"

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_BASE58_ALPHABET)}

# Well-known dev/test private keys (Hardhat/Anvil/Ganache defaults). These are
# public by design and appear in every scaffold — never a real leak.
_KNOWN_DEV_KEYS = {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
}

EVM_PRIVKEY_RE = re.compile(r"\b0x[0-9a-fA-F]{64}\b")

# bare 64-hex key in an assignment context (privateKey = "...", secret_key: "...")
BARE_HEX_KEY_RE = re.compile(
    r'(?i)\b(?:private[_-]?key|privkey|secret[_-]?key|signing[_-]?key|sk)\s*[:=]\s*["\']?([0-9a-fA-F]{64})["\']?'
)

# mnemonic/seed phrase declared behind a marker:  mnemonic = "abandon ability ... "
MNEMONIC_MARKER_RE = re.compile(
    r'(?i)\b(?:mnemonic|seed[ _-]?phrase|recovery[ _-]?phrase|bip39|wallet[ _-]?phrase)'
    r'[a-z_ -]{0,12}\s*[:=]\s*["\']([a-z]+(?:[ \t]+[a-z]+){11,23})["\']'
)

WIF_RE = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")

EXCHANGE_API_RES = [
    # Binance / Coinbase API key or secret: 64 hex
    (re.compile(r'(?i)\b(?:binance|coinbase)[a-z_ -]{0,16}\s*[:=]\s*["\']?([0-9a-fA-F]{64})["\']?'),
     "exchange_api_key_64hex"),
    # OKX API key/secret/passphrase: 32 hex
    (re.compile(r'(?i)\b(?:okx|okex)[a-z_ -]{0,16}\s*[:=]\s*["\']?([0-9a-fA-F]{32})["\']?'),
     "exchange_api_key_32hex"),
    # Kraken API key: 56 base64-ish (alnum + / + =)
    (re.compile(r'(?i)\b(?:kraken)[a-z_ -]{0,16}\s*[:=]\s*["\']?([A-Za-z0-9+/]{40,64}={0,2})["\']?'),
     "exchange_api_key_kraken"),
    # Bybit API key/secret: 18 alphanumeric (loose — value validated by entropy)
    (re.compile(r'(?i)\b(?:bybit)[a-z_ -]{0,16}\s*[:=]\s*["\']?([A-Za-z0-9]{18,32})["\']?'),
     "exchange_api_key_bybit"),
]

# Hardhat / Foundry config declarations (camelCase, JS/TS):  privateKey: "0x..."
HARDHAT_KEY_RE = re.compile(
    r'(?i)\b(?:privateKey|secretKey|deployer)\s*[:=]\s*["\'](0x[0-9a-fA-F]{64})["\']?'
)

# Paths that are test/fixture material (never real credentials)
_TEST_PATH_COMPONENTS = {"test", "tests", "fixtures", "fixture", "mocks", "__mocks__",
                        "examples", "example", "samples", "sample", "node_modules"}

_WORDLIST: set[str] | None = None
_WORD_INDEX: dict[str, int] | None = None


def _load_wordlist() -> tuple[set[str], dict[str, int]]:
    global _WORDLIST, _WORD_INDEX
    if _WORDLIST is None:
        data_file = Path(__file__).parent / "data" / "bip39_english.txt"
        try:
            words = [w.strip() for w in data_file.read_text(encoding="utf-8").splitlines()
                     if w.strip()]
        except OSError:
            words = []
        _WORDLIST = set(words)
        _WORD_INDEX = {w: i for i, w in enumerate(words)}
    return _WORDLIST, _WORD_INDEX


def _hex_entropy_ok(hexstr: str) -> bool:
    """Reject keys with too few distinct nibbles (0x1111..., 0x0000...)."""
    h = hexstr[2:] if hexstr.startswith("0x") else hexstr
    if h == "0" * len(h):
        return False
    return len(set(h)) >= 8


def _valid_evm_key(hexstr: str) -> bool:
    if hexstr.lower() in _KNOWN_DEV_KEYS:
        return False
    return _hex_entropy_ok(hexstr)


def _base58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("invalid base58 char")
        n = n * 58 + _B58_INDEX[ch]
    out = b""
    while n > 0:
        n, rem = divmod(n, 256)
        out = bytes([rem]) + out
    n_pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_pad + out


def _valid_wif(s: str) -> bool:
    try:
        raw = _base58decode(s)
    except ValueError:
        return False
    if len(raw) not in (37, 38):  # 37 = uncompressed, 38 = compressed
        return False
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        return False
    return payload[0] == 0x80  # mainnet WIF


def _bip39_checksum_valid(words: list[str], index: dict[str, int]) -> bool:
    """Validate BIP39 checksum (last word encodes CS bits of SHA256(entropy))."""
    n = len(words)
    if n not in (12, 24):
        return False
    if not all(w in index for w in words):
        return False
    ent_bits = 128 if n == 12 else 256
    cs_bits = n * 11 - ent_bits
    bits = "".join(f"{index[w]:011b}" for w in words)
    entropy_bits, checksum_bits = bits[:ent_bits], bits[ent_bits:]
    entropy_bytes = bytes(int(entropy_bits[i:i + 8], 2) for i in range(0, ent_bits, 8))
    digest = hashlib.sha256(entropy_bytes).digest()
    expected = format(digest[0], "08b")[:cs_bits]
    return checksum_bits == expected


def _is_test_path(rel_path: str) -> bool:
    p = rel_path.replace("\\", "/").lower()
    parts = p.split("/")
    return any(comp in _TEST_PATH_COMPONENTS for comp in parts[:-1])


def _mk(rel_path: str, line_no: int, title: str, severity: str, secret_type: str,
        fix: str) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        category=severity,
        title=title,
        file_path=rel_path,
        line=line_no,
        detail=f"<redacted:{secret_type}> at line {line_no}",
        fix_suggestion=fix,
        references=["CWE-798 (Hardcoded Credentials)", "SWC-135 (Unprotected Private Key)"],
    )


def detect(ctx: AuditContext) -> list[Finding]:
    if RULE_ID in ctx.skipped_detectors:
        return []

    wordlist, word_index = _load_wordlist()
    findings: list[Finding] = []

    for fp in ctx.get_files():
        rel_path = str(fp.relative_to(ctx.path))
        if _is_test_path(rel_path):
            continue
        try:
            content = ctx.read_file(fp)
        except Exception:
            continue
        if not content:
            continue

        # EVM-key findings keyed by normalized hex — one finding per physical key.
        # More specific contexts are emitted first and win the dedupe.
        evm_seen: dict[str, Finding] = {}

        def _emit_evm(key_hex: str, line_no: int, title: str, severity: str,
                      secret_type: str, fix: str) -> None:
            norm = key_hex.lower().lstrip("0x")
            if norm not in evm_seen:
                evm_seen[norm] = _mk(rel_path, line_no, title, severity,
                                     secret_type, fix)

        # 3. Hardhat/Foundry config private keys (camelCase — most specific)
        for m in HARDHAT_KEY_RE.finditer(content):
            if _valid_evm_key(m.group(1)):
                line_no = content[:m.start()].count("\n") + 1
                _emit_evm(m.group(1), line_no, "Private key in Hardhat/Foundry config",
                          "HIGH", "evm_private_key",
                          "Use env var (process.env.PRIVATE_KEY) or encrypted keystore.")

        # 2. bare 64-hex keys in key-assignment context (skip 0x-prefixed)
        for m in BARE_HEX_KEY_RE.finditer(content):
            s = m.start(1)
            if s >= 2 and content[s - 2:s].lower() == "0x":
                continue
            if _valid_evm_key(m.group(1)):
                line_no = content[:m.start()].count("\n") + 1
                _emit_evm(m.group(1), line_no, "Ethereum private key exposed (bare hex)",
                          "CRITICAL", "evm_private_key",
                          "Rotate immediately. Move key to env var or encrypted keystore; never commit.")

        # 1. EVM private keys (0x-prefixed) — generic catch-all
        for m in EVM_PRIVKEY_RE.finditer(content):
            if _valid_evm_key(m.group(0)):
                line_no = content[:m.start()].count("\n") + 1
                _emit_evm(m.group(0), line_no, "Ethereum private key exposed",
                          "CRITICAL", "evm_private_key",
                          "Rotate immediately. Move key to env var or encrypted keystore; never commit.")

        findings.extend(evm_seen.values())

        # 4. BIP39 mnemonics declared behind a marker
        for m in MNEMONIC_MARKER_RE.finditer(content):
            words = m.group(1).split()
            if len(words) in (12, 24) and _bip39_checksum_valid(words, word_index):
                line_no = content[:m.start()].count("\n") + 1
                findings.append(_mk(
                    rel_path, line_no, "BIP39 mnemonic seed phrase exposed", "CRITICAL",
                    "bip39_mnemonic",
                    "Rotate wallet. Store phrase in encrypted vault; never commit.",
                ))

        # 5. free-standing 24-word mnemonics (no marker) — checksum-validated
        _scan_free_mnemonics(content, rel_path, wordlist, word_index, findings)

        # 6. Bitcoin WIF (base58check-validated)
        for m in WIF_RE.finditer(content):
            if _valid_wif(m.group(0)):
                line_no = content[:m.start()].count("\n") + 1
                findings.append(_mk(
                    rel_path, line_no, "Bitcoin WIF private key exposed", "CRITICAL",
                    "bitcoin_wif",
                    "Rotate immediately. Never commit WIF keys; use hardware wallet.",
                ))

        # 7. exchange API keys
        for pattern, stype in EXCHANGE_API_RES:
            for m in pattern.finditer(content):
                value = m.group(1)
                if stype == "exchange_api_key_bybit" and len(set(value)) < 8:
                    # bybit values are alnum; require reasonable distinct-char count
                    continue
                line_no = content[:m.start()].count("\n") + 1
                findings.append(_mk(
                    rel_path, line_no, "Exchange API key/secret exposed", "HIGH",
                    stype,
                    "Revoke the API key on the exchange and store it in env vars / secrets manager.",
                ))

    return findings


def _scan_free_mnemonics(content: str, rel_path: str, wordlist: set[str],
                         word_index: dict[str, int], findings: list[Finding]) -> None:
    """Sliding-window scan for 24-word BIP39 phrases without a marker keyword."""
    if not wordlist:
        return
    tokens = re.findall(r"[a-z]{3,8}", content.lower())
    if len(tokens) < 24:
        return
    flags = [t in wordlist for t in tokens]
    i = 0
    n = len(tokens)
    while i < n:
        if not flags[i]:
            i += 1
            continue
        j = i
        while j < n and flags[j]:
            j += 1
        run = tokens[i:j]
        run_len = j - i
        if run_len >= 24:
            for k in range(run_len - 23):
                window = run[k:k + 24]
                if _bip39_checksum_valid(window, word_index):
                    # recover line: locate first word
                    start = content.lower().find(" ".join(window))
                    if start == -1:
                        start = content.lower().find(window[0])
                    line_no = content[:start].count("\n") + 1 if start >= 0 else 0
                    findings.append(_mk(
                        rel_path, line_no, "BIP39 mnemonic seed phrase exposed", "CRITICAL",
                        "bip39_mnemonic",
                        "Rotate wallet. Store phrase in encrypted vault; never commit.",
                    ))
                    break  # one finding per run is enough
        i = j
