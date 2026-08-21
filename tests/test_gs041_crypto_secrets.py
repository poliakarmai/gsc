"""tests/test_gs041_crypto_secrets.py — positive/negative fixtures for GS041."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs041_crypto_secrets as g


# Fixed, valid (non-dev) test secrets
VALID_EVM_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
VALID_WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
BIP39_12 = " ".join(["abandon"] * 11 + ["about"])
BIP39_24 = " ".join(["abandon"] * 23 + ["art"])
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


def _run(tmp_path: Path) -> list:
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _titles(findings):
    return {f["title"] for f in findings}


# ── Validators ────────────────────────────────────────────────────────────


def test_valid_evm_key():
    assert g._valid_evm_key(VALID_EVM_KEY) is True


def test_dev_key_rejected():
    assert g._valid_evm_key(DEV_KEY) is False


def test_all_zero_key_rejected():
    assert g._valid_evm_key("0x" + "0" * 64) is False


def test_bip39_checksum_12():
    idx = g._load_wordlist()[1]
    assert g._bip39_checksum_valid(BIP39_12.split(), idx) is True


def test_bip39_checksum_24():
    idx = g._load_wordlist()[1]
    assert g._bip39_checksum_valid(BIP39_24.split(), idx) is True


def test_bip39_bad_checksum_rejected():
    idx = g._load_wordlist()[1]
    bad = ["abandon"] * 11 + ["ability"]
    assert g._bip39_checksum_valid(bad, idx) is False


def test_wif_valid():
    assert g._valid_wif(VALID_WIF) is True


def test_wif_invalid():
    assert g._valid_wif(VALID_WIF[:-1] + "A") is False


# ── End-to-end positives ──────────────────────────────────────────────────


def test_evm_private_key_detected(tmp_path):
    (tmp_path / "leak.py").write_text(f'PRIVATE_KEY = "{VALID_EVM_KEY}"\n')
    assert "Ethereum private key exposed" in _titles(_run(tmp_path))


def test_bare_hex_key_detected(tmp_path):
    (tmp_path / "leak.py").write_text(f'private_key = "{VALID_EVM_KEY[2:]}"\n')
    assert "Ethereum private key exposed (bare hex)" in _titles(_run(tmp_path))


def test_hardhat_key_detected(tmp_path):
    (tmp_path / "hardhat.config.js").write_text(f'privateKey: "{VALID_EVM_KEY}",\n')
    assert "Private key in Hardhat/Foundry config" in _titles(_run(tmp_path))


def test_mnemonic_marker_detected(tmp_path):
    (tmp_path / "wallet.txt").write_text(f'mnemonic = "{BIP39_12}"\n')
    assert "BIP39 mnemonic seed phrase exposed" in _titles(_run(tmp_path))


def test_mnemonic_free_standalone_detected(tmp_path):
    # 24-word phrase without a marker keyword, checksum-validated
    (tmp_path / "notes.txt").write_text(f"backup phrase here: {BIP39_24}\n")
    assert "BIP39 mnemonic seed phrase exposed" in _titles(_run(tmp_path))


def test_wif_detected(tmp_path):
    (tmp_path / "btc.py").write_text(f'WIF = "{VALID_WIF}"\n')
    assert "Bitcoin WIF private key exposed" in _titles(_run(tmp_path))


def test_binance_api_key_detected(tmp_path):
    (tmp_path / "config.js").write_text(
        'const BINANCE_API_KEY = "ab12cd34ef56ab78cd90ef12ab34cd56'
        'ab12cd34ef56ab78cd90ef12ab34cd56";\n'
    )
    assert "Exchange API key/secret exposed" in _titles(_run(tmp_path))


# ── End-to-end negatives (must NOT fire) ──────────────────────────────────


def test_no_false_positive_on_clean_code(tmp_path):
    (tmp_path / "clean.py").write_text('x = 42\nprint("hello world")\n')
    assert _run(tmp_path) == []


def test_zero_key_not_flagged(tmp_path):
    (tmp_path / "fp.py").write_text(f'ZERO = "0x{"0" * 64}"\n')
    assert _run(tmp_path) == []


def test_dev_key_not_flagged(tmp_path):
    (tmp_path / "fp.py").write_text(f'DEV = "{DEV_KEY}"\n')
    assert _run(tmp_path) == []


def test_random_words_not_flagged(tmp_path):
    (tmp_path / "fp.py").write_text(
        "the quick brown fox jumps over the lazy dog near the river bank\n"
    )
    assert _run(tmp_path) == []


def test_test_path_excluded(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "leak.py").write_text(f'KEY = "{VALID_EVM_KEY}"\n')
    assert _run(tmp_path) == []
