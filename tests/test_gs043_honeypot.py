"""tests/test_gs043_honeypot.py — positive/negative fixtures for GS043 (honeypot/rug-pull)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs043_honeypot as g


def _run(tmp_path: Path) -> list:
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _titles(findings):
    return {f["title"] for f in findings}


# ── Positives ───────────────────────────────────────────────────────────────


def test_trading_toggle_detected(tmp_path):
    (tmp_path / "Honey.sol").write_text(
        "contract Honey {\n"
        "  bool public tradingEnabled = true;\n"
        "  address public owner;\n"
        "  function disableTrading() public { tradingEnabled = false; }\n"
        "}\n"
    )
    assert "Owner-controlled trading switch (honeypot indicator)" in _titles(_run(tmp_path))


def test_blacklist_detected(tmp_path):
    (tmp_path / "Honey.sol").write_text(
        "contract Honey {\n"
        "  mapping(address => bool) public isBlacklisted;\n"
        "  function addToBlacklist(address a) public { isBlacklisted[a] = true; }\n"
        "}\n"
    )
    assert "Blacklist mechanism can block selling (honeypot indicator)" in _titles(_run(tmp_path))


def test_unrestricted_mint_detected(tmp_path):
    (tmp_path / "Honey.sol").write_text(
        "contract Honey {\n"
        "  function mint(address to, uint256 amount) public {\n"
        "    _mint(to, amount);\n"
        "  }\n"
        "}\n"
    )
    assert "Unrestricted mint capability (rug vector)" in _titles(_run(tmp_path))


def test_fee_setter_detected(tmp_path):
    (tmp_path / "Honey.sol").write_text(
        "contract Honey {\n"
        "  uint public sellFee = 5;\n"
        "  function setFee(uint newFee) public { sellFee = newFee; }\n"
        "}\n"
    )
    assert "Owner-controlled fee/tax setter (rug indicator)" in _titles(_run(tmp_path))


# ── Negatives (must NOT fire) ───────────────────────────────────────────────


def test_clean_erc20_not_flagged(tmp_path):
    (tmp_path / "Token.sol").write_text(
        "contract Token {\n"
        "  string public name = \"Token\";\n"
        "  uint256 public totalSupply;\n"
        "  mapping(address => uint256) public balanceOf;\n"
        "  function transfer(address to, uint256 amount) public returns (bool) {\n"
        "    balanceOf[msg.sender] -= amount;\n"
        "    balanceOf[to] += amount;\n"
        "    return true;\n"
        "  }\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_guarded_mint_not_flagged(tmp_path):
    (tmp_path / "Token.sol").write_text(
        "contract Token {\n"
        "  address public owner;\n"
        "  function mint(address to, uint256 amount) public onlyOwner {\n"
        "    _mint(to, amount);\n"
        "  }\n"
        "}\n"
    )
    assert "Unrestricted mint capability (rug vector)" not in _titles(_run(tmp_path))


def test_if_revert_guarded_mint_not_flagged(tmp_path):
    (tmp_path / "Token.sol").write_text(
        "contract Token {\n"
        "  address public owner;\n"
        "  function mint(address to, uint256 amount) public {\n"
        "    if (msg.sender != owner) revert();\n"
        "    _mint(to, amount);\n"
        "  }\n"
        "}\n"
    )
    assert "Unrestricted mint capability (rug vector)" not in _titles(_run(tmp_path))


def test_internal_mint_not_flagged(tmp_path):
    # internal _mint helper is not a public mint surface
    (tmp_path / "Token.sol").write_text(
        "contract Token {\n"
        "  function _mint(address to, uint256 amount) internal {\n"
        "    totalSupply += amount;\n"
        "  }\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_comments_not_flagged(tmp_path):
    (tmp_path / "Token.sol").write_text(
        "contract Token {\n"
        "  // disableTrading() would be a honeypot red flag\n"
        "  // mapping(address => bool) blacklist;\n"
        "  /* function mint(address to, uint256 amount) public {} */\n"
        "  uint public x;\n"
        "}\n"
    )
    assert _run(tmp_path) == []
