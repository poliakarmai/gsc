"""tests/test_gs042_solidity.py — positive/negative fixtures for GS042 (Solidity SAST)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs042_solidity as g


def _run(tmp_path: Path) -> list:
    ctx = AuditContext(project="t", path=tmp_path)
    ctx.files = ctx.get_files()
    return g.detect(ctx)


def _titles(findings):
    return {f["title"] for f in findings}


# ── Positives ───────────────────────────────────────────────────────────────


def test_reentrancy_detected(tmp_path):
    (tmp_path / "Vault.sol").write_text(
        "contract Vault {\n"
        "  mapping(address => uint) public balances;\n"
        "  function withdraw() public {\n"
        "    uint amount = balances[msg.sender];\n"
        "    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
        "    balances[msg.sender] = 0;\n"
        "  }\n"
        "}\n"
    )
    assert "Reentrancy via low-level external call" in _titles(_run(tmp_path))


def test_tx_origin_detected(tmp_path):
    (tmp_path / "Wallet.sol").write_text(
        "contract Wallet {\n"
        "  address public owner;\n"
        "  function withdraw() public {\n"
        "    require(tx.origin == owner, \"not owner\");\n"
        "  }\n"
        "}\n"
    )
    assert "tx.origin used for authorization" in _titles(_run(tmp_path))


def test_delegatecall_detected(tmp_path):
    (tmp_path / "Proxy.sol").write_text(
        "contract Proxy {\n"
        "  function upgrade(address impl) public {\n"
        "    (bool ok, ) = impl.delegatecall(msg.data);\n"
        "  }\n"
        "}\n"
    )
    assert "delegatecall to external address" in _titles(_run(tmp_path))


def test_unguarded_selfdestruct_detected(tmp_path):
    (tmp_path / "Killable.sol").write_text(
        "contract Killable {\n"
        "  function kill() public {\n"
        "    selfdestruct(payable(msg.sender));\n"
        "  }\n"
        "}\n"
    )
    assert "selfdestruct without access control" in _titles(_run(tmp_path))


def test_unchecked_arithmetic_detected(tmp_path):
    (tmp_path / "Math.sol").write_text(
        "contract Math {\n"
        "  function add(uint a, uint b) public pure returns (uint) {\n"
        "    unchecked { return a + b; }\n"
        "  }\n"
        "}\n"
    )
    assert "unchecked arithmetic block" in _titles(_run(tmp_path))


def test_send_detected(tmp_path):
    (tmp_path / "Send.sol").write_text(
        "contract Send {\n"
        "  function pay() public payable {\n"
        "    msg.sender.send(msg.value);\n"
        "  }\n"
        "}\n"
    )
    assert ".send() used (return value may be ignored)" in _titles(_run(tmp_path))


def test_oracle_detected(tmp_path):
    (tmp_path / "Oracle.sol").write_text(
        "contract Oracle {\n"
        "  function price(address pair) public view returns (uint) {\n"
        "    (uint r0, uint r1, ) = IUniswapV2Pair(pair).getReserves();\n"
        "    return r1 * 1e18 / r0;\n"
        "  }\n"
        "}\n"
    )
    assert "Direct DEX price read (oracle manipulation)" in _titles(_run(tmp_path))


# ── Negatives (must NOT fire) ───────────────────────────────────────────────


def test_clean_contract_not_flagged(tmp_path):
    (tmp_path / "Clean.sol").write_text(
        "contract Clean {\n"
        "  uint public x;\n"
        "  function set(uint v) public { x = v; }\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_comment_not_flagged(tmp_path):
    (tmp_path / "Comments.sol").write_text(
        "contract Comments {\n"
        "  // selfdestruct(payable(msg.sender));\n"
        "  // tx.origin is bad\n"
        "  /* .call{value: 1}(\"\") */\n"
        "  uint public x;\n"
        "}\n"
    )
    assert _run(tmp_path) == []


def test_guarded_selfdestruct_not_flagged(tmp_path):
    (tmp_path / "Guarded.sol").write_text(
        "contract Guarded {\n"
        "  address public owner;\n"
        "  function kill() public onlyOwner {\n"
        "    selfdestruct(payable(owner));\n"
        "  }\n"
        "}\n"
    )
    assert "selfdestruct without access control" not in _titles(_run(tmp_path))


def test_require_guarded_selfdestruct_not_flagged(tmp_path):
    (tmp_path / "Guarded2.sol").write_text(
        "contract Guarded2 {\n"
        "  address public owner;\n"
        "  function kill() public {\n"
        "    require(msg.sender == owner, \"not owner\");\n"
        "    selfdestruct(payable(owner));\n"
        "  }\n"
        "}\n"
    )
    assert "selfdestruct without access control" not in _titles(_run(tmp_path))


def test_if_revert_guarded_selfdestruct_not_flagged(tmp_path):
    (tmp_path / "Guarded3.sol").write_text(
        "contract Guarded3 {\n"
        "  address public owner;\n"
        "  function kill() public {\n"
        "    if (msg.sender != owner) revert();\n"
        "    selfdestruct(payable(owner));\n"
        "  }\n"
        "}\n"
    )
    assert "selfdestruct without access control" not in _titles(_run(tmp_path))


def test_transfer_not_flagged(tmp_path):
    # .transfer() is gas-limited and reentrancy-safe (not a finding)
    (tmp_path / "Transfer.sol").write_text(
        "contract Transfer {\n"
        "  function pay() public payable {\n"
        "    msg.sender.transfer(msg.value);\n"
        "  }\n"
        "}\n"
    )
    assert _run(tmp_path) == []
