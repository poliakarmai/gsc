"""Evidence Passport (audit Killer feature B): verdict logic + HMAC round-trip."""
import pytest

from gsc_cli.gsc_evidence_passport import (
    make_passport,
    verdict_from_isolation,
    verify_passport,
)


def test_verdict_mapping():
    assert verdict_from_isolation("docker", "sha256:abc") == "verified"
    assert verdict_from_isolation("podman", "sha256:abc") == "verified"
    assert verdict_from_isolation("docker", None) == "structural"
    assert verdict_from_isolation("rlimit", "sha256:abc") == "unverified"
    assert verdict_from_isolation("", None) == "unverified"


def test_passport_sign_verify_roundtrip():
    key = b"test-signing-key-0123456789abcdef"
    passport = make_passport(
        finding_key="abc123def456", verdict="verified",
        before={"exit_code": 0, "isolation": "docker"},
        after={"exit_code": 0, "isolation": "docker"},
        scanner_sha="deadbeef", image_digest="sha256:abc",
        signing_key=key, repo="acme/repo", commit="abc1234",
    )
    assert passport["schema"] == "gsc.evidence.v1"
    assert passport["verdict"] == "verified"
    assert passport["signature"]
    assert verify_passport(passport, key) is True


def test_tampered_passport_fails_verification():
    key = b"test-signing-key-0123456789abcdef"
    passport = make_passport(
        finding_key="abc123def456", verdict="verified",
        before={"isolation": "docker"}, after={"isolation": "docker"},
        scanner_sha="deadbeef", image_digest="sha256:abc", signing_key=key,
    )
    passport["finding_key"] = "evil0000000000"
    assert verify_passport(passport, key) is False


def test_wrong_key_fails_verification():
    passport = make_passport(
        finding_key="abc123def456", verdict="structural",
        before={"isolation": "docker"}, after={"isolation": "docker"},
        scanner_sha="deadbeef", image_digest=None, signing_key=b"a" * 32,
    )
    assert verify_passport(passport, b"b" * 32) is False


def test_unsigned_passport_has_no_signature():
    passport = make_passport(
        finding_key="abc123def456", verdict="structural",
        before={"isolation": "docker"}, after={"isolation": "docker"},
        scanner_sha="deadbeef", image_digest=None, signing_key=None,
    )
    assert "signature" not in passport


def test_verified_requires_image_digest():
    with pytest.raises(ValueError):
        make_passport(
            finding_key="abc123def456", verdict="verified",
            before={}, after={}, scanner_sha="deadbeef",
            image_digest=None, signing_key=None,
        )


def test_short_signing_key_rejected():
    with pytest.raises(ValueError):
        make_passport(
            finding_key="abc123def456", verdict="structural",
            before={}, after={}, scanner_sha="deadbeef", image_digest=None,
            signing_key=b"short",
        )


def test_verify_rejects_bad_schema_and_verdict():
    key = b"test-signing-key-0123456789abcdef"
    p = make_passport(
        finding_key="abc123def456", verdict="structural",
        before={}, after={}, scanner_sha="deadbeef", image_digest=None, signing_key=key,
    )
    p["schema"] = "evil"
    assert verify_passport(p, key) is False
    p2 = make_passport(
        finding_key="abc123def456", verdict="structural",
        before={}, after={}, scanner_sha="deadbeef", image_digest=None, signing_key=key,
    )
    p2["verdict"] = "verified"  # but no digest
    assert verify_passport(p2, key) is False
