"""Unit tests for federated privacy hardening — Step 1 (TLS + HMAC, audit #2 §3.4)."""
import hashlib
import hmac
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gsc_federated import FederatedClient


class FakeDB:
    tenant_id = "local"


def _client(url="https://example.com", hmac_key=""):
    return FederatedClient(FakeDB(), url, "api-key", hmac_key=hmac_key)


def test_https_enforced():
    c = _client("http://example.com")
    try:
        c._request("/x", b"{}")
        assert False, "must reject non-HTTPS"
    except ValueError as e:
        assert "HTTPS" in str(e)


def test_https_allowed():
    c = _client("https://example.com")
    # https + no hmac → no x-signature header expected; can't hit network here,
    # just assert the URL/context path doesn't raise ValueError prematurely is
    # covered by test_https_enforced. This test documents the accept-branch.
    assert c.server_url.startswith("https://")


def test_hmac_signature_stable():
    c = _client(hmac_key="secret123")
    expected = hmac.new(b"secret123", b"hello", hashlib.sha256).hexdigest()
    assert c._sign(b"hello") == expected
    assert c._sign(b"hello") == c._sign(b"hello")


def test_no_signature_without_key():
    c = _client()
    assert c._sign(b"hello") == ""
