"""tests/test_gs014_credential_exposure.py — positive/negative fixtures for GS014.

Covers the precision fixes: postgres self-reference / variable-interpolation /
placeholder filtering, documentation + docstring skip, and DER/OpenSSH public-key
detection. TP cases (real creds in config, private keys, unattend, WireGuard,
sudoers) must still fire.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from gsc_core.gsc_detectors import AuditContext
from gsc_core.gsc_detectors import gs014_credential_exposure as gs014


@pytest.fixture()
def scan(tmp_path):
    def _scan(files):
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content)
        ctx = AuditContext(project="test", path=tmp_path)
        return gs014.detect(ctx)
    return _scan


def _titles(fs):
    return [f["title"] for f in fs]


# ── positive (TP must still fire) ──────────────────────────────────────────

def test_real_postgres_cred(scan):
    fs = scan({"config.py": 'DATABASE_URL = "postgres://app:S3cretProd!@db:5432/app"\n'})
    assert any("PostgreSQL connection string" in t for t in _titles(fs))


def test_real_postgres_cred_in_env(scan):
    fs = scan({".env": "DATABASE_URL=postgres://app:realpass@db/app\n"})
    assert any("PostgreSQL connection string" in t for t in _titles(fs))


def test_private_key_root(scan):
    fs = scan({"id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                          "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
                          "-----END OPENSSH PRIVATE KEY-----\n"})
    assert any("Private key file" in t for t in _titles(fs))


def test_autounattend_base64(scan):
    fs = scan({"autounattend.xml":
               "<AdministratorPassword><Value>UEFzc3dvcmQxMjM0NTY3ODkwYWJjZGVmZ2hpams=</Value></AdministratorPassword>\n"})
    assert any("Base64-encoded admin password" in t for t in _titles(fs))


def test_wireguard_private_key(scan):
    fs = scan({"wg0.conf": "PrivateKey = cCBmNWo0N2VkdWJmb3duZWR1YmZvd25lZHVib3duZWR1Yg=\n"})
    assert any("WireGuard private key" in t for t in _titles(fs))


def test_sudoers_nopasswd(scan):
    fs = scan({"sudoers": "deploy ALL=(ALL) NOPASSWD: ALL\n"})
    assert any("NOPASSWD" in t for t in _titles(fs))


# ── negative (FP fixes — must NOT fire) ────────────────────────────────────

def test_postgres_self_ref(scan):
    fs = scan({"config.py": 'DATABASE_URL = "postgres://postgres:postgres@localhost/db"\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_remnawave_self_ref(scan):
    fs = scan({"docker-compose.yml":
               "environment:\n  DATABASE_URL: postgres://remnawave:remnawave@postgres:5432/remnawave\n"})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_var_ref(scan):
    fs = scan({"config.py": 'DATABASE_URL = "postgres://app:${POSTGRES_PASSWORD}@db:5432/app"\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_placeholder_prefix(scan):
    fs = scan({"config.py": 'DATABASE_URL = "postgresql://test_user:test_password@localhost/test"\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_scott_redacted(scan):
    fs = scan({"config.py": 'DATABASE_URL = "postgresql://scott:***@localhost/test"\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_md_doc(scan):
    fs = scan({"README.md": "# docs\npostgresql://user:MyExamplePass@localhost/test\n"})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_docstring(scan):
    fs = scan({"app.py": '"""Example: postgresql://user:MyExamplePass@localhost/test"""\nx = 1\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_change_me_placeholder(scan):
    # 'CHANGE_ME' / 'change-me' (underscore/hyphen) placeholder must not fire
    fs = scan({"secrets.yaml":
               'GSC_DATABASE_URL: "postgresql://gsc_app:CHANGE_ME@postgres:5432/gsc"\n'})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_comment_line(scan):
    # commented-out example URL is documentation, not a live credential
    fs = scan({"docker-compose.yml":
               "  #   GSC_DATABASE_URL=postgres://gsc:gsc_dev_pw@postgres:5432/gsc\n"})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_postgres_regex_self_flag(scan):
    # a detector's own regex alternation must not be flagged as a URL
    fs = scan({"detector.py":
               "_URL_RE = re.compile(r'postgres://(?:user|admin):(?:pass|secret)@')\n"})
    assert not any("PostgreSQL" in t for t in _titles(fs))


def test_public_pem_cert(scan):
    fs = scan({"cacert.pem": "-----BEGIN CERTIFICATE-----\n"
                             "MIIDazCCAlOgAwIBAgIUTestCertificateBody00000000\n"
                             "-----END CERTIFICATE-----\n"})
    assert not any("Private key file" in t for t in _titles(fs))


def test_public_ssh_key(scan):
    fs = scan({"server.key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest=="})
    assert not any("Private key file" in t for t in _titles(fs))


def test_binary_der_pem(scan):
    fs = scan({"ca.pem": b"\x30\x82\x01\x00" + b"\x00" * 120})
    assert not any("Private key file" in t for t in _titles(fs))
