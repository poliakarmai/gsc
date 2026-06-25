#!/usr/bin/env python3
"""
GSC Database Encryption — encrypts SQLite DB at rest using Fernet (AES-128-CBC).
Transparent: gsc.py calls decrypt_on_open / encrypt_on_close.

Key source (priority):
  1. GSC_DB_KEY env var
  2. ~/.gsc/db.key file (auto-generated on first run)
  3. Plaintext (no encryption) if neither exists
"""
import os, sys, sqlite3
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

DB_PATH = os.path.expanduser("~/.hermes/state/gsc_audit.db")
ENC_PATH = DB_PATH + ".enc"
KEY_FILE = os.path.expanduser("~/.gsc/db.key")


def _get_key() -> bytes | None:
    """Get or create encryption key."""
    env_key = os.environ.get("GSC_DB_KEY")
    if env_key:
        return base64.urlsafe_b64decode(env_key)

    kf = Path(KEY_FILE)
    if kf.exists():
        return base64.urlsafe_b64decode(kf.read_text().strip())

    # Generate new key
    key = Fernet.generate_key()
    kf.parent.mkdir(parents=True, exist_ok=True)
    kf.write_text(base64.urlsafe_b64encode(key).decode())
    kf.chmod(0o600)
    return key


def is_encrypted() -> bool:
    """Check if DB is encrypted."""
    return os.path.exists(ENC_PATH)


def encrypt_db():
    """Encrypt plaintext DB → .enc file. Removes plaintext DB."""
    if not os.path.exists(DB_PATH):
        print("No DB to encrypt"); return

    key = _get_key()
    if not key:
        print("No encryption key available"); return

    with open(DB_PATH, "rb") as f:
        plaintext = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(plaintext)

    with open(ENC_PATH, "wb") as f:
        f.write(encrypted)

    # Remove plaintext, keep encrypted
    os.remove(DB_PATH)
    print(f"✅ DB encrypted → {ENC_PATH} ({len(encrypted)} bytes)")


def decrypt_db():
    """Decrypt .enc file → plaintext DB for use."""
    if not os.path.exists(ENC_PATH):
        return  # Not encrypted

    key = _get_key()
    if not key:
        print("No encryption key — cannot decrypt"); return

    with open(ENC_PATH, "rb") as f:
        encrypted = f.read()

    fernet = Fernet(key)
    try:
        plaintext = fernet.decrypt(encrypted)
    except Exception as e:
        print(f"Decryption failed: {e} — wrong key?"); return

    with open(DB_PATH, "wb") as f:
        f.write(plaintext)
    # Keep .enc as backup, write plaintext for sqlite3


def decrypt_on_open():
    """Transparent decrypt before sqlite3.connect()."""
    if is_encrypted():
        decrypt_db()
    return DB_PATH


def encrypt_on_close():
    """Transparent encrypt after operations."""
    if os.path.exists(DB_PATH):
        encrypt_db()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "encrypt":
        encrypt_db()
    elif cmd == "decrypt":
        decrypt_db()
    elif cmd == "status":
        if is_encrypted():
            key_exists = os.path.exists(KEY_FILE) or bool(os.environ.get("GSC_DB_KEY"))
            print(f"🔒 Encrypted ({os.path.getsize(ENC_PATH)} bytes) — key: {'✅' if key_exists else '❌ missing'}")
        else:
            print(f"🔓 Plaintext ({os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0} bytes)")
            print("  Run 'gsc encrypt-db' to secure")
    else:
        print("Usage: gsc encrypt-db | decrypt-db | status")
