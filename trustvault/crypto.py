"""Envelope encryption for stored files and the audit HMAC key.

Every file version gets its own random 256-bit data key (DEK). The file is
encrypted with AES-256-GCM under the DEK, and the DEK is itself encrypted
("wrapped") with the master key (KEK). Both encryptions bind the document id
and version id as associated data, so a blob copied onto another document's
record fails authentication instead of being served.

Destroying a version's wrapped key ("crypto-shredding") makes the blob - and
every copy of it in a backup of the blob store - permanently unreadable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
KEY_LEN = 32


class IntegrityError(Exception):
    """Ciphertext, key or plaintext failed authentication."""


def _load_or_create_key(env_name: str, path: Path, create: bool) -> bytes:
    env_value = os.environ.get(env_name)
    if env_value:
        key = base64.b64decode(env_value)
        if len(key) != KEY_LEN:
            raise ValueError(f"{env_name} must be {KEY_LEN} bytes, base64 encoded")
        return key
    if path.exists():
        key = base64.b64decode(path.read_text(encoding="ascii").strip())
        if len(key) != KEY_LEN:
            raise ValueError(f"{path} does not contain a {KEY_LEN}-byte key")
        return key
    if not create:
        raise FileNotFoundError(f"Key file {path} missing. Run scripts/init_db.py first or set {env_name}.")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    # O_EXCL: never overwrite an existing key by accident.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(key).decode("ascii"))
    return key


@dataclass
class KeyRing:
    master_key: bytes
    audit_key: bytes

    @classmethod
    def load(cls, keys_dir: Path, create: bool = False) -> "KeyRing":
        master = _load_or_create_key("TRUSTVAULT_MASTER_KEY", keys_dir / "master.key", create)
        audit = _load_or_create_key("TRUSTVAULT_AUDIT_KEY", keys_dir / "audit.key", create)
        if hmac.compare_digest(master, audit):
            raise ValueError("Master key and audit key must differ")
        return cls(master_key=master, audit_key=audit)

    # --- file encryption -------------------------------------------------
    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        """Return (blob, wrapped_key). blob = nonce || ciphertext+tag."""
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_LEN)
        blob = nonce + AESGCM(dek).encrypt(nonce, plaintext, aad)
        wrap_nonce = os.urandom(NONCE_LEN)
        wrapped = wrap_nonce + AESGCM(self.master_key).encrypt(wrap_nonce, dek, b"dek|" + aad)
        return blob, wrapped

    def decrypt(self, blob: bytes, wrapped_key: bytes | None, aad: bytes) -> bytes:
        if not wrapped_key:
            raise IntegrityError("content key destroyed")
        try:
            dek = AESGCM(self.master_key).decrypt(wrapped_key[:NONCE_LEN], wrapped_key[NONCE_LEN:], b"dek|" + aad)
            return AESGCM(dek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
        except (InvalidTag, ValueError) as exc:
            raise IntegrityError("blob failed authentication") from exc

    # --- audit -------------------------------------------------------------
    def audit_mac(self, message: bytes) -> str:
        return hmac.new(self.audit_key, message, hashlib.sha256).hexdigest()

    # --- share links ---------------------------------------------------------
    @property
    def link_key(self) -> bytes:
        """Signing key for share links, derived from the master key with its own
        label, so a link signature can never be confused with any other MAC."""
        return hmac.new(self.master_key, b"trustvault|share-link-signing|v1", hashlib.sha256).digest()

    def link_mac(self, message: bytes) -> bytes:
        return hmac.new(self.link_key, message, hashlib.sha256).digest()


    # --- small per-user secrets (two-step sign-in) ----------------------------
    @property
    def secrets_key(self) -> bytes:
        """AES key for small secrets stored in the database (TOTP seeds),
        derived from the master key with its own label."""
        return hmac.new(self.master_key, b"trustvault|user-secrets|v1", hashlib.sha256).digest()

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        """AES-256-GCM; ``aad`` binds the secret to its owner (a sealed seed
        copied onto another user's row does not decrypt)."""
        nonce = os.urandom(NONCE_LEN)
        return nonce + AESGCM(self.secrets_key).encrypt(nonce, plaintext, aad)

    def unseal(self, blob: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(self.secrets_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
        except (InvalidTag, ValueError, TypeError) as exc:
            raise IntegrityError("sealed secret failed authentication") from exc

    def backup_code_hash(self, user_id: str, code: str) -> str:
        """Keyed hash of a backup code: a copy of the database alone cannot be
        used to test guesses offline."""
        key = hmac.new(self.master_key, b"trustvault|backup-codes|v1", hashlib.sha256).digest()
        return hmac.new(key, f"{user_id}|{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def aad_for(document_id: str, version_id: str) -> bytes:
    return f"trustvault|{document_id}|{version_id}".encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
