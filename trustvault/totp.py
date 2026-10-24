"""Two-step sign-in: time-based one-time passwords (RFC 6238) and backup codes.

Standard library only for the codes themselves (HMAC-SHA1, 30-second steps,
6 digits - what Google Authenticator, Microsoft Authenticator, Authy and
1Password expect). The QR picture for enrolment is drawn by ``segno`` (pure
Python, no other dependencies); without it the UI shows the setup key only.

Security properties:
* the secret is stored encrypted (``KeyRing.seal``), never in plain text;
* a code is accepted for the current 30-second step and one step either side
  (clock drift), and **never twice**: the last step used is stored per user;
* backup codes are random, single-use, and stored only as keyed hashes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse

DIGITS = 6
STEP_SECONDS = 30
DRIFT_STEPS = 1
ISSUER = "TrustVault"
BACKUP_CODE_COUNT = 10
_BACKUP_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i: easy to copy by hand


def new_secret() -> str:
    """160 random bits, base32 (the format authenticator apps accept)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret: str, counter: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def step_at(timestamp: float) -> int:
    return int(timestamp // STEP_SECONDS)


def code_at(secret: str, timestamp: float) -> str:
    return hotp(secret, step_at(timestamp))


def normalize(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def looks_like_totp(code: str) -> bool:
    c = normalize(code)
    return len(c) == DIGITS and c.isdigit()


def find_step(secret: str, code: str, timestamp: float) -> int | None:
    """The time step whose code equals ``code`` (current step +- drift), or None."""
    c = normalize(code)
    if not looks_like_totp(c):
        return None
    now = step_at(timestamp)
    for step in range(now - DRIFT_STEPS, now + DRIFT_STEPS + 1):
        if hmac.compare_digest(hotp(secret, step), c):
            return step
    return None


def provisioning_uri(secret: str, account: str) -> str:
    label = urllib.parse.quote(f"{ISSUER}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": ISSUER, "algorithm": "SHA1",
                                    "digits": DIGITS, "period": STEP_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def qr_data_uri(uri: str) -> str | None:
    """A PNG of the QR code as a data: URI (allowed by the CSP's img-src)."""
    try:
        import segno
    except ImportError:  # pragma: no cover - the key can still be typed in
        return None
    return segno.make(uri, error="m").png_data_uri(scale=6, border=2, dark="#0A0A0A", light="#FFFFFF")


def grouped(secret: str) -> str:
    """'JBSW Y3DP EHPK 3PXP' - easier to type into an app by hand."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def new_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """``xxxx-xxxx`` codes, 31^8 (about 2^40) possibilities each."""
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes
