"""Passwords, tokens and rate limiting."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import Settings

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012", "qwertyuiop12",
    "letmein12345", "welcome12345", "admin1234567", "iloveyou1234", "changeme1234",
    "trustvault123", "trustvault2026", "p@ssw0rd1234", "passw0rd1234",
}
# Common words people pad with digits/symbols to reach a length rule
# ("Password1234!", "Welcome@2026"). Checked after stripping that padding.
COMMON_BASES = {
    "password", "passw0rd", "p@ssw0rd", "p@ssword", "qwerty", "qwertyuiop", "letmein", "welcome", "admin",
    "administrator", "iloveyou", "changeme", "trustvault", "monkey", "dragon", "sunshine", "football",
    "abc", "abcdef", "secret", "login", "master", "default", "company",
}

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128


class Passwords:
    """Argon2id hashing with a constant-cost path for unknown users."""

    def __init__(self, settings: Settings):
        self._ph = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
        )
        # Verifying against this hash when the username does not exist makes a
        # failed login take the same time either way (no user enumeration).
        self._dummy_hash = self._ph.hash(secrets.token_urlsafe(24))

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, stored_hash: str | None, password: str) -> bool:
        try:
            return self._ph.verify(stored_hash or self._dummy_hash, password) and stored_hash is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._ph.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return False


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        problems.append(f"must be at most {PASSWORD_MAX_LENGTH} characters")
    core = password.lower().strip("0123456789!@#$%^&*()_+-=.,?~ ")
    if password.lower() in COMMON_PASSWORDS or core in COMMON_BASES or core.isdigit() or not core:
        problems.append("is too common")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if len(set(password)) < 6:
        problems.append("must use a wider range of characters")
    return problems


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_ref(token_hash: str) -> str:
    """A short tag that links audit events of one sign-in session.

    Derived one-way from the stored token hash (itself one-way from the
    token), with its own label so it is never equal to - or a prefix of -
    anything that can authenticate. 16 hex characters: unique enough to
    group events, useless as a credential."""
    return hashlib.sha256(b"trustvault|audit-session|" + token_hash.encode("ascii")).hexdigest()[:16]


def tokens_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class RateLimiter:
    """In-process sliding-window limiter (single-process deployment).

    A multi-instance deployment would move this to Redis; see THREATS.md.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
