"""Two-step sign-in: the server side of TOTP enrolment, verification and backup codes.

Sign-in with two-step sign-in on::

    POST /api/auth/login          password correct -> {"two_factor": "verify", "challenge": ...}   (no session yet)
    POST /api/auth/login/verify   challenge + 6-digit code (or a backup code) -> session

An administrator or owner without it (TOTP_REQUIRED_ROLES) is made to set it up
before any session exists::

    POST /api/auth/login          password correct -> {"two_factor": "enroll", "challenge", QR, key}
    POST /api/auth/login/enroll   challenge + first code -> session + 10 backup codes (shown once)

A wrong code counts towards the same account lockout as a wrong password, and a
challenge dies after TWO_FACTOR_MAX_ATTEMPTS wrong codes or
TWO_FACTOR_CHALLENGE_SECONDS. A code is never accepted twice.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta

from fastapi import HTTPException

from . import totp
from .audit import AuditContext
from .config import TWO_FACTOR_MAX_ATTEMPTS
from .context import AppContext
from .crypto import IntegrityError
from .errors import CodedHTTPException
from .db import Tx
from .security import hash_token, new_token
from .utils import iso, new_id, now_iso, utcnow

# Shown to the caller for every failed code: it does not say whether the code
# was wrong, already used, or the backup code unknown (the audit trail does).
CODE_REFUSED = "That code did not work. Check the time on your phone and try the newest code."
CHALLENGE_GONE = "This sign-in has expired. Enter your username and password again."

# Backup codes that are still unused. The "used_at IS NULL" line is what makes a
# backup code single-use; tools/mutation_check.py removes it to prove a test notices.
_UNUSED_BACKUP_SQL = (
    "SELECT id FROM backup_codes WHERE user_id = :uid AND code_hash = :hash "
    "AND used_at IS NULL "  # AUTHZ-SQL[backup-code-single-use]
)


def _aad(user_id: str) -> bytes:
    return f"trustvault|totp|{user_id}".encode("utf-8")


def seal_secret(ctx: AppContext, user_id: str, secret: str) -> bytes:
    return ctx.keyring.seal(secret.encode("ascii"), _aad(user_id))


def open_secret(ctx: AppContext, user_id: str, sealed: bytes) -> str:
    return ctx.keyring.unseal(sealed, _aad(user_id)).decode("ascii")


def required_for(ctx: AppContext, role: str) -> bool:
    return role in ctx.settings.totp_required_roles


def needed_at_login(ctx: AppContext, user) -> str | None:
    """'verify' if the person has two-step sign-in on, 'enroll' if their role
    requires it and they have not set it up, else None."""
    if user["totp_enabled_at"]:  # AUTHZ-CHECK[second-factor-enforced]
        return "verify"
    if required_for(ctx, user["role"]):  # AUTHZ-CHECK[second-factor-required-for-role]
        return "enroll"
    return None


def enrolment_offer(ctx: AppContext, username: str, secret: str) -> dict:
    uri = totp.provisioning_uri(secret, username)
    return {"secret": secret, "secret_grouped": totp.grouped(secret), "otpauth_uri": uri,
            "qr": totp.qr_data_uri(uri), "issuer": totp.ISSUER, "account": username,
            "digits": totp.DIGITS, "period": totp.STEP_SECONDS}


# --------------------------------------------------------------- challenges --
@dataclass
class Challenge:
    token_hash: str
    user: dict
    kind: str
    mode: str
    secret: bytes | None
    attempts: int


def start_challenge(tx: Tx, ctx: AppContext, user, kind: str, mode: str, ip: str | None, user_agent: str | None,
                    secret: bytes | None = None) -> tuple[str, str]:
    """Create the 'password was right, code still to come' step. Returns (token, expires_at)."""
    now = utcnow()
    tx.execute("DELETE FROM login_challenges WHERE expires_at <= ? OR user_id = ?", (iso(now), user["id"]))
    token = new_token()
    expires = iso(now + timedelta(seconds=ctx.settings.two_factor_challenge_seconds))
    tx.execute("""INSERT INTO login_challenges (token_hash, user_id, kind, mode, secret, created_at, expires_at, ip, user_agent)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
               (hash_token(token), user["id"], kind, mode, secret, iso(now), expires, ip, user_agent))
    return token, expires


def load_challenge(conn: sqlite3.Connection, token: str) -> Challenge | None:
    row = conn.execute(
        """SELECT c.token_hash, c.kind, c.mode, c.secret, c.attempts, c.expires_at, u.*
           FROM login_challenges c JOIN users u ON u.id = c.user_id WHERE c.token_hash = ?""",
        (hash_token(token or ""),)).fetchone()
    if row is None or row["expires_at"] <= now_iso():  # AUTHZ-CHECK[challenge-must-be-live]
        return None
    user = {k: row[k] for k in row.keys() if k not in ("token_hash", "kind", "mode", "secret", "attempts", "expires_at")}
    return Challenge(row["token_hash"], user, row["kind"], row["mode"], row["secret"], row["attempts"])


def note_failed_code(tx: Tx, ctx: AppContext, challenge: Challenge, audit_ctx: AuditContext, reason: str,
                     method: str) -> bool:
    """Record a wrong code: it counts towards the account lockout, and the
    challenge dies after TWO_FACTOR_MAX_ATTEMPTS. Returns True if it died."""
    from .lockout import record_failed_attempt
    attempts = challenge.attempts + 1
    dead = attempts >= TWO_FACTOR_MAX_ATTEMPTS
    if dead:  # AUTHZ-CHECK[challenge-attempts-limited]
        tx.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge.token_hash,))
    else:
        tx.execute("UPDATE login_challenges SET attempts = ? WHERE token_hash = ?", (attempts, challenge.token_hash))
    ctx.audit.append(tx, audit_ctx, "auth.2fa_failed", "denied",
                     details={"reason": reason, "method": method, "stage": challenge.kind, "attempt": attempts,
                              "challenge_ended": dead})
    record_failed_attempt(tx, ctx, challenge.user, audit_ctx, via="second_factor")
    return dead


# -------------------------------------------------------------------- codes --
def check_totp(ctx: AppContext, user: dict, code: str, sealed: bytes | None = None) -> tuple[int | None, str]:
    """(accepted step, reason). ``sealed`` defaults to the user's active seed."""
    sealed = sealed if sealed is not None else user.get("totp_secret")
    if not sealed:
        return None, "not_enrolled"
    try:
        secret = open_secret(ctx, user["id"], sealed)
    except IntegrityError:  # a seed copied from another user's row, or a damaged one
        return None, "secret_unreadable"
    step = totp.find_step(secret, code, utcnow().timestamp())
    if step is None:
        return None, "bad_code"
    last = user.get("totp_last_step")
    if last is not None and step <= last:  # AUTHZ-CHECK[totp-code-never-reused]
        return None, "code_reused"
    return step, "ok"


def use_backup_code(tx: Tx, ctx: AppContext, user: dict, code: str) -> int | None:
    """Consume a backup code. Returns how many unused codes remain, or None."""
    normalized = totp.normalize(code)
    if len(normalized) != 8:
        return None
    row = tx.execute(_UNUSED_BACKUP_SQL, {"uid": user["id"],
                                          "hash": ctx.keyring.backup_code_hash(user["id"], normalized)}).fetchone()
    if row is None:
        return None
    tx.execute("UPDATE backup_codes SET used_at = ? WHERE id = ?", (now_iso(), row["id"]))
    return tx.execute("SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                      (user["id"],)).fetchone()[0]


def new_backup_codes(tx: Tx, ctx: AppContext, user_id: str) -> list[str]:
    """Replace every backup code of the user; return the new ones (shown once)."""
    codes = totp.new_backup_codes()
    tx.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    now = now_iso()
    for code in codes:
        tx.execute("INSERT INTO backup_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
                   (new_id(), user_id, ctx.keyring.backup_code_hash(user_id, totp.normalize(code)), now))
    return codes


def activate(tx: Tx, ctx: AppContext, user_id: str, sealed: bytes, step: int) -> list[str]:
    """Turn two-step sign-in on with this seed; returns fresh backup codes."""
    tx.execute("""UPDATE users SET totp_secret = ?, totp_enabled_at = ?, totp_last_step = ?, totp_pending = NULL,
                  totp_pending_at = NULL WHERE id = ?""", (sealed, now_iso(), step, user_id))
    return new_backup_codes(tx, ctx, user_id)


def deactivate(tx: Tx, user_id: str) -> None:
    tx.execute("""UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL,
                  totp_pending = NULL, totp_pending_at = NULL WHERE id = ?""", (user_id,))
    tx.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    tx.execute("DELETE FROM login_challenges WHERE user_id = ?", (user_id,))


def unused_backup_codes(conn, user_id: str) -> int:
    return conn.execute("SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                        (user_id,)).fetchone()[0]


def refuse_code() -> HTTPException:
    return CodedHTTPException(401, CODE_REFUSED, "code_refused")


def refuse_challenge() -> HTTPException:
    return CodedHTTPException(401, CHALLENGE_GONE, "sign_in_expired")
