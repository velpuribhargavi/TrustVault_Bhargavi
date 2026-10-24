"""Temporary account lockout after repeated failures.

Wrong passwords (sign-in and "change password") and wrong two-step codes all
count towards the same limit: LOGIN_MAX_FAILURES (5) failures lock the account
for LOCKOUT_MINUTES (15). Reaching the limit writes an 'auth.account_locked'
audit event; every refused attempt is also recorded by its caller. Sign-in is
additionally rate-limited per IP address (routes/auth.py, 'rate_limited').
"""
from __future__ import annotations

from datetime import timedelta

from .audit import AuditContext
from .context import AppContext
from .db import Tx
from .utils import iso, utcnow


def record_failed_attempt(tx: Tx, ctx: AppContext, user, audit_ctx: AuditContext, via: str) -> str | None:
    """Count one failure for ``user``. Returns the lockout end if this failure
    locked the account, else None."""
    failures = tx.execute("SELECT failed_logins FROM users WHERE id = ?", (user["id"],)).fetchone()[0] + 1
    if failures >= ctx.settings.login_max_failures:  # AUTHZ-CHECK[repeated-failures-lock-account]
        locked_until = iso(utcnow() + timedelta(minutes=ctx.settings.lockout_minutes))
        tx.execute("UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?", (locked_until, user["id"]))
        tx.execute("DELETE FROM login_challenges WHERE user_id = ?", (user["id"],))
        ctx.audit.append(tx, audit_ctx, "auth.account_locked", "info", target_user_id=user["id"],
                         details={"reason": "too_many_failures", "via": via, "failures": failures,
                                  "locked_until": locked_until, "lockout_minutes": ctx.settings.lockout_minutes})
        return locked_until
    tx.execute("UPDATE users SET failed_logins = ? WHERE id = ?", (failures, user["id"]))
    return None
