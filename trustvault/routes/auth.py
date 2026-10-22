"""Authentication: login, logout, current user, password change."""
from __future__ import annotations

import secrets
import sqlite3
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..audit import AuditContext
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, anonymous_audit_ctx, app_ctx, client_ip, cookie_name, current_principal, get_db
from ..models import ChangePasswordRequest, LoginRequest
from ..security import hash_token, new_token, password_problems
from ..utils import clean_line, iso, now_iso, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_FAILED = ("Sign-in failed. Check your username and password. "
                "Repeated failures lock the account for a while.")
MAX_SESSIONS_PER_USER = 10


def user_public(user: dict) -> dict:
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "role": user["role"], "is_external": bool(user["is_external"])}


@router.post("/login", summary="Sign in (anyone)")
def login(body: LoginRequest, request: Request, response: Response,
          conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    ip = client_ip(request)
    attempted = clean_line(body.username, 64)
    audit_ctx = anonymous_audit_ctx(request, attempted)

    if not ctx.limiter.allow(f"login-ip:{ip}", ctx.settings.login_rate_per_ip_per_minute, 60):
        with transaction(conn) as tx:
            ctx.audit.append(tx, audit_ctx, "auth.login", "denied", details={"reason": "rate_limited"})
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Wait a minute and try again.")

    user = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    # Always run Argon2 - against a dummy hash for unknown users - so response
    # time does not reveal whether the username exists.
    password_ok = ctx.passwords.verify(user["password_hash"] if user else None, body.password)
    now = now_iso()

    reason = None
    if user is None:
        reason = "unknown_user"
    elif user["locked_until"] and user["locked_until"] > now:  # AUTHZ-CHECK[account-lockout]
        reason = "account_locked"
    elif not password_ok:  # AUTHZ-CHECK[password-must-match]
        reason = "bad_password"
    elif not user["is_active"]:  # AUTHZ-CHECK[inactive-user-cannot-login]
        reason = "inactive_user"

    if reason:
        with transaction(conn) as tx:
            details = {"reason": reason}
            if user is not None and reason == "bad_password":
                failures = user["failed_logins"] + 1
                locked_until = None
                if failures >= ctx.settings.login_max_failures:
                    locked_until = iso(utcnow() + timedelta(minutes=ctx.settings.lockout_minutes))
                    details["locked_until"] = locked_until
                    failures = 0
                tx.execute("UPDATE users SET failed_logins = ?, locked_until = COALESCE(?, locked_until) WHERE id = ?",
                           (failures, locked_until, user["id"]))
            ctx.audit.append(tx, AuditContext(user["id"] if user else None, attempted, audit_ctx.ip,
                                              audit_ctx.user_agent),
                             "auth.login", "denied", details=details)
        raise HTTPException(status_code=401, detail=LOGIN_FAILED)

    token = new_token()
    csrf = secrets.token_urlsafe(32)
    created = utcnow()
    expires = created + timedelta(hours=ctx.settings.session_absolute_hours)
    with transaction(conn) as tx:
        tx.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        if ctx.passwords.needs_rehash(user["password_hash"]):
            tx.execute("UPDATE users SET password_hash = ? WHERE id = ?", (ctx.passwords.hash(body.password), user["id"]))
        tx.execute(
            """INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (hash_token(token), user["id"], csrf, iso(created), iso(created), iso(expires), ip,
             clean_line(request.headers.get("user-agent", ""), 200)),
        )
        # Cap concurrent sessions per user; the oldest are dropped.
        tx.execute(
            """DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN
               (SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)""",
            (user["id"], user["id"], MAX_SESSIONS_PER_USER),
        )
        ctx.audit.append(tx, AuditContext(user["id"], user["username"], ip, audit_ctx.user_agent),
                         "auth.login", "allowed", details={"mode": body.mode})

    result = {"user": user_public(dict(user)), "csrf_token": csrf, "expires_at": iso(expires)}
    if body.mode == "bearer":
        result["token"] = token  # for API clients; no cookie is set
    else:
        response.set_cookie(cookie_name(ctx), token, httponly=True, secure=ctx.settings.cookie_secure,
                            samesite="strict", path="/", max_age=ctx.settings.session_absolute_hours * 3600)
    return result


@router.post("/logout", summary="Sign out (any signed-in user)")
def logout(response: Response, principal: Principal = Depends(current_principal),
           conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    with transaction(conn) as tx:
        tx.execute("DELETE FROM sessions WHERE token_hash = ?", (principal.token_hash,))
        ctx.audit.append(tx, principal.audit_ctx, "auth.logout", "allowed")
    response.delete_cookie(cookie_name(ctx), path="/")
    return {"ok": True}


@router.get("/me", summary="Current user and CSRF token (any signed-in user)")
def me(principal: Principal = Depends(current_principal)):
    return {"user": user_public(principal.user), "csrf_token": principal.csrf_token}


@router.post("/change-password", summary="Change own password (any signed-in user)")
def change_password(body: ChangePasswordRequest, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    row = conn.execute("SELECT password_hash, failed_logins FROM users WHERE id = ?", (principal.id,)).fetchone()
    if not ctx.passwords.verify(row["password_hash"], body.current_password):  # AUTHZ-CHECK[change-password-needs-current]
        # Wrong guesses here count towards the same lockout as sign-in.
        # Otherwise a stolen session could brute-force the password through
        # this endpoint, which has no other rate limit.
        failures = row["failed_logins"] + 1
        locked = failures >= ctx.settings.login_max_failures
        with transaction(conn) as tx:
            if locked:  # AUTHZ-CHECK[password-guessing-locks-account]
                tx.execute("UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                           (iso(utcnow() + timedelta(minutes=ctx.settings.lockout_minutes)), principal.id))
                # The session guessing the password may be stolen: end every session.
                tx.execute("DELETE FROM sessions WHERE user_id = ?", (principal.id,))
            else:
                tx.execute("UPDATE users SET failed_logins = ? WHERE id = ?", (failures, principal.id))
            ctx.audit.append(tx, principal.audit_ctx, "auth.password_change", "denied",
                             details={"reason": "bad_current_password", "account_locked": locked})
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    problems = password_problems(body.new_password, principal.user["username"])
    if problems:
        raise HTTPException(status_code=400, detail="New password " + "; ".join(problems))
    with transaction(conn) as tx:
        tx.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                   (ctx.passwords.hash(body.new_password), now_iso(), principal.id))
        # Every other session of this user stops working immediately.
        cur = tx.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (principal.id, principal.token_hash))
        ctx.audit.append(tx, principal.audit_ctx, "auth.password_change", "allowed",
                         details={"other_sessions_revoked": cur.rowcount})
    return {"ok": True}
