"""Authentication: sign-in (with two-step sign-in), sessions, password, TOTP.

Sign-in is one step for people without two-step sign-in, two steps for
people with it, and for administrators and owners (TOTP_REQUIRED_ROLES) two
steps always - the first time, the second step is setting it up. No session
exists until every step has passed. See twofactor.py for the flow.
"""
from __future__ import annotations

import secrets
import sqlite3
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from .. import totp, twofactor
from ..audit import AuditContext
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, anonymous_audit_ctx, app_ctx, client_ip, cookie_name, current_principal, get_db
from ..lockout import record_failed_attempt
from ..models import (ChangePasswordRequest, CodeRequest, DisableTwoFactorRequest, LoginRequest, LogoutRequest,
                      PasswordConfirmRequest, TwoFactorLoginRequest)
from ..security import hash_token, new_token, password_problems, session_ref
from ..utils import clean_line, describe_device, iso, now_iso, parse_iso, utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGIN_FAILED = ("Sign-in failed. Check your username and password. "
                "Repeated failures lock the account for a while.")
TOO_MANY = "Too many sign-in attempts. Wait a minute and try again."
MAX_SESSIONS_PER_USER = 10
PENDING_SETUP_MINUTES = 10

# The current user's sessions. The user_id line is what stops one person from
# listing or ending another person's sessions (mutation-tested).
_OWN_SESSIONS_SQL = (
    "SELECT token_hash, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions WHERE 1 = 1 "
    "AND user_id = :uid "  # AUTHZ-SQL[sessions-are-own-only]
)


def user_public(user: dict) -> dict:
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "role": user["role"], "is_external": bool(user["is_external"])}


# ------------------------------------------------------------------ cookies --
def cookie_is_secure(ctx: AppContext, request: Request) -> bool:
    """Secure whenever HTTPS is used: always with COOKIE_SECURE=1, and also
    automatically when the request itself arrived over HTTPS (or, behind a
    trusted proxy, X-Forwarded-Proto says so)."""
    if ctx.settings.cookie_secure:
        return True
    scheme = request.url.scheme
    if ctx.settings.trust_proxy:
        scheme = (request.headers.get("x-forwarded-proto") or scheme).split(",")[0].strip().lower()
    return scheme == "https"


def set_session_cookie(response: Response, ctx: AppContext, request: Request, token: str) -> None:
    response.set_cookie(cookie_name(ctx), token, httponly=True, secure=cookie_is_secure(ctx, request),
                        samesite="strict", path="/", max_age=ctx.settings.session_absolute_hours * 3600)


def clear_session_cookie(response: Response, ctx: AppContext, request: Request) -> None:
    response.delete_cookie(cookie_name(ctx), path="/", httponly=True, secure=cookie_is_secure(ctx, request),
                           samesite="strict")


# ------------------------------------------------------------------ sign-in --
def _rate_limited(ctx: AppContext, ip: str) -> bool:
    return not ctx.limiter.allow(f"login-ip:{ip}", ctx.settings.login_rate_per_ip_per_minute, 60)


def create_session(tx, ctx: AppContext, request: Request, user: dict, mode: str, second_factor: str,
                   extra: dict | None = None) -> tuple[dict, str]:
    """The last step of every successful sign-in. Returns (response body, token)."""
    token = new_token()
    token_hash = hash_token(token)
    csrf = secrets.token_urlsafe(32)
    created = utcnow()
    expires = created + timedelta(hours=ctx.settings.session_absolute_hours)
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent")
    tx.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
    tx.execute(
        """INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (token_hash, user["id"], csrf, iso(created), iso(created), iso(expires), ip, clean_line(user_agent or "", 200)),
    )
    # Cap concurrent sessions per user; the oldest are dropped.
    tx.execute(
        """DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN
           (SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)""",
        (user["id"], user["id"], MAX_SESSIONS_PER_USER),
    )
    ctx.audit.append(tx, AuditContext(user["id"], user["username"], ip, user_agent, session_ref=session_ref(token_hash)),
                     "auth.login", "allowed", details={"mode": mode, "second_factor": second_factor, **(extra or {})})
    body = {"user": user_public(user), "csrf_token": csrf, "expires_at": iso(expires),
            "session": session_info(ctx, {"last_seen_at": iso(created), "expires_at": iso(expires)})}
    if mode == "bearer":
        body["token"] = token  # for API clients; no cookie is set
    return body, token


def _finish(response: Response, ctx: AppContext, request: Request, body: dict, token: str, mode: str) -> dict:
    if mode != "bearer":
        set_session_cookie(response, ctx, request, token)
    return body


@router.post("/login", summary="Sign in, step 1: username and password (anyone). With two-step sign-in this "
                               "returns a challenge instead of a session.")
def login(body: LoginRequest, request: Request, response: Response,
          conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    ip = client_ip(request)
    attempted = clean_line(body.username, 64)
    audit_ctx = anonymous_audit_ctx(request, attempted)

    if _rate_limited(ctx, ip):
        with transaction(conn) as tx:
            ctx.audit.append(tx, audit_ctx, "auth.login", "denied", details={"reason": "rate_limited"})
        raise HTTPException(status_code=429, detail=TOO_MANY)

    row = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    user = dict(row) if row else None
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
        named = AuditContext(user["id"] if user else None, attempted, audit_ctx.ip, audit_ctx.user_agent)
        with transaction(conn) as tx:
            ctx.audit.append(tx, named, "auth.login", "denied", details={"reason": reason})
            if user is not None and reason == "bad_password":
                # The 5th failure locks the account and writes 'auth.account_locked'.
                record_failed_attempt(tx, ctx, user, named, via="password")
        raise HTTPException(status_code=401, detail=LOGIN_FAILED)

    needed = twofactor.needed_at_login(ctx, user)
    with transaction(conn) as tx:
        if ctx.passwords.needs_rehash(user["password_hash"]):
            tx.execute("UPDATE users SET password_hash = ? WHERE id = ?", (ctx.passwords.hash(body.password), user["id"]))
        if needed is not None:
            # The password was right; no session until the second step passes.
            offer, sealed = {}, None
            if needed == "enroll":
                secret = totp.new_secret()
                sealed = twofactor.seal_secret(ctx, user["id"], secret)
                offer = twofactor.enrolment_offer(ctx, user["username"], secret)
            token, expires = twofactor.start_challenge(tx, ctx, user, needed, body.mode, ip,
                                                       clean_line(request.headers.get("user-agent", ""), 200), sealed)
            ctx.audit.append(tx, AuditContext(user["id"], user["username"], ip, audit_ctx.user_agent),
                             "auth.2fa_required", "info", details={"stage": needed, "mode": body.mode})
            return {"two_factor": needed, "challenge": token, "expires_at": expires,
                    "required_for_role": twofactor.required_for(ctx, user["role"]), **offer}
        result, token = create_session(tx, ctx, request, user, body.mode, "none")
    return _finish(response, ctx, request, result, token, body.mode)


def _challenge_or_refuse(conn, ctx: AppContext, request: Request, token: str, kind: str):
    """Load a live challenge of this kind, or record the refusal and raise."""
    ip = client_ip(request)
    anonymous = anonymous_audit_ctx(request)
    if _rate_limited(ctx, ip):
        with transaction(conn) as tx:
            ctx.audit.append(tx, anonymous, "auth.2fa_failed", "denied", details={"reason": "rate_limited", "stage": kind})
        raise HTTPException(status_code=429, detail=TOO_MANY)
    challenge = twofactor.load_challenge(conn, token)
    if challenge is None or challenge.kind != kind:
        with transaction(conn) as tx:
            ctx.audit.append(tx, anonymous, "auth.2fa_failed", "denied",
                             details={"reason": "challenge_invalid", "stage": kind})
        raise twofactor.refuse_challenge()
    user = challenge.user
    named = AuditContext(user["id"], user["username"], ip, request.headers.get("user-agent"))
    blocked = "inactive_user" if not user["is_active"] else \
        "account_locked" if user["locked_until"] and user["locked_until"] > now_iso() else None
    if blocked:
        with transaction(conn) as tx:
            tx.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge.token_hash,))
            ctx.audit.append(tx, named, "auth.2fa_failed", "denied", details={"reason": blocked, "stage": kind})
        raise twofactor.refuse_challenge()
    return challenge, named


@router.post("/login/verify", summary="Sign in, step 2: the 6-digit code from the authenticator app, or a backup "
                                      "code (anyone holding a challenge from step 1)")
def login_verify(body: TwoFactorLoginRequest, request: Request, response: Response,
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    challenge, named = _challenge_or_refuse(conn, ctx, request, body.challenge, "verify")
    user = challenge.user
    method = "totp" if totp.looks_like_totp(body.code) else "backup_code"
    refused = False
    with transaction(conn) as tx:
        step, remaining, why = None, None, "bad_backup_code"
        if method == "totp":
            step, why = twofactor.check_totp(ctx, user, body.code)
        else:
            remaining = twofactor.use_backup_code(tx, ctx, user, body.code)
        accepted = step is not None or remaining is not None
        if not accepted:  # AUTHZ-CHECK[second-factor-must-match]
            twofactor.note_failed_code(tx, ctx, challenge, named, why, method)
            refused = True
        else:
            if step is not None:
                tx.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
            tx.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge.token_hash,))
            extra = {"backup_codes_left": remaining} if method == "backup_code" else None
            result, token = create_session(tx, ctx, request, user, challenge.mode, method, extra)
    if refused:
        raise twofactor.refuse_code()
    if method == "backup_code":
        result["backup_codes_left"] = remaining
    return _finish(response, ctx, request, result, token, challenge.mode)


@router.post("/login/enroll", summary="Sign in, step 2 for a first-time administrator or owner: confirm the new "
                                      "authenticator with its first code. Returns 10 backup codes, shown once.")
def login_enroll(body: TwoFactorLoginRequest, request: Request, response: Response,
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    challenge, named = _challenge_or_refuse(conn, ctx, request, body.challenge, "enroll")
    user = challenge.user
    refused = False
    with transaction(conn) as tx:
        step, why = twofactor.check_totp(ctx, {**user, "totp_last_step": None}, body.code, sealed=challenge.secret)
        if step is None:  # AUTHZ-CHECK[enrolment-needs-a-working-code]
            twofactor.note_failed_code(tx, ctx, challenge, named, why, "totp")
            refused = True
        else:
            codes = twofactor.activate(tx, ctx, user["id"], challenge.secret, step)
            tx.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge.token_hash,))
            ctx.audit.append(tx, named, "auth.2fa_enrolled", "allowed",
                             details={"via": "sign_in", "required_for_role": twofactor.required_for(ctx, user["role"]),
                                      "backup_codes": len(codes)})
            result, token = create_session(tx, ctx, request, user, challenge.mode, "totp", {"enrolled": True})
    if refused:
        raise twofactor.refuse_code()
    result["backup_codes"] = codes
    return _finish(response, ctx, request, result, token, challenge.mode)


@router.post("/logout", summary="Sign out (any signed-in user). The browser sends a reason when its timer ran out.")
def logout(request: Request, response: Response, body: Optional[LogoutRequest] = None,
           principal: Principal = Depends(current_principal),
           conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    with transaction(conn) as tx:
        tx.execute("DELETE FROM sessions WHERE token_hash = ?", (principal.token_hash,))
        if body is not None and body.reason:
            ctx.audit.append(tx, principal.audit_ctx, "auth.session_expired", "info",
                             details={"reason": body.reason, "detected": "browser",
                                      "last_seen_at": principal.session["last_seen_at"]})
        else:
            ctx.audit.append(tx, principal.audit_ctx, "auth.logout", "allowed")
    clear_session_cookie(response, ctx, request)
    return {"ok": True}


def session_info(ctx: AppContext, session: dict) -> dict:
    """What the UI needs to warn before an idle or end-of-day sign-out."""
    return {"idle_timeout_seconds": ctx.settings.session_idle_minutes * 60,
            "warning_seconds": ctx.settings.session_warning_seconds,
            "last_seen_at": session["last_seen_at"], "expires_at": session["expires_at"],
            "server_time": now_iso()}


@router.get("/me", summary="Current user, CSRF token and session limits (any signed-in user)")
def me(principal: Principal = Depends(current_principal), ctx: AppContext = Depends(app_ctx)):
    return {"user": user_public(principal.user), "csrf_token": principal.csrf_token,
            "session": session_info(ctx, principal.session)}


@router.post("/keepalive", summary="'Stay signed in': restart the idle timer (any signed-in user)")
def keepalive(principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db),
              ctx: AppContext = Depends(app_ctx)):
    # The absolute limit (SESSION_MAX_HOURS) is never extended - only the idle timer restarts.
    now = now_iso()
    with transaction(conn) as tx:
        tx.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (now, principal.token_hash))
        ctx.audit.append(tx, principal.audit_ctx, "auth.session_extended", "info",
                         details={"idle_timeout_minutes": ctx.settings.session_idle_minutes})
    return {"ok": True, "session": session_info(ctx, {**principal.session, "last_seen_at": now})}


@router.post("/change-password", summary="Change own password (any signed-in user)")
def change_password(body: ChangePasswordRequest, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (principal.id,)).fetchone()
    if not ctx.passwords.verify(row["password_hash"], body.current_password):  # AUTHZ-CHECK[change-password-needs-current]
        # Wrong guesses here count towards the same lockout as sign-in.
        # Otherwise a stolen session could brute-force the password through
        # this endpoint, which has no other rate limit.
        _wrong_password(conn, ctx, principal, dict(row), "auth.password_change")
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


def _wrong_password(conn, ctx: AppContext, principal: Principal, user: dict, action: str) -> None:
    """A wrong current password from a signed-in session. It counts towards the
    lockout; if this locks the account, every session ends - the session that
    is guessing may be stolen."""
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, action, "denied", details={"reason": "bad_current_password"})
        locked_until = record_failed_attempt(tx, ctx, user, principal.audit_ctx, via=action)
        if locked_until:  # AUTHZ-CHECK[password-guessing-locks-account]
            tx.execute("DELETE FROM sessions WHERE user_id = ?", (principal.id,))


def _own_user(conn, principal: Principal) -> dict:
    return dict(conn.execute("SELECT * FROM users WHERE id = ?", (principal.id,)).fetchone())


# --------------------------------------------------------- two-step sign-in --
@router.get("/2fa", summary="Two-step sign-in status of the current user (any signed-in user)")
def two_factor_status(principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db),
                      ctx: AppContext = Depends(app_ctx)):
    user = _own_user(conn, principal)
    return {"enabled": bool(user["totp_enabled_at"]), "enabled_at": user["totp_enabled_at"],
            "required": twofactor.required_for(ctx, principal.role),
            "backup_codes_left": twofactor.unused_backup_codes(conn, principal.id) if user["totp_enabled_at"] else 0}


@router.post("/2fa/setup", summary="Start setting up two-step sign-in (or moving it to a new phone): returns the QR "
                                   "code and key. Needs the password. Nothing changes until /2fa/enable confirms a code.")
def two_factor_setup(body: PasswordConfirmRequest, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _own_user(conn, principal)
    if not ctx.passwords.verify(user["password_hash"], body.password):  # AUTHZ-CHECK[2fa-setup-needs-password]
        _wrong_password(conn, ctx, principal, user, "auth.2fa_setup")
        raise HTTPException(status_code=400, detail="Password is incorrect")
    secret = totp.new_secret()
    with transaction(conn) as tx:
        tx.execute("UPDATE users SET totp_pending = ?, totp_pending_at = ? WHERE id = ?",
                   (twofactor.seal_secret(ctx, principal.id, secret), now_iso(), principal.id))
        ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_setup", "info",
                         details={"replacing": bool(user["totp_enabled_at"])})
    return twofactor.enrolment_offer(ctx, principal.user["username"], secret)


@router.post("/2fa/enable", summary="Confirm the new authenticator with its first code. Turns two-step sign-in on, "
                                    "signs out every other session, returns 10 backup codes (shown once).")
def two_factor_enable(body: CodeRequest, principal: Principal = Depends(current_principal),
                      conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _own_user(conn, principal)
    fresh = user["totp_pending_at"] and \
        parse_iso(user["totp_pending_at"]) > utcnow() - timedelta(minutes=PENDING_SETUP_MINUTES)
    if not user["totp_pending"] or not fresh:
        raise HTTPException(status_code=400, detail="Start the set-up again (it is valid for 10 minutes).")
    if not ctx.limiter.allow(f"2fa-enable:{principal.id}", 10, 60):
        raise HTTPException(status_code=429, detail=TOO_MANY)
    step, why = twofactor.check_totp(ctx, {**user, "totp_last_step": None}, body.code, sealed=user["totp_pending"])
    if step is None:  # AUTHZ-CHECK[2fa-enable-needs-a-working-code]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_failed", "denied",
                             details={"reason": why, "method": "totp", "stage": "enable"})
        raise twofactor.refuse_code()
    with transaction(conn) as tx:
        codes = twofactor.activate(tx, ctx, principal.id, user["totp_pending"], step)
        others = tx.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                            (principal.id, principal.token_hash)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_enrolled", "allowed",
                         details={"via": "account", "replaced": bool(user["totp_enabled_at"]),
                                  "backup_codes": len(codes), "other_sessions_revoked": others})
    return {"enabled": True, "backup_codes": codes, "other_sessions_revoked": others}


@router.post("/2fa/disable", summary="Turn two-step sign-in off (password + a current code). Refused for roles "
                                     "that require it.")
def two_factor_disable(body: DisableTwoFactorRequest, principal: Principal = Depends(current_principal),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    if twofactor.required_for(ctx, principal.role):  # AUTHZ-CHECK[required-2fa-cannot-be-turned-off]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_disabled", "denied",
                             details={"reason": "required_for_role", "role": principal.role})
        raise HTTPException(status_code=403, detail="Two-step sign-in is required for your role and cannot be turned off.")
    user = _own_user(conn, principal)
    if not user["totp_enabled_at"]:
        return {"enabled": False}
    if not ctx.passwords.verify(user["password_hash"], body.password):  # AUTHZ-CHECK[2fa-disable-needs-password]
        _wrong_password(conn, ctx, principal, user, "auth.2fa_disabled")
        raise HTTPException(status_code=400, detail="Password is incorrect")
    refused = False
    with transaction(conn) as tx:
        if totp.looks_like_totp(body.code):
            step, why = twofactor.check_totp(ctx, user, body.code)
            ok = step is not None
        else:
            ok, why = twofactor.use_backup_code(tx, ctx, user, body.code) is not None, "bad_backup_code"
        if not ok:  # AUTHZ-CHECK[2fa-disable-needs-a-code]
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_disabled", "denied", details={"reason": why})
            record_failed_attempt(tx, ctx, user, principal.audit_ctx, via="auth.2fa_disabled")
            refused = True
        else:
            twofactor.deactivate(tx, principal.id)
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_disabled", "allowed", details={})
    if refused:
        raise twofactor.refuse_code()
    return {"enabled": False}


@router.post("/2fa/backup-codes", summary="Replace the backup codes (a current 6-digit code). The new codes are "
                                          "shown once; the old ones stop working.")
def two_factor_new_backup_codes(body: CodeRequest, principal: Principal = Depends(current_principal),
                                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _own_user(conn, principal)
    if not user["totp_enabled_at"]:
        raise HTTPException(status_code=400, detail="Two-step sign-in is not on.")
    step, why = twofactor.check_totp(ctx, user, body.code)
    with transaction(conn) as tx:
        if step is None:  # AUTHZ-CHECK[new-backup-codes-need-a-code]
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_failed", "denied",
                             details={"reason": why, "method": "totp", "stage": "backup_codes"})
            record_failed_attempt(tx, ctx, user, principal.audit_ctx, via="second_factor")
            codes = None
        else:
            tx.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, principal.id))
            codes = twofactor.new_backup_codes(tx, ctx, principal.id)
            ctx.audit.append(tx, principal.audit_ctx, "auth.2fa_backup_codes_renewed", "allowed",
                             details={"backup_codes": len(codes)})
    if codes is None:
        raise twofactor.refuse_code()
    return {"backup_codes": codes}


# ----------------------------------------------------------------- sessions --
def _own_sessions(conn, principal: Principal) -> list[dict]:
    return [dict(r) for r in conn.execute(_OWN_SESSIONS_SQL, {"uid": principal.id})]


@router.get("/sessions", summary="Where I am signed in: device, IP, signed in, last seen (any signed-in user)")
def list_sessions(principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db)):
    items = []
    for r in _own_sessions(conn, principal):
        items.append({"id": session_ref(r["token_hash"]), "device": describe_device(r["user_agent"]),
                      "user_agent": r["user_agent"], "ip": r["ip"], "created_at": r["created_at"],
                      "last_seen_at": r["last_seen_at"], "expires_at": r["expires_at"],
                      "current": r["token_hash"] == principal.token_hash})
    current = [i for i in items if i["current"]]
    others = sorted((i for i in items if not i["current"]), key=lambda i: i["last_seen_at"], reverse=True)
    return {"items": current + others, "server_time": now_iso()}


@router.delete("/sessions/{ref}", summary="Sign out one of my sessions, at once, on the server (any signed-in user)")
def end_session(request: Request, response: Response, ref: str = Path(..., pattern=r"^[0-9a-f]{16}$"),
                principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db),
                ctx: AppContext = Depends(app_ctx)):
    match = next((r for r in _own_sessions(conn, principal) if session_ref(r["token_hash"]) == ref), None)
    if match is None:
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "auth.session_revoked", "denied",
                             details={"reason": "session_not_found", "session": ref})
        raise HTTPException(status_code=404, detail="No such session")
    current = match["token_hash"] == principal.token_hash
    with transaction(conn) as tx:
        tx.execute("DELETE FROM sessions WHERE token_hash = ?", (match["token_hash"],))
        ctx.audit.append(tx, principal.audit_ctx, "auth.session_revoked", "allowed",
                         details={"session": ref, "this_session": current, "device": describe_device(match["user_agent"]),
                                  "ip": match["ip"]})
    if current:
        clear_session_cookie(response, ctx, request)
    return {"ok": True, "signed_out_here": current}


@router.post("/sessions/sign-out-everywhere", summary="End every session of mine, this one included (any signed-in user)")
def sign_out_everywhere(request: Request, response: Response, principal: Principal = Depends(current_principal),
                        conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    with transaction(conn) as tx:
        ended = tx.execute("DELETE FROM sessions WHERE user_id = ?", (principal.id,)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "auth.signed_out_everywhere", "allowed", details={"sessions": ended})
    clear_session_cookie(response, ctx, request)
    return {"ok": True, "sessions_ended": ended}
