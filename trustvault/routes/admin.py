"""Administration: users, audit trail, integrity, alerts, access review.

Administrators can see *metadata* (who has access to what, what happened)
but never document content, and can only ever reduce access.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from dataclasses import asdict, dataclass
from dataclasses import field as dc_field
from datetime import date, timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi import Path as PathParam

from .. import twofactor
from ..alerts import compute_alerts
from ..audit_text import GROUPS, action_group, action_label, describe, reason_text
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, app_ctx, get_db, require_role
from ..expiry import log_expired_grants
from ..models import BulkRevokeRequest, CreateUserRequest, ResetPasswordRequest, UpdateUserRequest
from ..security import password_problems
from ..utils import clean_line, is_valid_id, iso, new_id, now_iso, parse_iso, utcnow

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role("admin")


def _user_row(r) -> dict:
    d = dict(r)
    for secret in ("password_hash", "totp_secret", "totp_pending", "totp_pending_at", "totp_last_step"):
        d.pop(secret, None)  # never leaves the server, not even to an administrator
    d["is_active"] = bool(d["is_active"])
    d["is_external"] = bool(d["is_external"])
    d["two_factor"] = bool(d.pop("totp_enabled_at", None))
    return d


# -------------------------------------------------------------------- users --
@router.get("/users", summary="List users (admin)")
def list_users(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT u.*, (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS active_sessions,
                  (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id AND d.purged_at IS NULL) AS owned_documents,
                  (SELECT COUNT(*) FROM grants g WHERE g.user_id = u.id AND g.expires_at > :now) AS grants_held
           FROM users u ORDER BY u.username COLLATE NOCASE""", {"now": now_iso()}
    ).fetchall()
    return {"items": [_user_row(r) for r in rows]}


@router.post("/users", status_code=201, summary="Create a user (admin)")
def create_user(body: CreateUserRequest, principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    problems = password_problems(body.password, body.username)
    if problems:
        raise HTTPException(status_code=400, detail="Password " + "; ".join(problems))
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (body.username,)).fetchone():
        raise HTTPException(status_code=409, detail="Username already exists")
    user_id = new_id()
    now = now_iso()
    with transaction(conn) as tx:
        tx.execute(
            """INSERT INTO users (id, username, display_name, password_hash, role, is_external, created_at,
                                  password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, body.username, clean_line(body.display_name, 80), ctx.passwords.hash(body.password),
             body.role, int(body.is_external), now, now),
        )
        ctx.audit.append(tx, principal.audit_ctx, "user.create", "allowed", target_user_id=user_id,
                         details={"username": body.username, "role": body.role, "is_external": body.is_external})
    return {"id": user_id, "username": body.username, "role": body.role}


def _load_user(conn, user_id: str) -> dict:
    """Load a user an admin may still change. Deleted accounts are final: they
    can never be re-activated, re-roled, unlocked or given a new password."""
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() if is_valid_id(user_id) else None
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    if row["deleted_at"] is not None:  # AUTHZ-CHECK[deleted-account-is-final]
        raise HTTPException(status_code=409, detail="This account was deleted and can no longer be changed")
    return dict(row)


@router.patch("/users/{user_id}", summary="Change role / activate / deactivate (admin). Deactivation is immediate.")
def update_user(user_id: str, body: UpdateUserRequest, principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    changes: dict = {}
    if body.display_name is not None and clean_line(body.display_name, 80) != user["display_name"]:
        changes["display_name"] = clean_line(body.display_name, 80)
    if body.role is not None and body.role != user["role"]:
        changes["role"] = body.role
    if body.is_active is not None and int(body.is_active) != user["is_active"]:
        changes["is_active"] = int(body.is_active)
    if body.is_external is not None and int(body.is_external) != user["is_external"]:
        changes["is_external"] = int(body.is_external)
    if not changes:
        return {"ok": True, "changed": []}
    # Because an admin can never demote or deactivate themselves, the caller
    # always remains an active admin: the system cannot end up with none.
    if user["id"] == principal.id and ("role" in changes or "is_active" in changes):  # AUTHZ-CHECK[admin-cannot-change-self]
        raise HTTPException(status_code=400, detail="You cannot change your own role or deactivate yourself")

    with transaction(conn) as tx:
        sets = ", ".join(f"{k} = :{k}" for k in changes)  # keys from the fixed set above
        tx.execute(f"UPDATE users SET {sets} WHERE id = :id", {**changes, "id": user["id"]})
        revoked = 0
        if changes.get("is_active") == 0:
            # Leaving the company: every session ends now. Grants and share
            # links are checked against is_active on every request, so they
            # stop working at the same moment (links they created included).
            revoked = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "user.update", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "sessions_revoked": revoked,
                                  "changes": {k: {"from": user[k], "to": v} for k, v in changes.items()}})
    return {"ok": True, "changed": sorted(changes), "sessions_revoked": revoked}


@router.delete("/users/{user_id}",
               summary="Delete a user (admin). Final: sign-in, sessions, grants and links end; "
                       "the record stays so the audit trail still names them.")
def delete_user(user_id: str, principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    if user["id"] == principal.id:  # AUTHZ-CHECK[admin-cannot-delete-self]
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    owned = conn.execute("SELECT COUNT(*) FROM documents WHERE owner_id = ? AND purged_at IS NULL",
                         (user["id"],)).fetchone()[0]
    if owned:
        raise HTTPException(status_code=409, detail=(
            f"{user['username']} still owns {owned} document(s). They must be destroyed first - "
            "or deactivate the account instead, which keeps their documents."))
    now = now_iso()
    with transaction(conn) as tx:
        grants = tx.execute("DELETE FROM grants WHERE user_id = ?", (user["id"],)).rowcount
        sessions = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? "
                   "WHERE suggested_user_id = ? AND status = 'pending'", (now, user["id"]))
        tx.execute("UPDATE users SET is_active = 0, deleted_at = ?, failed_logins = 0, locked_until = NULL "
                   "WHERE id = ?", (now, user["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "user.delete", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "role": user["role"], "grants_removed": grants,
                                  "sessions_revoked": sessions})
    return {"ok": True, "grants_removed": grants, "sessions_revoked": sessions}


@router.post("/users/{user_id}/reset-password", summary="Set a new password and end all sessions (admin)")
def reset_password(user_id: str, body: ResetPasswordRequest, principal: Principal = Depends(admin_only),
                   conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    problems = password_problems(body.new_password, user["username"])
    if problems:
        raise HTTPException(status_code=400, detail="Password " + "; ".join(problems))
    with transaction(conn) as tx:
        tx.execute("UPDATE users SET password_hash = ?, password_changed_at = ?, failed_logins = 0, locked_until = NULL "
                   "WHERE id = ?", (ctx.passwords.hash(body.new_password), now_iso(), user["id"]))
        revoked = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "user.password_reset", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "sessions_revoked": revoked})
    return {"ok": True, "sessions_revoked": revoked}


@router.post("/users/{user_id}/reset-2fa",
             summary="Turn off someone's two-step sign-in after they lost their phone (admin). Ends their sessions; "
                     "if their role requires it, they set it up again at their next sign-in.")
def reset_two_factor(user_id: str, principal: Principal = Depends(admin_only),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    # Your own is changed from the Account page, which asks for your password and
    # a code - so a stolen administrator session cannot strip its own second factor.
    if user["id"] == principal.id:  # AUTHZ-CHECK[admin-cannot-reset-own-2fa]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "user.2fa_reset", "denied", target_user_id=user["id"],
                             details={"reason": "own_account", "username": user["username"]})
        raise HTTPException(status_code=400, detail="Use the Account page to change your own two-step sign-in")
    with transaction(conn) as tx:
        was_on = bool(user["totp_enabled_at"])
        twofactor.deactivate(tx, user["id"])
        ended = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "user.2fa_reset", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "was_enabled": was_on, "sessions_revoked": ended})
    return {"ok": True, "sessions_revoked": ended}


@router.post("/users/{user_id}/unlock", summary="Clear a sign-in lockout (admin)")
def unlock_user(user_id: str, principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    with transaction(conn) as tx:
        tx.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "user.unlock", "allowed", target_user_id=user["id"],
                         details={"username": user["username"]})
    return {"ok": True}


@router.post("/users/{user_id}/revoke-sessions", summary="Sign a user out everywhere (admin)")
def revoke_sessions(user_id: str, principal: Principal = Depends(admin_only),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    user = _load_user(conn, user_id)
    with transaction(conn) as tx:
        n = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "user.sessions_revoked", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "sessions_revoked": n})
    return {"ok": True, "sessions_revoked": n}


# -------------------------------------------------------------------- audit --
# Quick filters. Each is a fixed SQL fragment (no user input in the text);
# values are bound parameters. They combine with each other and with the
# form filters using AND.
SHARING_ACTIONS = ("access.granted", "access.changed", "access.extended", "access.revoked", "access.bulk_revoked",
                   "link.created", "link.revoked_all", "ai.suggestion.accepted")
PRESETS: dict[str, tuple[str, str, str]] = {
    "denied": ("Denied only", "Refused requests", "a.outcome = 'denied'"),
    "last_24h": ("Last 24 hours", "Events from the last 24 hours", "a.ts >= :since_24h"),
    "downloads": ("Downloads", "Downloads of current and older versions, allowed and refused",
                  "a.action IN ('document.download', 'document.version_download')"),
    "sharing": ("Sharing changes", "Access given, changed, extended or removed; share links made or stopped",
                "a.action IN (" + ", ".join(f"'{x}'" for x in SHARING_ACTIONS) + ")"),
    "expired": ("Expired access", "Access that ran out, and requests refused because access or a link had expired",
                "(a.action = 'access.expired' OR (a.outcome = 'denied' AND "
                "json_extract(a.details, '$.reason') IN ('grant_expired', 'link_expired')))"),
}
PresetName = Literal["denied", "last_24h", "downloads", "sharing", "expired"]

_EVENT_SELECT = """SELECT a.*, d.name AS document_name, t.username AS target_username
                   FROM audit_log a
                   LEFT JOIN documents d ON d.id = a.document_id
                   LEFT JOIN users t ON t.id = a.target_user_id"""


@dataclass
class AuditFilters:
    action: Optional[str] = None
    outcome: Optional[str] = None
    actor: Optional[str] = None
    document_id: Optional[str] = None
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    reason: Optional[str] = None
    session: Optional[str] = None
    preset: list[str] = dc_field(default_factory=list)

    def sql(self) -> tuple[str, dict]:
        clauses, params = ["1 = 1"], {}
        if self.action:
            if self.action.endswith("."):
                clauses.append("a.action LIKE :action ESCAPE '\\'")
                params["action"] = self.action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            else:
                clauses.append("a.action = :action")
                params["action"] = self.action
        if self.outcome:
            clauses.append("a.outcome = :outcome")
            params["outcome"] = self.outcome
        if self.actor:
            clauses.append("a.actor_name = :actor COLLATE NOCASE")
            params["actor"] = self.actor
        if self.document_id:
            clauses.append("a.document_id = :document_id")
            params["document_id"] = self.document_id
        if self.date_from:
            clauses.append("a.ts >= :df")
            params["df"] = f"{self.date_from.isoformat()}T00:00:00.000000Z"
        if self.date_to:
            clauses.append("a.ts <= :dt")
            params["dt"] = f"{self.date_to.isoformat()}T23:59:59.999999Z"
        if self.reason:
            clauses.append("a.outcome = 'denied' AND json_extract(a.details, '$.reason') = :reason")
            params["reason"] = self.reason
        if self.session:
            clauses.append("a.session_ref = :session")
            params["session"] = self.session
        for key in dict.fromkeys(self.preset):  # each preset once, in the order given
            clauses.append(PRESETS[key][2])
            if key == "last_24h":
                params["since_24h"] = iso(utcnow() - timedelta(hours=24))
        return " AND ".join(clauses), params  # fixed fragments only; values are bound parameters

    def as_dict(self) -> dict:
        """The filters in force, for the export's audit event."""
        out = {k: (v.isoformat() if isinstance(v, date) else v) for k, v in asdict(self).items() if v}
        return out


def audit_filters(
    action: Optional[str] = Query(None, max_length=64, description="Exact action, or a prefix ending in '.' e.g. 'access.'"),
    outcome: Optional[Literal["allowed", "denied", "error", "info"]] = None,
    actor: Optional[str] = Query(None, max_length=64, description="Actor username"),
    document_id: Optional[str] = Query(None, max_length=64),
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    reason: Optional[str] = Query(None, max_length=64, pattern=r"^[a-z_]+$",
                                  description="Internal denial reason, e.g. no_grant (denied events only)"),
    session: Optional[str] = Query(None, pattern=r"^[0-9a-f]{16}$", description="Events of one sign-in session"),
    preset: list[PresetName] = Query([], description="Quick filters: " + ", ".join(PRESETS)),
) -> AuditFilters:
    return AuditFilters(action, outcome, actor, document_id, date_from, date_to, reason, session, list(preset))


def _event(row) -> dict:
    e = dict(row)
    try:
        e["details"] = json.loads(e["details"] or "{}")
    except ValueError:
        e["details"] = {"unparsed": e["details"]}
    e["action_label"] = action_label(e["action"])
    e["summary"] = describe(e)
    return e


@router.get("/audit", summary="Search the audit trail (admin). Each event has a plain-language summary.")
def audit_search(
    filters: AuditFilters = Depends(audit_filters),
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=500),
    principal: Principal = Depends(admin_only),
    conn: sqlite3.Connection = Depends(get_db),
):
    where, params = filters.sql()
    total = conn.execute(f"SELECT COUNT(*) AS n FROM audit_log a WHERE {where}", params).fetchone()["n"]
    rows = conn.execute(
        f"{_EVENT_SELECT} WHERE {where} ORDER BY a.seq DESC LIMIT :limit OFFSET :offset",
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    ).fetchall()
    return {"items": [_event(r) for r in rows], "total": total, "page": page, "page_size": page_size,
            "server_time": now_iso()}


@router.get("/audit/options", summary="Values for the audit filters: actions, denial reasons, quick filters (admin)")
def audit_options(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    actions = conn.execute("SELECT action, COUNT(*) AS n FROM audit_log GROUP BY action ORDER BY action").fetchall()
    reasons = conn.execute(
        """SELECT json_extract(details, '$.reason') AS reason, COUNT(*) AS n FROM audit_log
           WHERE outcome = 'denied' GROUP BY reason ORDER BY n DESC, reason""").fetchall()
    return {
        "actions": [{"action": r["action"], "label": action_label(r["action"]), "group": action_group(r["action"]),
                     "count": r["n"]} for r in actions],
        "groups": GROUPS,
        "reasons": [{"reason": r["reason"], "label": reason_text(r["reason"]) or r["reason"], "count": r["n"]}
                    for r in reasons if r["reason"]],
        "presets": [{"key": k, "label": v[0], "description": v[1]} for k, v in PRESETS.items()],
    }


@router.get("/audit/events/{seq}", summary="One audit event in full, its hash check and its session (admin)")
def audit_event(seq: int = PathParam(..., ge=1, le=2 ** 62), principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    row = conn.execute(f"{_EVENT_SELECT} WHERE a.seq = ?", (seq,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such audit event")
    session = None
    if row["session_ref"]:
        total = conn.execute("SELECT COUNT(*) FROM audit_log WHERE session_ref = ?", (row["session_ref"],)).fetchone()[0]
        events = conn.execute(f"{_EVENT_SELECT} WHERE a.session_ref = ? ORDER BY a.seq ASC LIMIT 200",
                              (row["session_ref"],)).fetchall()
        session = {"ref": row["session_ref"], "total": total, "events": [_event(r) for r in events],
                   "truncated": total > len(events)}
    return {"event": _event(row), "integrity": ctx.audit.check_entry(conn, dict(row)), "session": session}


CSV_COLUMNS = ("seq", "time_utc", "actor", "actor_id", "action", "action_label", "outcome", "summary",
               "document_id", "document_name", "target_user", "ip", "user_agent", "session_ref", "details_json",
               "prev_hash", "entry_hash")
# A cell starting with one of these is run as a formula by Excel / LibreOffice
# / Google Sheets. Usernames from failed sign-ins and user agents are typed by
# whoever is attacking, so every cell is neutralised (OWASP "CSV injection").
FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_cell(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_START):  # AUTHZ-CHECK[csv-formula-neutralised]
        return "'" + text
    return text


@router.get("/audit/export", summary="Export the filtered audit trail as CSV (admin). The response carries the "
                                     "file's SHA-256, which is also written to the audit trail.")
def audit_export(filters: AuditFilters = Depends(audit_filters), principal: Principal = Depends(admin_only),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    where, params = filters.sql()
    total = conn.execute(f"SELECT COUNT(*) AS n FROM audit_log a WHERE {where}", params).fetchone()["n"]
    limit = ctx.settings.audit_export_max_rows
    if total > limit:
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "audit.export", "denied",
                             details={"reason": "too_many_rows", "rows": total, "limit": limit,
                                      "filters": filters.as_dict()})
        raise HTTPException(status_code=400, detail=f"{total} events match; one export can hold at most {limit}. "
                                                    "Narrow the filters (for example a date range) and export in parts.")
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for row in conn.execute(f"{_EVENT_SELECT} WHERE {where} ORDER BY a.seq ASC", params):
        e = _event(row)
        writer.writerow([csv_cell(v) for v in (
            e["seq"], e["ts"], e["actor_name"], e["actor_id"], e["action"], e["action_label"], e["outcome"],
            e["summary"], e["document_id"], e["document_name"], e["target_username"], e["ip"], e["user_agent"],
            e["session_ref"], row["details"], e["prev_hash"], e["entry_hash"])])
    body = b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")  # BOM: Excel then reads UTF-8 correctly
    digest = hashlib.sha256(body).hexdigest()
    filename = f"trustvault-audit-{utcnow():%Y%m%d-%H%M%S}.csv"
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "audit.export", "allowed",
                         details={"rows": total, "bytes": len(body), "sha256": digest, "filename": filename,
                                  "format": "csv", "filters": filters.as_dict()})
    return Response(body, media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-SHA256": digest,
        "X-Export-Rows": str(total),
        "Cache-Control": "no-store",
    })


@router.get("/audit/verify", summary="Verify the audit hash chain and external anchors (admin). "
                                     "Reports 'Chain intact (N events)' or the first broken or missing event.")
def audit_verify(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db),
                 ctx: AppContext = Depends(app_ctx)):
    result = ctx.audit.verify(conn).as_dict()
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "audit.verify", "info",
                         details={"ok": result["ok"], "entries_checked": result["entries_checked"],
                                  "first_bad_seq": result["first_bad_seq"], "message": result["message"]})
    return result


@router.get("/alerts", summary="Things worth noticing, derived from the audit trail (admin)")
def alerts(hours: int = Query(24, ge=1, le=24 * 30), principal: Principal = Depends(admin_only),
           conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    verify = ctx.audit.verify(conn).as_dict()
    return {"items": compute_alerts(conn, hours, verify), "integrity": verify}


@router.get("/stats", summary="Dashboard counters (admin)")
def stats(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    now = utcnow()
    since = iso(now.replace(hour=0, minute=0, second=0, microsecond=0))
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]  # noqa: E731
    return {
        "users": q("SELECT COUNT(*) FROM users WHERE is_active = 1"),
        "documents": q("SELECT COUNT(*) FROM documents WHERE deleted_at IS NULL AND purged_at IS NULL"),
        "in_trash": q("SELECT COUNT(*) FROM documents WHERE deleted_at IS NOT NULL AND purged_at IS NULL"),
        "grants": q("SELECT COUNT(*) FROM grants WHERE expires_at > ?", iso(now)),
        "expiring_24h": q("SELECT COUNT(*) FROM grants WHERE expires_at > ? AND expires_at <= ?",
                          iso(now), iso(now + timedelta(hours=24))),
        "links_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ? AND action = 'link.created' "
                         "AND outcome = 'allowed'", since),
        "events_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ?", since),
        "denied_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ? AND outcome = 'denied'", since),
        "downloads_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ? AND outcome = 'allowed' AND action IN "
                             "('document.download','document.version_download')", since),
    }


# ----------------------------------------------------------- access review --
@router.get("/documents", summary="All documents - metadata only, never content (admin)")
def admin_documents(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT d.id, d.name, d.category, d.classification, d.created_at, d.updated_at, d.deleted_at, d.purged_at,
                  u.username AS owner_username, u.is_active AS owner_active,
                  (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.expires_at > :now) AS grants,
                  (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.expires_at <= :now) AS expired_grants,
                  (SELECT COUNT(*) FROM document_versions v WHERE v.document_id = d.id) AS versions
           FROM documents d JOIN users u ON u.id = d.owner_id ORDER BY d.updated_at DESC""",
        {"now": now_iso()},
    ).fetchall()
    return {"items": [{**dict(r), "owner_active": bool(r["owner_active"])} for r in rows]}


@router.get("/documents/{doc_id}/access", summary="Who can reach a document, and until when (admin, metadata only)")
def admin_document_access(doc_id: str, principal: Principal = Depends(admin_only),
                          conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = conn.execute("SELECT id, name, owner_id, access_version FROM documents WHERE id = ?", (doc_id,)).fetchone() \
        if is_valid_id(doc_id) else None
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")
    log_expired_grants(conn, ctx.audit, document_id=doc["id"])
    now = now_iso()
    grants = conn.execute(
        """SELECT g.id, g.permission, g.expires_at, g.created_at, g.source, u.username, u.is_active, u.is_external
           FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = ?
           ORDER BY g.expires_at <= ?, u.username""", (doc["id"], now)).fetchall()
    links = conn.execute(
        """SELECT ts, actor_name, details FROM audit_log WHERE document_id = ? AND action = 'link.created'
           AND outcome = 'allowed' ORDER BY seq DESC LIMIT 20""", (doc["id"],)).fetchall()
    recent_links = []
    for r in links:
        d = json.loads(r["details"])
        recent_links.append({"created_at": r["ts"], "created_by": r["actor_name"], "recipient": d.get("recipient"),
                             "permission": d.get("permission"), "expires_at": d.get("expires_at"),
                             "live": d.get("expires_at", "") > now and d.get("access_version") == doc["access_version"]})
    return {"document": dict(doc), "server_time": now,
            "grants": [{**dict(g), "expired": g["expires_at"] <= now} for g in grants],
            "recent_links": recent_links}


@router.delete("/grants/{grant_id}", summary="Emergency revoke of any grant (admin; can only reduce access)")
def admin_revoke_grant(grant_id: str, principal: Principal = Depends(admin_only),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    grant = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone() if is_valid_id(grant_id) else None
    if grant is None:
        raise HTTPException(status_code=404, detail="Grant not found")
    with transaction(conn) as tx:
        tx.execute("DELETE FROM grants WHERE id = ?", (grant["id"],))
        tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (grant["document_id"],))
        ctx.audit.append(tx, principal.audit_ctx, "access.revoked", "allowed", document_id=grant["document_id"],
                         target_user_id=grant["user_id"],
                         details={"grant_id": grant["id"], "permission": grant["permission"],
                                  "expires_at": grant["expires_at"], "by_admin": True})
    return {"ok": True}


# ------------------------------------------------- unused access (bulk) --
# What counts as *using* a grant: anything that touched the document's content
# or details through it. Read from the audit trail itself, so "unused" is backed
# by the same tamper-evident evidence as everything else.
USE_ACTIONS = ("document.view", "document.preview", "document.preview_page", "document.download",
               "document.version_download", "document.update", "document.version_upload", "link.opened")


def _last_use(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    marks = ", ".join("?" for _ in USE_ACTIONS)
    rows = conn.execute(
        f"""SELECT document_id, actor_id, MAX(ts) AS last FROM audit_log
            WHERE outcome = 'allowed' AND action IN ({marks}) AND document_id IS NOT NULL AND actor_id IS NOT NULL
            GROUP BY document_id, actor_id""", USE_ACTIONS).fetchall()
    return {(r["document_id"], r["actor_id"]): r["last"] for r in rows}


def _idle(grant, last_use: dict, now) -> tuple[str | None, str, int]:
    """(last used, idle since, whole days idle). Idle since = the later of the
    grant's creation and its last use."""
    used = last_use.get((grant["document_id"], grant["user_id"]))
    since = max(grant["created_at"], used or "")
    return used, since, int((now - parse_iso(since)).total_seconds() // 86400)


@router.get("/access-review", summary="Live grants with when each was last used; flags those unused for "
                                      "UNUSED_GRANT_DAYS (30) (admin, metadata only)")
def access_review(unused_days: Optional[int] = Query(None, ge=1, le=366), principal: Principal = Depends(admin_only),
                  conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    days = unused_days or ctx.settings.unused_grant_days
    now = utcnow()
    rows = conn.execute(
        """SELECT g.id, g.document_id, g.user_id, g.permission, g.created_at, g.expires_at, g.source,
                  d.name AS document_name, d.deleted_at, o.username AS owner_username,
                  u.username, u.display_name, u.is_external, u.is_active
           FROM grants g JOIN documents d ON d.id = g.document_id JOIN users u ON u.id = g.user_id
           JOIN users o ON o.id = d.owner_id
           WHERE g.expires_at > ? AND d.purged_at IS NULL""", (iso(now),)).fetchall()
    last_use = _last_use(conn)
    items = []
    for g in rows:
        used, since, idle_days = _idle(g, last_use, now)
        items.append({"grant_id": g["id"], "document_id": g["document_id"], "document_name": g["document_name"],
                      "owner": g["owner_username"], "username": g["username"], "display_name": g["display_name"],
                      "is_external": bool(g["is_external"]), "is_active": bool(g["is_active"]),
                      "permission": g["permission"], "granted_at": g["created_at"], "expires_at": g["expires_at"],
                      "last_used_at": used, "days_unused": idle_days, "in_trash": bool(g["deleted_at"]),
                      "flagged": idle_days >= days})
    items.sort(key=lambda i: (not i["flagged"], -i["days_unused"], i["document_name"].lower(), i["username"].lower()))
    return {"unused_days": days, "server_time": iso(now), "flagged": sum(i["flagged"] for i in items), "items": items}


@router.post("/access-review/revoke", summary="Bulk revoke (admin; only reduces access). Every affected document's "
                                              "access_version goes up once, so its outstanding share links stop too.")
def bulk_revoke(body: BulkRevokeRequest, principal: Principal = Depends(admin_only),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    wanted = [g for g in dict.fromkeys(body.grant_ids) if is_valid_id(g)]
    marks = ", ".join("?" for _ in wanted) or "NULL"
    grants = conn.execute(f"SELECT * FROM grants WHERE id IN ({marks})", wanted).fetchall()  # placeholders only
    if not grants:
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "access.bulk_revoked", "denied",
                             details={"reason": "not_found", "requested": len(body.grant_ids)})
        raise HTTPException(status_code=404, detail="None of those grants exist any more")
    now = utcnow()
    last_use = _last_use(conn)
    documents: list[str] = []
    with transaction(conn) as tx:
        for g in grants:
            used, _, idle_days = _idle(g, last_use, now)
            tx.execute("DELETE FROM grants WHERE id = ?", (g["id"],))
            ctx.audit.append(tx, principal.audit_ctx, "access.revoked", "allowed", document_id=g["document_id"],
                             target_user_id=g["user_id"],
                             details={"grant_id": g["id"], "permission": g["permission"], "expires_at": g["expires_at"],
                                      "by_admin": True, "bulk": True, "last_used_at": used, "unused_days": idle_days})
            if g["document_id"] not in documents:
                documents.append(g["document_id"])
        for doc_id in documents:
            tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc_id,))  # AUTHZ-CHECK[bulk-revoke-kills-links]
        ctx.audit.append(tx, principal.audit_ctx, "access.bulk_revoked", "allowed",
                         details={"grants": len(grants), "documents": documents, "not_found": len(wanted) - len(grants),
                                  "unused_days": ctx.settings.unused_grant_days})
    return {"revoked": len(grants), "documents": len(documents), "not_found": len(body.grant_ids) - len(grants)}


@router.post("/documents/{doc_id}/links/revoke-all",
             summary="Emergency: invalidate every outstanding share link of a document (admin; only reduces access)")
def admin_revoke_links(doc_id: str, principal: Principal = Depends(admin_only),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = conn.execute("SELECT id, access_version FROM documents WHERE id = ?", (doc_id,)).fetchone() \
        if is_valid_id(doc_id) else None
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")
    with transaction(conn) as tx:
        tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "link.revoked_all", "allowed", document_id=doc["id"],
                         details={"from_version": doc["access_version"], "to_version": doc["access_version"] + 1,
                                  "by_admin": True})
    return {"ok": True}
