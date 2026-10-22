"""Administration: users, audit trail, integrity, alerts, access review.

Administrators can see *metadata* (who has access to what, what happened)
but never document content, and can only ever reduce access.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import date
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..alerts import compute_alerts
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, app_ctx, get_db, require_role
from ..models import CreateUserRequest, ResetPasswordRequest, UpdateUserRequest
from ..security import password_problems
from ..utils import clean_line, is_valid_id, iso, new_id, now_iso, utcnow

router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_only = require_role("admin")


def _user_row(r) -> dict:
    d = dict(r)
    d.pop("password_hash", None)
    d["is_active"] = bool(d["is_active"])
    d["is_external"] = bool(d["is_external"])
    return d


# -------------------------------------------------------------------- users --
@router.get("/users", summary="List users (admin)")
def list_users(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT u.*, (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS active_sessions,
                  (SELECT COUNT(*) FROM documents d WHERE d.owner_id = u.id AND d.purged_at IS NULL) AS owned_documents,
                  (SELECT COUNT(*) FROM grants g WHERE g.user_id = u.id) AS grants_held
           FROM users u ORDER BY u.username COLLATE NOCASE"""
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
            # stop working at the same moment.
            revoked = tx.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],)).rowcount
        ctx.audit.append(tx, principal.audit_ctx, "user.update", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "sessions_revoked": revoked,
                                  "changes": {k: {"from": user[k], "to": v} for k, v in changes.items()}})
    return {"ok": True, "changed": sorted(changes), "sessions_revoked": revoked}


@router.delete("/users/{user_id}",
               summary="Delete a user (admin). Final: sign-in, sessions, grants and their share links end; "
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
        links = tx.execute("UPDATE share_links SET revoked_at = COALESCE(revoked_at, ?) WHERE created_by = ?",
                           (now, user["id"])).rowcount
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? "
                   "WHERE suggested_user_id = ? AND status = 'pending'", (now, user["id"]))
        tx.execute("UPDATE users SET is_active = 0, deleted_at = ?, failed_logins = 0, locked_until = NULL "
                   "WHERE id = ?", (now, user["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "user.delete", "allowed", target_user_id=user["id"],
                         details={"username": user["username"], "role": user["role"], "grants_removed": grants,
                                  "sessions_revoked": sessions, "links_revoked": links})
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
@router.get("/audit", summary="Search the audit trail (admin)")
def audit_search(
    action: Optional[str] = Query(None, max_length=64, description="Exact action or prefix ending in '.' e.g. 'permission.'"),
    outcome: Optional[Literal["allowed", "denied", "error", "info"]] = None,
    actor: Optional[str] = Query(None, max_length=64, description="Actor username"),
    document_id: Optional[str] = Query(None, max_length=64),
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=500),
    principal: Principal = Depends(admin_only),
    conn: sqlite3.Connection = Depends(get_db),
):
    clauses, params = ["1 = 1"], {}
    if action:
        if action.endswith("."):
            clauses.append("a.action LIKE :action ESCAPE '\\'")
            params["action"] = action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        else:
            clauses.append("a.action = :action")
            params["action"] = action
    if outcome:
        clauses.append("a.outcome = :outcome")
        params["outcome"] = outcome
    if actor:
        clauses.append("a.actor_name = :actor COLLATE NOCASE")
        params["actor"] = actor
    if document_id:
        clauses.append("a.document_id = :document_id")
        params["document_id"] = document_id
    if date_from:
        clauses.append("a.ts >= :df")
        params["df"] = f"{date_from.isoformat()}T00:00:00.000000Z"
    if date_to:
        clauses.append("a.ts <= :dt")
        params["dt"] = f"{date_to.isoformat()}T23:59:59.999999Z"
    where = " AND ".join(clauses)  # fixed fragments only; values are bound parameters
    total = conn.execute(f"SELECT COUNT(*) AS n FROM audit_log a WHERE {where}", params).fetchone()["n"]
    rows = conn.execute(
        f"""SELECT a.*, d.name AS document_name FROM audit_log a LEFT JOIN documents d ON d.id = a.document_id
            WHERE {where} ORDER BY a.seq DESC LIMIT :limit OFFSET :offset""",
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    ).fetchall()
    items = [{**dict(r), "details": json.loads(r["details"])} for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/audit/verify", summary="Verify the audit hash chain and external anchors (admin)")
def audit_verify(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db),
                 ctx: AppContext = Depends(app_ctx)):
    result = ctx.audit.verify(conn).as_dict()
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "audit.verify", "info",
                         details={"ok": result["ok"], "entries_checked": result["entries_checked"],
                                  "first_bad_seq": result["first_bad_seq"]})
    return result


@router.get("/alerts", summary="Things worth noticing, derived from the audit trail (admin)")
def alerts(hours: int = Query(24, ge=1, le=24 * 30), principal: Principal = Depends(admin_only),
           conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    verify = ctx.audit.verify(conn).as_dict()
    return {"items": compute_alerts(conn, hours, verify), "integrity": verify}


@router.get("/stats", summary="Dashboard counters (admin)")
def stats(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    since = iso(utcnow().replace(hour=0, minute=0, second=0, microsecond=0))
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]  # noqa: E731
    return {
        "users": q("SELECT COUNT(*) FROM users WHERE is_active = 1"),
        "documents": q("SELECT COUNT(*) FROM documents WHERE deleted_at IS NULL AND purged_at IS NULL"),
        "in_trash": q("SELECT COUNT(*) FROM documents WHERE deleted_at IS NOT NULL AND purged_at IS NULL"),
        "grants": q("SELECT COUNT(*) FROM grants"),
        "active_links": q("SELECT COUNT(*) FROM share_links WHERE revoked_at IS NULL AND expires_at > ? "
                          "AND use_count < max_uses", now_iso()),
        "events_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ?", since),
        "denied_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ? AND outcome = 'denied'", since),
        "downloads_today": q("SELECT COUNT(*) FROM audit_log WHERE ts >= ? AND outcome = 'allowed' AND action IN "
                             "('document.download','document.version_download','share_link.download')", since),
    }


# ----------------------------------------------------------- access review --
@router.get("/documents", summary="All documents - metadata only, never content (admin)")
def admin_documents(principal: Principal = Depends(admin_only), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT d.id, d.name, d.category, d.created_at, d.updated_at, d.deleted_at, d.purged_at,
                  u.username AS owner_username, u.is_active AS owner_active,
                  (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id) AS grants,
                  (SELECT COUNT(*) FROM share_links l WHERE l.document_id = d.id AND l.revoked_at IS NULL
                     AND l.expires_at > :now AND l.use_count < l.max_uses) AS active_links,
                  (SELECT COUNT(*) FROM document_versions v WHERE v.document_id = d.id) AS versions
           FROM documents d JOIN users u ON u.id = d.owner_id ORDER BY d.updated_at DESC""",
        {"now": now_iso()},
    ).fetchall()
    return {"items": [{**dict(r), "owner_active": bool(r["owner_active"])} for r in rows]}


@router.get("/documents/{doc_id}/access", summary="Who can reach a document (admin, metadata only)")
def admin_document_access(doc_id: str, principal: Principal = Depends(admin_only),
                          conn: sqlite3.Connection = Depends(get_db)):
    doc = conn.execute("SELECT id, name, owner_id FROM documents WHERE id = ?", (doc_id,)).fetchone() \
        if is_valid_id(doc_id) else None
    if doc is None:
        raise HTTPException(status_code=404, detail="Document not found")
    grants = conn.execute(
        """SELECT g.id, g.permission, g.expires_at, g.created_at, g.source, u.username, u.is_active, u.is_external
           FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = ?""", (doc["id"],)).fetchall()
    links = conn.execute(
        """SELECT id, label, created_at, expires_at, max_uses, use_count, revoked_at FROM share_links
           WHERE document_id = ? ORDER BY created_at DESC""", (doc["id"],)).fetchall()
    return {"document": dict(doc), "grants": [dict(g) for g in grants], "share_links": [dict(link) for link in links]}


@router.delete("/grants/{grant_id}", summary="Emergency revoke of any grant (admin; can only reduce access)")
def admin_revoke_grant(grant_id: str, principal: Principal = Depends(admin_only),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    grant = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone() if is_valid_id(grant_id) else None
    if grant is None:
        raise HTTPException(status_code=404, detail="Grant not found")
    with transaction(conn) as tx:
        tx.execute("DELETE FROM grants WHERE id = ?", (grant["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "permission.revoke", "allowed", document_id=grant["document_id"],
                         target_user_id=grant["user_id"],
                         details={"grant_id": grant["id"], "permission": grant["permission"], "by_admin": True})
    return {"ok": True}


@router.post("/share-links/{link_id}/revoke", summary="Emergency revoke of any share link (admin)")
def admin_revoke_link(link_id: str, principal: Principal = Depends(admin_only),
                      conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    link = conn.execute("SELECT * FROM share_links WHERE id = ?", (link_id,)).fetchone() if is_valid_id(link_id) else None
    if link is None:
        raise HTTPException(status_code=404, detail="Link not found")
    with transaction(conn) as tx:
        tx.execute("UPDATE share_links SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), link["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "share_link.revoke", "allowed", document_id=link["document_id"],
                         details={"link_id": link["id"], "by_admin": True})
    return {"ok": True}
