"""Sharing: per-person grants, external share links, access suggestions and
the user directory owners pick people from."""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..authz import Action, authorize
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, app_ctx, current_principal, get_db, require_role
from ..models import GrantRequest, ShareLinkRequest
from ..security import hash_token, new_token
from ..suggestions import suggest_readers
from ..utils import clean_line, is_valid_id, iso, new_id, now_iso, utcnow

router = APIRouter(tags=["sharing"])

MAX_GRANT_DAYS = 366


# ---------------------------------------------------------------- directory --
@router.get("/api/users/directory", summary="People that can be granted access (role: owner)")
def user_directory(principal: Principal = Depends(require_role("owner")), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT id, username, display_name, is_external FROM users
           WHERE is_active = 1 AND role != 'admin' AND id != ? ORDER BY display_name COLLATE NOCASE""",
        (principal.id,),
    ).fetchall()
    return {"items": [{**dict(r), "is_external": bool(r["is_external"])} for r in rows]}


# ------------------------------------------------------------------- grants --
@router.get("/api/documents/{doc_id}/grants", summary="Who has access (owner only)")
def list_grants(doc_id: str, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    rows = conn.execute(
        """SELECT g.id, g.permission, g.created_at, g.expires_at, g.source,
                  u.id AS user_id, u.username, u.display_name, u.is_external, u.is_active,
                  gb.username AS granted_by
           FROM grants g JOIN users u ON u.id = g.user_id JOIN users gb ON gb.id = g.granted_by
           WHERE g.document_id = ? ORDER BY u.display_name COLLATE NOCASE""",
        (doc["id"],),
    ).fetchall()
    now = now_iso()
    items = []
    for r in rows:
        item = dict(r)
        item["is_external"] = bool(item["is_external"])
        item["is_active"] = bool(item["is_active"])
        item["expired"] = bool(item["expires_at"] and item["expires_at"] <= now)
        items.append(item)
    return {"items": items}


@router.post("/api/documents/{doc_id}/grants", status_code=201,
             summary="Grant or change a person's access (owner only)")
def grant_access(doc_id: str, body: GrantRequest, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)

    def refuse(status: int, message: str, reason: str, target_id: str | None = None):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "permission.grant", "denied", document_id=doc["id"],
                             target_user_id=target_id, details={"reason": reason, "username": body.username[:64]})
        raise HTTPException(status_code=status, detail=message)

    target = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    if target is None:
        refuse(404, "No such user", "unknown_user")
    if target["id"] == doc["owner_id"]:
        refuse(400, "The owner already has full access", "target_is_owner", target["id"])
    if not target["is_active"]:  # AUTHZ-CHECK[grant-target-must-be-active]
        refuse(400, "That account is deactivated", "target_inactive", target["id"])
    if target["role"] == "admin":  # AUTHZ-CHECK[grant-target-not-admin]
        refuse(400, "Administrators cannot be given document access (separation of duties)", "target_admin", target["id"])

    expires_at = None
    if body.expires_at is not None:
        exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
        if exp <= utcnow():
            raise HTTPException(status_code=400, detail="Expiry must be in the future")
        if exp > utcnow() + timedelta(days=MAX_GRANT_DAYS):
            raise HTTPException(status_code=400, detail=f"Expiry must be within {MAX_GRANT_DAYS} days")
        expires_at = iso(exp)

    suggestion = None
    if body.suggestion_id is not None:
        suggestion = conn.execute("SELECT * FROM suggestions WHERE id = ?", (body.suggestion_id,)).fetchone()
        mismatch = (suggestion is None or suggestion["document_id"] != doc["id"]
                    or suggestion["suggested_user_id"] != target["id"] or suggestion["status"] != "pending")
        if mismatch:  # AUTHZ-CHECK[suggestion-matches-document]
            refuse(400, "Suggestion does not match this document and person, or was already decided",
                   "suggestion_mismatch", target["id"])

    existing = conn.execute("SELECT * FROM grants WHERE document_id = ? AND user_id = ?",
                            (doc["id"], target["id"])).fetchone()
    source = "suggestion" if suggestion else "manual"
    details = {"permission": body.permission, "expires_at": expires_at, "target_username": target["username"],
               "target_external": bool(target["is_external"]), "source": source}
    with transaction(conn) as tx:
        if existing:
            tx.execute("UPDATE grants SET permission = ?, expires_at = ?, granted_by = ?, source = ? WHERE id = ?",
                       (body.permission, expires_at, principal.id, source, existing["id"]))
            grant_id, action = existing["id"], "permission.change"
            details["previous"] = {"permission": existing["permission"], "expires_at": existing["expires_at"]}
        else:
            grant_id, action = new_id(), "permission.grant"
            tx.execute(
                """INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (grant_id, doc["id"], target["id"], body.permission, principal.id, now_iso(), expires_at, source),
            )
        if suggestion:
            tx.execute("UPDATE suggestions SET status = 'accepted', decided_at = ? WHERE id = ?",
                       (now_iso(), suggestion["id"]))
            details["suggestion_id"] = suggestion["id"]
            details["suggested_permission"] = suggestion["permission"]
            ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.accepted", "allowed", document_id=doc["id"],
                             target_user_id=target["id"],
                             details={"suggestion_id": suggestion["id"], "decided_permission": body.permission,
                                      "decided_by": principal.user["username"]})
        details["grant_id"] = grant_id
        ctx.audit.append(tx, principal.audit_ctx, action, "allowed", document_id=doc["id"],
                         target_user_id=target["id"], details=details)
    return {"id": grant_id, "permission": body.permission, "expires_at": expires_at, "source": source}


@router.delete("/api/documents/{doc_id}/grants/{grant_id}", summary="Revoke a grant (owner only). Immediate.")
def revoke_grant(doc_id: str, grant_id: str, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    grant = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone() if is_valid_id(grant_id) else None
    if grant is None or grant["document_id"] != doc["id"]:  # AUTHZ-CHECK[grant-belongs-to-document]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "permission.revoke", "denied", document_id=doc["id"],
                             details={"reason": "grant_not_in_document", "grant_id": grant_id[:64]})
        raise HTTPException(status_code=404, detail="Grant not found")
    target = conn.execute("SELECT username FROM users WHERE id = ?", (grant["user_id"],)).fetchone()
    with transaction(conn) as tx:
        tx.execute("DELETE FROM grants WHERE id = ?", (grant["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "permission.revoke", "allowed", document_id=doc["id"],
                         target_user_id=grant["user_id"],
                         details={"grant_id": grant["id"], "permission": grant["permission"],
                                  "target_username": target["username"]})
    return {"ok": True}


# -------------------------------------------------------------- share links --
def _link_public(row: dict) -> dict:
    now = now_iso()
    status = "active"
    if row["revoked_at"]:
        status = "revoked"
    elif row["expires_at"] <= now:
        status = "expired"
    elif row["use_count"] >= row["max_uses"]:
        status = "used_up"
    return {"id": row["id"], "label": row["label"], "created_at": row["created_at"], "expires_at": row["expires_at"],
            "max_uses": row["max_uses"], "use_count": row["use_count"], "revoked_at": row["revoked_at"],
            "status": status}


@router.get("/api/documents/{doc_id}/share-links", summary="External share links (owner only)")
def list_links(doc_id: str, principal: Principal = Depends(current_principal),
               conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    rows = conn.execute("SELECT * FROM share_links WHERE document_id = ? ORDER BY created_at DESC", (doc["id"],)).fetchall()
    return {"items": [_link_public(dict(r)) for r in rows]}


@router.post("/api/documents/{doc_id}/share-links", status_code=201,
             summary="Create a read-only, expiring external link (owner only). The token is shown once.")
def create_link(doc_id: str, body: ShareLinkRequest, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    if body.expires_in_hours > ctx.settings.share_link_max_hours:
        raise HTTPException(status_code=400, detail=f"Links can live at most {ctx.settings.share_link_max_hours} hours")
    if body.max_uses > ctx.settings.share_link_max_uses:
        raise HTTPException(status_code=400, detail=f"Links allow at most {ctx.settings.share_link_max_uses} downloads")
    token = new_token()
    link_id = new_id()
    expires_at = iso(utcnow() + timedelta(hours=body.expires_in_hours))
    label = clean_line(body.label, 100)
    with transaction(conn) as tx:
        tx.execute(
            """INSERT INTO share_links (id, document_id, token_hash, created_by, created_at, expires_at, max_uses, label)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (link_id, doc["id"], hash_token(token), principal.id, now_iso(), expires_at, body.max_uses, label),
        )
        ctx.audit.append(tx, principal.audit_ctx, "share_link.create", "allowed", document_id=doc["id"],
                         details={"link_id": link_id, "expires_at": expires_at, "max_uses": body.max_uses,
                                  "label": label})
    # The token lives in the URL *fragment*: browsers never send it to the
    # server in the page request, so it stays out of access logs and Referer.
    return {"id": link_id, "token": token, "path": f"/share#{token}", "expires_at": expires_at,
            "max_uses": body.max_uses}


@router.delete("/api/documents/{doc_id}/share-links/{link_id}", summary="Revoke a share link (owner only). Immediate.")
def revoke_link(doc_id: str, link_id: str, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    link = conn.execute("SELECT * FROM share_links WHERE id = ?", (link_id,)).fetchone() if is_valid_id(link_id) else None
    if link is None or link["document_id"] != doc["id"]:  # AUTHZ-CHECK[link-belongs-to-document]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "share_link.revoke", "denied", document_id=doc["id"],
                             details={"reason": "link_not_in_document", "link_id": link_id[:64]})
        raise HTTPException(status_code=404, detail="Link not found")
    with transaction(conn) as tx:
        tx.execute("UPDATE share_links SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), link["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "share_link.revoke", "allowed", document_id=doc["id"],
                         details={"link_id": link["id"]})
    return {"ok": True}


# -------------------------------------------------------------- suggestions --
@router.get("/api/documents/{doc_id}/suggestions",
            summary="Suggest people who may need view access (owner only). Never grants anything.")
def get_suggestions(doc_id: str, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    proposals = suggest_readers(conn, principal.id, doc)
    now = now_iso()
    with transaction(conn) as tx:
        # Older undecided suggestions for this document are superseded.
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? WHERE document_id = ? AND status = 'pending'",
                   (now, doc["id"]))
        for p in proposals:
            p["suggestion_id"] = new_id()
            tx.execute(
                """INSERT INTO suggestions (id, document_id, owner_id, suggested_user_id, permission, score, reasons,
                                            status, created_at) VALUES (?, ?, ?, ?, 'view', ?, ?, 'pending', ?)""",
                (p["suggestion_id"], doc["id"], principal.id, p["user_id"], p["score"], json.dumps(p["reasons"]), now),
            )
        ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.generated", "info", document_id=doc["id"],
                         details={"engine": "local-heuristic-v1",
                                  "suggestions": [{"suggestion_id": p["suggestion_id"], "username": p["username"],
                                                   "permission": p["permission"], "score": p["score"]}
                                                  for p in proposals]})
    return {"items": proposals,
            "note": "Suggestions never change access. Confirm a person to give them view-only access (you can choose a higher level instead)."}


@router.post("/api/documents/{doc_id}/suggestions/{suggestion_id}/dismiss", summary="Dismiss a suggestion (owner only)")
def dismiss_suggestion(doc_id: str, suggestion_id: str, principal: Principal = Depends(current_principal),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = authorize(conn, ctx.audit, principal.audit_ctx, principal.user, doc_id, Action.SHARE)
    sug = conn.execute("SELECT * FROM suggestions WHERE id = ?", (suggestion_id,)).fetchone() \
        if is_valid_id(suggestion_id) else None
    if sug is None or sug["document_id"] != doc["id"]:  # AUTHZ-CHECK[dismiss-suggestion-belongs-to-document]
        raise HTTPException(status_code=404, detail="Suggestion not found")
    if sug["status"] != "pending":
        raise HTTPException(status_code=409, detail="Suggestion already decided")
    with transaction(conn) as tx:
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? WHERE id = ?", (now_iso(), sug["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.dismissed", "info", document_id=doc["id"],
                         target_user_id=sug["suggested_user_id"], details={"suggestion_id": sug["id"]})
    return {"ok": True}
