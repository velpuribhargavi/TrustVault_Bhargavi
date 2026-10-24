"""Documents: upload, search, metadata, download, versions, edit, delete.

Every endpoint that touches one document starts with ``require_access()``
(see authz.py) - the one shared check. The content endpoints (metadata,
preview, page images, downloads) also accept a share link in the
X-Link-Token header.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import date
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response

from ..authz import Action, Decision, require_access, visible_documents_clause
from ..context import AppContext
from ..crypto import IntegrityError
from ..db import transaction
from ..deps import Principal, app_ctx, current_principal, get_db, link_token, require_role
from .. import classification as labels
from ..models import ClassificationRequest, DocumentUpdate
from ..preview import OFFICE_TYPES, NoSuchPage, PreviewError, extract_text, kind_for, page_count, render_page
from ..services import content_disposition, crypto_shred_document, get_version, read_version, store_version
from ..utils import new_id, now_iso, utcnow
from ..validation import (ValidationError, validate_category, validate_description, validate_doc_name,
                          validate_upload)

router = APIRouter(prefix="/api/documents", tags=["documents"])

# Audit detail fields only administrators may see (why a request was refused,
# what was probed). Removed from the owner's per-document activity view.
INTERNAL_DETAIL_KEYS = ("reason", "requested_id", "requested_version", "link_id", "error")

SORTS = {
    "updated_desc": "d.updated_at DESC",
    "created_desc": "d.created_at DESC",
    "created_asc": "d.created_at ASC",
    "name_asc": "d.name COLLATE NOCASE ASC",
    "name_desc": "d.name COLLATE NOCASE DESC",
}


def _read_upload(file: UploadFile, ctx: AppContext) -> bytes:
    data = file.file.read(ctx.settings.max_upload_bytes + 1)
    if len(data) > ctx.settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    return data


def _reject_upload(conn, ctx: AppContext, principal: Principal, action: str, document_id: str | None,
                   filename: str | None, error: Exception) -> None:
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, action, "denied", document_id=document_id,
                         details={"reason": "validation", "error": str(error), "filename": (filename or "")[:200]})
    raise HTTPException(status_code=400, detail=str(error))


def _doc_summary(row: dict) -> dict:
    return {
        "id": row["id"], "name": row["name"], "category": row["category"], "description": row["description"],
        "classification": row.get("classification") or labels.DEFAULT,
        "owner": {"id": row["owner_id"], "username": row.get("owner_username"),
                  "display_name": row.get("owner_display_name")},
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "deleted_at": row.get("deleted_at"),
        "current_version": {"id": row.get("current_version_id"), "version_no": row.get("version_no"),
                            "extension": row.get("extension"), "size_bytes": row.get("size_bytes")},
        "my_permission": row.get("my_permission"),
        "my_access_expires_at": row.get("my_access_expires_at"),
    }


def _access_details(d: Decision) -> dict:
    """How the caller reached the document - recorded with every allowed access."""
    out = {"permission": d.permission, "via": d.via}
    if d.via == "link" and d.link is not None:
        out["link_id"] = d.link.link_id
    return out


# ------------------------------------------------------------------ upload --
@router.post("", status_code=201, summary="Upload a new document (role: owner)")
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    category: str = Form(...),
    name: str = Form(""),
    description: str = Form(""),
    classification: str = Form("internal"),
    principal: Principal = Depends(require_role("owner")),
    conn: sqlite3.Connection = Depends(get_db),
    ctx: AppContext = Depends(app_ctx),
):
    data = _read_upload(file, ctx)
    try:
        safe_name, file_type = validate_upload(file.filename or "", data, ctx.settings.max_upload_bytes)
        category = validate_category(category)
        display_name = validate_doc_name(name) if name.strip() else safe_name
        description = validate_description(description)
        label = labels.validate(classification)
    except (ValidationError, labels.BadLabel) as exc:
        _reject_upload(conn, ctx, principal, "document.upload", None, file.filename, exc)

    doc_id = new_id()
    now = now_iso()
    with transaction(conn) as tx:
        tx.execute(
            """INSERT INTO documents (id, owner_id, name, category, description, classification, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (doc_id, principal.id, display_name, category, description, label, now, now),
        )
        version = store_version(tx, ctx, document_id=doc_id, filename=safe_name, file_type=file_type,
                                data=data, uploaded_by=principal.id)
        ctx.audit.append(tx, principal.audit_ctx, "document.upload", "allowed", document_id=doc_id,
                         details={"name": display_name, "filename": safe_name, "category": category,
                                  "classification": label, "size": version["size_bytes"], "sha256": version["sha256"],
                                  "version_id": version["id"]})
    return {"id": doc_id, "name": display_name, "category": category, "classification": label,
            "version": version["version_no"], "sha256": version["sha256"]}


# ------------------------------------------------------------------ search --
@router.get("", summary="Search documents I can access (any signed-in user; admins see none)")
def search_documents(
    q: Optional[str] = Query(None, max_length=200, description="Substring of the document name"),
    owner: Optional[str] = Query(None, max_length=64, description="Owner username (exact)"),
    category: Optional[str] = Query(None, max_length=40),
    date_from: Optional[date] = Query(None, description="Uploaded on or after (YYYY-MM-DD)"),
    date_to: Optional[date] = Query(None, description="Uploaded on or before (YYYY-MM-DD)"),
    scope: Literal["all", "mine", "shared"] = "all",
    sort: Literal["updated_desc", "created_desc", "created_asc", "name_asc", "name_desc"] = "updated_desc",
    page: int = Query(1, ge=1, le=10_000),
    page_size: int = Query(25, ge=1, le=100),
    principal: Principal = Depends(current_principal),
    conn: sqlite3.Connection = Depends(get_db),
):
    scope_sql = visible_documents_clause(principal.user)
    if scope_sql is None:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}
    params: dict = {"uid": principal.id, "now": now_iso()}
    clauses = ["d.purged_at IS NULL"]
    clauses.append(scope_sql)  # AUTHZ-CHECK[search-scoped-to-access]
    clauses.append("d.deleted_at IS NULL")  # AUTHZ-CHECK[search-hides-trash]
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("d.name LIKE :q ESCAPE '\\'")
        params["q"] = f"%{escaped}%"
    if owner:
        clauses.append("u.username = :owner COLLATE NOCASE")
        params["owner"] = owner
    if category:
        clauses.append("d.category = :category")
        params["category"] = category.lower()
    if date_from:
        clauses.append("d.created_at >= :date_from")
        params["date_from"] = f"{date_from.isoformat()}T00:00:00.000000Z"
    if date_to:
        clauses.append("d.created_at <= :date_to")
        params["date_to"] = f"{date_to.isoformat()}T23:59:59.999999Z"
    if scope == "mine":
        clauses.append("d.owner_id = :uid")
    elif scope == "shared":
        clauses.append("d.owner_id != :uid")
    # Only fixed SQL fragments are joined here; every user value is a bound parameter.
    base = ("FROM documents d JOIN users u ON u.id = d.owner_id "
            "LEFT JOIN document_versions v ON v.id = d.current_version_id "
            f"WHERE {' AND '.join(clauses)}")
    total = conn.execute(f"SELECT COUNT(*) AS n {base}", params).fetchone()["n"]
    params.update(limit=page_size, offset=(page - 1) * page_size)
    rows = conn.execute(
        f"""SELECT d.*, u.username AS owner_username, u.display_name AS owner_display_name,
                   v.version_no, v.extension, v.size_bytes,
                   CASE WHEN d.owner_id = :uid THEN 'owner'
                        ELSE (SELECT g.permission FROM grants g WHERE g.document_id = d.id AND g.user_id = :uid)
                   END AS my_permission,
                   CASE WHEN d.owner_id = :uid THEN NULL
                        ELSE (SELECT g.expires_at FROM grants g WHERE g.document_id = d.id AND g.user_id = :uid)
                   END AS my_access_expires_at
            {base}
            ORDER BY {SORTS[sort]} LIMIT :limit OFFSET :offset""",
        params,
    ).fetchall()
    return {"items": [_doc_summary(dict(r)) for r in rows], "total": total, "page": page, "page_size": page_size,
            "server_time": params["now"]}


@router.get("/trash", summary="My deleted documents (role: owner)")
def list_trash(principal: Principal = Depends(require_role("owner")), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT d.*, u.username AS owner_username, u.display_name AS owner_display_name,
                  v.version_no, v.extension, v.size_bytes, 'owner' AS my_permission
           FROM documents d JOIN users u ON u.id = d.owner_id
           LEFT JOIN document_versions v ON v.id = d.current_version_id
           WHERE d.owner_id = ? AND d.deleted_at IS NOT NULL AND d.purged_at IS NULL
           ORDER BY d.deleted_at DESC""",
        (principal.id,),
    ).fetchall()
    return {"items": [_doc_summary(dict(r)) for r in rows]}


# ------------------------------------------------------------- one document --
@router.get("/{doc_id}", summary="Document metadata and versions (owner, live grant, or a share link for you)")
def get_document(doc_id: str, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx),
                 link: Optional[str] = Depends(link_token)):
    d = require_access(conn, ctx, principal, doc_id, Action.VIEW, link_token=link, audit_action="document.view")
    doc = d.doc
    owner = conn.execute("SELECT username, display_name FROM users WHERE id = ?", (doc["owner_id"],)).fetchone()
    versions = conn.execute(
        """SELECT v.id, v.version_no, v.original_filename, v.extension, v.size_bytes, v.sha256, v.created_at,
                  u.username AS uploaded_by
           FROM document_versions v JOIN users u ON u.id = v.uploaded_by
           WHERE v.document_id = ? ORDER BY v.version_no DESC""",
        (doc["id"],),
    ).fetchall()
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "document.view", "allowed", document_id=doc["id"],
                         details=_access_details(d))
    return {
        "id": doc["id"], "name": doc["name"], "category": doc["category"], "description": doc["description"],
        "classification": doc["classification"],
        "owner": {"id": doc["owner_id"], "username": owner["username"], "display_name": owner["display_name"]},
        "created_at": doc["created_at"], "updated_at": doc["updated_at"], "deleted_at": doc["deleted_at"],
        "current_version_id": doc["current_version_id"], "my_permission": d.permission,
        "access_via": d.via, "access_expires_at": d.access_expires_at, "server_time": now_iso(),
        "versions": [dict(v) for v in versions],
    }


def _send_version(conn, ctx: AppContext, principal: Principal, d: Decision, version: dict, action: str) -> Response:
    doc = d.doc
    try:
        data = read_version(ctx, version)
    except IntegrityError as exc:
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, action, "error", document_id=doc["id"],
                             details={"reason": "integrity", "error": str(exc), "version_id": version["id"]})
        raise HTTPException(status_code=500, detail="Stored file failed its integrity check; administrators have been alerted")
    # Audit BEFORE the bytes leave: if the audit write fails, nothing is sent.
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, action, "allowed", document_id=doc["id"],
                         details={"version_id": version["id"], "version_no": version["version_no"],
                                  "sha256": version["sha256"], "size": version["size_bytes"], **_access_details(d)})
    return download_response(data, version)


def download_response(data: bytes, version: dict) -> Response:
    return Response(
        content=data,
        media_type=version["mime_type"],
        headers={
            # Always a download, never rendered on our origin (stops stored XSS
            # through uploaded files), and sandboxed even if a browser tries.
            "Content-Disposition": content_disposition(version["original_filename"]),
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Content-SHA256": version["sha256"],
        },
    )


@router.get("/{doc_id}/download",
            summary="Download the original file, current version (owner, download/edit grant or download link - NOT view)")
def download_current(doc_id: str, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx),
                     link: Optional[str] = Depends(link_token)):
    d = require_access(conn, ctx, principal, doc_id, Action.DOWNLOAD, link_token=link, audit_action="document.download")
    version = get_version(conn, d.doc["current_version_id"])
    return _send_version(conn, ctx, principal, d, version, "document.download")


@router.get("/{doc_id}/versions/{version_id}/download",
            summary="Download a specific version (owner, download/edit grant or download link - NOT view)")
def download_version(doc_id: str, version_id: str, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx),
                     link: Optional[str] = Depends(link_token)):
    # The version must belong to the document being checked - otherwise access
    # to one document would open every version id in the system. check_access
    # tests that too (reason version_not_in_document).
    d = require_access(conn, ctx, principal, doc_id, Action.DOWNLOAD, version_id=version_id, link_token=link,
                       audit_action="document.version_download")
    return _send_version(conn, ctx, principal, d, d.version, "document.version_download")


def _watermark_for(principal: Principal, doc: dict) -> str:
    """Tiled over every rendered page: who it was rendered for and when - and
    CONFIDENTIAL in front for a Confidential document."""
    return (f"{labels.watermark_prefix(doc['classification'])}{principal.user['username']} · "
            f"{utcnow().strftime('%Y-%m-%d %H:%M UTC')} · TrustVault view-only")


def _current_plaintext(conn, ctx: AppContext, principal: Principal, doc: dict, action: str) -> tuple[dict, bytes]:
    version = get_version(conn, doc["current_version_id"])
    try:
        return version, read_version(ctx, version)
    except IntegrityError as exc:
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, action, "error", document_id=doc["id"],
                             details={"reason": "integrity", "error": str(exc), "version_id": version["id"]})
        raise HTTPException(status_code=500, detail="Stored file failed its integrity check; administrators have been alerted")


def _render_source(ctx: AppContext, version: dict, data: bytes) -> tuple[str, bytes, str]:
    """What to render: Office files become PDF through LibreOffice when it is
    installed (page images, like a PDF); otherwise their text is extracted."""
    if version["extension"] in OFFICE_TYPES and ctx.office.available:
        try:
            return "pdf", ctx.office.pdf_for(version["id"], version["extension"], data), "libreoffice"
        except PreviewError:
            pass  # conversion failed or timed out: fall back to text
    return version["extension"], data, "builtin"


@router.get("/{doc_id}/preview",
            summary="Open in the browser (owner, live grant or a share link for you). Never returns the original file.")
def preview_document(doc_id: str, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx),
                     link: Optional[str] = Depends(link_token)):
    d = require_access(conn, ctx, principal, doc_id, Action.VIEW, link_token=link, audit_action="document.preview")
    doc = d.doc
    version, data = _current_plaintext(conn, ctx, principal, doc, "document.preview")
    watermark = _watermark_for(principal, doc)
    try:
        extension, source, renderer = _render_source(ctx, version, data)
        kind = kind_for(extension)
        if kind == "pages":
            result = {"kind": "pages", "pages": page_count(extension, source)}
        else:
            text, truncated = extract_text(extension, source)
            result = {"kind": "text", "text": text, "truncated": truncated}
    except PreviewError as exc:
        raise HTTPException(status_code=422, detail=f"This document cannot be previewed: {exc}")
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "document.preview", "allowed", document_id=doc["id"],
                         details={"version_id": version["id"], "kind": result["kind"], "renderer": renderer,
                                  "pages": result.get("pages"), **_access_details(d)})
    return {**result, "watermark": watermark, "classification": doc["classification"],
            "filename": version["original_filename"], "renderer": renderer,
            "version_no": version["version_no"], "can_download": d.permission != "view",
            "access_via": d.via, "access_expires_at": d.access_expires_at}


@router.get("/{doc_id}/preview/pages/{page_no}",
            summary="One rendered, watermarked page as PNG (owner, live grant or a share link for you)")
def preview_page(doc_id: str, page_no: int, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx),
                 link: Optional[str] = Depends(link_token)):
    d = require_access(conn, ctx, principal, doc_id, Action.VIEW, link_token=link, audit_action="document.preview_page")
    doc = d.doc
    version, data = _current_plaintext(conn, ctx, principal, doc, "document.preview_page")
    try:
        extension, source, _ = _render_source(ctx, version, data)
        png = render_page(extension, source, page_no, _watermark_for(principal, doc))
    except NoSuchPage:
        raise HTTPException(status_code=404, detail="No such page")
    except PreviewError as exc:
        raise HTTPException(status_code=422, detail=f"This document cannot be previewed: {exc}")
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "document.preview_page", "allowed", document_id=doc["id"],
                         details={"version_id": version["id"], "page": page_no, **_access_details(d)})
    return Response(content=png, media_type="image/png", headers={
        "Content-Disposition": 'inline; filename="preview.png"',
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


@router.post("/{doc_id}/versions", status_code=201, summary="Upload a new version (owner or edit grant)")
def upload_version(doc_id: str, file: UploadFile = File(...), principal: Principal = Depends(current_principal),
                   conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.EDIT, audit_action="document.version_upload").doc
    data = _read_upload(file, ctx)
    try:
        safe_name, file_type = validate_upload(file.filename or "", data, ctx.settings.max_upload_bytes)
    except ValidationError as exc:
        _reject_upload(conn, ctx, principal, "document.version_upload", doc["id"], file.filename, exc)
    with transaction(conn) as tx:
        version = store_version(tx, ctx, document_id=doc["id"], filename=safe_name, file_type=file_type,
                                data=data, uploaded_by=principal.id)
        ctx.audit.append(tx, principal.audit_ctx, "document.version_upload", "allowed", document_id=doc["id"],
                         details={"filename": safe_name, "version_no": version["version_no"],
                                  "version_id": version["id"], "sha256": version["sha256"],
                                  "size": version["size_bytes"]})
    return {"id": version["id"], "version_no": version["version_no"], "sha256": version["sha256"]}


@router.patch("/{doc_id}", summary="Rename / recategorise / describe (owner or edit grant)")
def update_document(doc_id: str, body: DocumentUpdate, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.EDIT, audit_action="document.update").doc
    changes = {}
    try:
        if body.name is not None and validate_doc_name(body.name) != doc["name"]:
            changes["name"] = validate_doc_name(body.name)
        if body.category is not None and validate_category(body.category) != doc["category"]:
            changes["category"] = validate_category(body.category)
        if body.description is not None and validate_description(body.description) != doc["description"]:
            changes["description"] = validate_description(body.description)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not changes:
        return {"ok": True, "changed": []}
    with transaction(conn) as tx:
        sets = ", ".join(f"{k} = :{k}" for k in changes)  # keys come from the fixed set above
        tx.execute(f"UPDATE documents SET {sets}, updated_at = :now WHERE id = :id",
                   {**changes, "now": now_iso(), "id": doc["id"]})
        ctx.audit.append(tx, principal.audit_ctx, "document.update", "allowed", document_id=doc["id"],
                         details={"changes": {k: {"from": doc[k], "to": v} for k, v in changes.items()}})
    return {"ok": True, "changed": sorted(changes)}


@router.put("/{doc_id}/classification",
            summary="Change the label: public, internal or confidential (owner only). Raising it to confidential "
                    "cancels outstanding share links.")
def classify_document(doc_id: str, body: ClassificationRequest, principal: Principal = Depends(current_principal),
                      conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.CLASSIFY, audit_action="document.classified").doc
    old, new = doc["classification"], body.classification
    if old == new:
        return {"ok": True, "classification": new, "changed": False}
    raised = labels.RANK[new] > labels.RANK[old]
    with transaction(conn) as tx:
        tx.execute("UPDATE documents SET classification = ?, updated_at = ? WHERE id = ?", (new, now_iso(), doc["id"]))
        if raised and new == "confidential":  # AUTHZ-CHECK[confidential-cancels-old-links]
            # Links issued while it was Internal or Public should not outlive that.
            tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "document.classified", "allowed", document_id=doc["id"],
                         details={"from": old, "to": new, "links_invalidated": raised and new == "confidential"})
    return {"ok": True, "classification": new, "changed": True}


@router.delete("/{doc_id}", summary="Move to trash (owner only). Grants and links stop working at once.")
def delete_document(doc_id: str, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.DELETE).doc
    with transaction(conn) as tx:
        tx.execute("UPDATE documents SET deleted_at = ?, deleted_by = ?, access_version = access_version + 1 "
                   "WHERE id = ?", (now_iso(), principal.id, doc["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "document.delete", "allowed", document_id=doc["id"],
                         details={"name": doc["name"], "retention_days": ctx.settings.trash_retention_days})
    return {"ok": True, "status": "in_trash", "retention_days": ctx.settings.trash_retention_days}


@router.post("/{doc_id}/restore", summary="Restore from trash (owner only)")
def restore_document(doc_id: str, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.RESTORE).doc
    if doc["deleted_at"] is None:
        raise HTTPException(status_code=409, detail="Document is not in the trash")
    with transaction(conn) as tx:
        tx.execute("UPDATE documents SET deleted_at = NULL, deleted_by = NULL WHERE id = ?", (doc["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "document.restore", "allowed", document_id=doc["id"])
    return {"ok": True}


@router.delete("/{doc_id}/purge", summary="Permanently destroy a trashed document (owner only)")
def purge_document(doc_id: str, principal: Principal = Depends(current_principal),
                   conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.PURGE).doc
    if doc["deleted_at"] is None:
        raise HTTPException(status_code=409, detail="Move the document to the trash first")
    with transaction(conn) as tx:
        n = crypto_shred_document(tx, ctx, doc["id"])
        ctx.audit.append(tx, principal.audit_ctx, "document.purge", "allowed", document_id=doc["id"],
                         details={"name": doc["name"], "versions_shredded": n})
    return {"ok": True, "versions_shredded": n}


@router.get("/{doc_id}/activity", summary="Audit trail of this document (owner only; refusal reasons are admin-only)")
def document_activity(doc_id: str, limit: int = Query(200, ge=1, le=1000),
                      principal: Principal = Depends(current_principal),
                      conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.AUDIT, audit_action="document.activity").doc
    rows = conn.execute(
        """SELECT seq, ts, actor_name, action, outcome, details FROM audit_log
           WHERE document_id = ? ORDER BY seq DESC LIMIT ?""",
        (doc["id"], limit),
    ).fetchall()
    # The owner sees who did what and whether it was allowed - but never WHY a
    # request was refused: the internal reasons are for administrators only.
    items = []
    for r in rows:
        details = json.loads(r["details"])
        for key in INTERNAL_DETAIL_KEYS:
            details.pop(key, None)
        items.append({**dict(r), "details": details})
    return {"items": items}
