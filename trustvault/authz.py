"""The permission model - the single place where document access is decided.

Every route that touches a document calls ``authorize()`` before it does
anything else. Nothing is cached: each call reads the user, the document and
the grant from the database, so a revoked grant or a deactivated user stops
working on the very next request.

Permission levels (per document, per named person)
---------------------------------------------------
The owner chooses one level for each person they share with:

* ``view``     - open the document in the browser. The server sends a
  watermarked rendering (page images / extracted text), never the file.
* ``download`` - view + download the original file (any version).
* ``edit``     - download + upload a new version + change name/category/description.
* ``owner``    - the person who uploaded the document. Everything above, plus
  delete / restore / purge, manage grants and share links, see the
  document's audit trail, ask for access suggestions.

Global roles
------------
* ``admin``  - manages users and reads the audit log. **Never** gets document
  content, even through a grant (separation of duties). Can only *remove*
  access (emergency revoke), never add it.
* ``owner``  - may upload documents (and so become their owner).
* ``viewer`` - may only use documents that were explicitly granted to them.

Lines tagged ``AUTHZ-CHECK`` / ``AUTHZ-SQL`` are mutated one at a time by
``tools/mutation_check.py``; the test suite must fail for every mutant.
"""
from __future__ import annotations

import sqlite3
from enum import Enum

from fastapi import HTTPException

from .audit import AuditContext, AuditLog
from .db import transaction
from .utils import is_valid_id, now_iso


class Action(str, Enum):
    VIEW = "view"            # metadata, version list, watermarked in-browser rendering
    DOWNLOAD = "download"    # the original file
    EDIT = "edit"
    DELETE = "delete"
    RESTORE = "restore"
    PURGE = "purge"
    SHARE = "share"
    AUDIT = "audit"


PERMISSION_LEVELS = ("view", "download", "edit")  # lowest to highest

PERMISSION_ACTIONS: dict[str, frozenset[Action]] = {
    "view": frozenset({Action.VIEW}),
    "download": frozenset({Action.VIEW, Action.DOWNLOAD}),
    "edit": frozenset({Action.VIEW, Action.DOWNLOAD, Action.EDIT}),
    "owner": frozenset(Action),
}

# What the owner may still do while a document is in the trash.
TRASH_ACTIONS = frozenset({Action.VIEW, Action.RESTORE, Action.PURGE})

_GRANT_LOOKUP_SQL = (
    "SELECT permission, expires_at FROM grants WHERE 1 = 1 "
    "AND document_id = :doc_id "  # AUTHZ-SQL[grant-matches-document]
    "AND user_id = :user_id "  # AUTHZ-SQL[grant-matches-user]
)

# Search/listing scope: a document is visible when I own it or hold a live grant.
ACCESS_SCOPE_SQL = (
    "(d.owner_id = :uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = :uid "
    "AND (g.expires_at IS NULL OR g.expires_at > :now) "  # AUTHZ-SQL[search-grant-expiry]
    "))"
)


def effective_permission(conn: sqlite3.Connection, user: dict, doc: dict, now: str | None = None) -> str | None:
    """Return 'owner', 'edit', 'download', 'view' or None for this user on this document."""
    now = now or now_iso()
    if not user["is_active"]:  # AUTHZ-CHECK[inactive-user-has-no-access]
        return None
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-has-no-content-access]
        return None
    if doc["owner_id"] == user["id"]:
        return "owner"
    grant = conn.execute(_GRANT_LOOKUP_SQL, {"doc_id": doc["id"], "user_id": user["id"]}).fetchone()
    if grant is None:
        return None
    if grant["expires_at"] is not None and grant["expires_at"] <= now:  # AUTHZ-CHECK[expired-grant-ignored]
        return None
    return grant["permission"]


def _deny(conn, audit: AuditLog, ctx: AuditContext, doc_id: str | None, action: Action,
          reason: str, status: int) -> None:
    with transaction(conn) as tx:
        audit.append(tx, ctx, f"document.{action.value}", "denied",
                     document_id=doc_id if doc_id and is_valid_id(doc_id) else None,
                     details={"reason": reason, "requested_id": (doc_id or "")[:64]})
    if status == 404:
        # Same answer whether the document does not exist or exists but is not
        # yours: an attacker learns nothing by probing ids.
        raise HTTPException(status_code=404, detail="Document not found")
    raise HTTPException(status_code=status, detail=f"Your access to this document does not allow '{action.value}'")


def authorize(conn: sqlite3.Connection, audit: AuditLog, ctx: AuditContext, user: dict,
              doc_id: str, action: Action) -> dict:
    """Return the document row (plus ``permission``) or raise 403/404.

    Denials are written to the audit trail before the error is returned.
    """
    doc = None
    if is_valid_id(doc_id):
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None or doc["purged_at"] is not None:  # AUTHZ-CHECK[document-must-exist]
        _deny(conn, audit, ctx, doc_id, action, "not_found", 404)
    doc = dict(doc)
    perm = effective_permission(conn, user, doc)
    if perm is None:  # AUTHZ-CHECK[no-permission-no-access]
        _deny(conn, audit, ctx, doc_id, action, "no_permission", 404)
    if doc["deleted_at"] is not None and (perm != "owner" or action not in TRASH_ACTIONS):  # AUTHZ-CHECK[trashed-document-locked]
        _deny(conn, audit, ctx, doc_id, action, "in_trash", 404)
    if action not in PERMISSION_ACTIONS.get(perm, frozenset()):  # AUTHZ-CHECK[permission-allows-action]
        _deny(conn, audit, ctx, doc_id, action, f"{perm}_cannot_{action.value}", 403)
    doc["permission"] = perm
    return doc


def visible_documents_clause(user: dict) -> str | None:
    """SQL clause restricting a document query to what ``user`` may see, or
    None when the user may see nothing at all."""
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-search-sees-nothing]
        return None
    return ACCESS_SCOPE_SQL
