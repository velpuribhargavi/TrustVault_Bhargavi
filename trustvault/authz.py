"""The permission model - the single place where document access is decided.

``check_access()`` is the ONE function that decides whether a person may do
something to a document. Every endpoint that touches a document - and in
particular every endpoint that returns file content (metadata, preview, page
images, downloads, version downloads) - calls ``require_access()``, which runs
``check_access()``, writes a ``denied`` audit row with the internal reason
when the answer is no, and then raises the one uniform error:

    403  "You don't have access to this file."

Nothing is cached: every call reads the user, the document, the grant and the
link state from the database, so revoking, expiring or deactivating takes
effect on the very next request.

Permission levels (per document, per named person)
---------------------------------------------------
* ``view``     - open it in the browser. The server sends a watermarked
  rendering (page images / extracted text), never the file.
* ``download`` - view + download the original file (any version).
* ``edit``     - download + upload a new version + change name/category/description.
* ``owner``    - the uploader. Everything, plus delete / restore / purge,
  manage grants and links, see the document's audit trail, ask for suggestions.

A person reaches a document in one of three ways: they own it, they hold a
grant that has not expired (every grant expires), or they present a share link
that was made for them (5 minutes, signed, see ``links.py``).

Global roles
------------
* ``admin``  - manages users and reads the audit log. **Never** gets document
  content, through a grant or a link (separation of duties).
* ``owner``  - may upload documents (and so become their owner).
* ``viewer`` - may only use documents that were explicitly shared with them.

Lines tagged ``AUTHZ-CHECK`` / ``AUTHZ-SQL`` are mutated one at a time by
``tools/mutation_check.py``; the test suite must fail for every mutant.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .context import AppContext
from .db import transaction
from .errors import no_access
from .expiry import log_expired_grants
from .links import BadLink, LinkClaims, verify_signature
from .utils import is_valid_id, iso, utcnow


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
_RANK = {None: 0, "view": 1, "download": 2, "edit": 3, "owner": 4}

PERMISSION_ACTIONS: dict[str, frozenset[Action]] = {
    "view": frozenset({Action.VIEW}),
    "download": frozenset({Action.VIEW, Action.DOWNLOAD}),
    "edit": frozenset({Action.VIEW, Action.DOWNLOAD, Action.EDIT}),
    "owner": frozenset(Action),
}

# What the owner may still do while a document is in the trash.
TRASH_ACTIONS = frozenset({Action.VIEW, Action.RESTORE, Action.PURGE})

# The internal reasons for a refusal, in the order check_access() tests them.
# The caller only ever sees "You don't have access to this file."; the reason
# goes to the audit trail.
DENIAL_REASONS = (
    "invalid_document_id",        # not even a well-formed id
    "document_not_found",
    "document_destroyed",         # crypto-shredded
    "user_inactive",              # deactivated or deleted account
    "admin_never_reads_content",  # separation of duties
    # -- a share link was presented and could not be used (checked in this order)
    "link_invalid",               # malformed, or the signature does not match
    "link_wrong_document",
    "link_wrong_recipient",       # made for somebody else (forwarded)
    "link_expired",               # older than LINK_TTL_SECONDS
    "link_revoked",               # access_version changed since it was made
    "link_owner_changed",         # its creator is no longer the active owner
    # -- no usable link and no usable grant
    "grant_expired",
    "grant_revoked",              # the owner (or an admin) took the access away
    "no_grant",                   # never shared with this person
    # -- has access, but not to this
    "document_in_trash",
    "level_too_low",              # recorded as "<level>_cannot_<action>", e.g. view_cannot_download
    "version_not_in_document",    # a version id that belongs to another document
)

_GRANT_LOOKUP_SQL = (
    "SELECT id, permission, expires_at FROM grants WHERE 1 = 1 "
    "AND document_id = :doc_id "  # AUTHZ-SQL[grant-matches-document]
    "AND user_id = :user_id "  # AUTHZ-SQL[grant-matches-user]
)

# Search/listing scope: a document is visible when I own it or hold a live grant.
ACCESS_SCOPE_SQL = (
    "(d.owner_id = :uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = :uid "
    "AND g.expires_at > :now "  # AUTHZ-SQL[search-grant-expiry]
    "))"
)


@dataclass
class Decision:
    allowed: bool
    reason: str                      # "ok" when allowed, else one of DENIAL_REASONS
    action: Action
    doc: dict | None = None
    permission: str | None = None    # owner / edit / download / view
    via: str | None = None           # owner / grant / link
    grant: dict | None = None
    link: LinkClaims | None = None
    link_problem: str | None = None  # why a presented link was not used (even if a grant was)
    version: dict | None = None

    @property
    def access_expires_at(self) -> str | None:
        """When the access used for this request ends (None for the owner)."""
        if self.via == "grant" and self.grant:
            return self.grant["expires_at"]
        if self.via == "link" and self.link:
            return iso(datetime.fromtimestamp(self.link.expires_at, tz=timezone.utc))
        return None


def _was_revoked(conn: sqlite3.Connection, doc_id: str, user_id: str) -> bool:
    """For the audit reason only: was this person's last grant taken away?"""
    row = conn.execute(
        """SELECT action FROM audit_log WHERE document_id = ? AND target_user_id = ?
           AND outcome = 'allowed' AND action IN ('access.granted', 'access.changed', 'access.revoked')
           ORDER BY seq DESC LIMIT 1""",
        (doc_id, user_id)).fetchone()
    return row is not None and row["action"] == "access.revoked"


def _parse_link(keyring, token: str) -> LinkClaims | None:
    try:
        return verify_signature(keyring, token)
    except BadLink:
        return None


def _link_problem(conn: sqlite3.Connection, claims: LinkClaims | None, doc: dict, user: dict,
                  now_ts: float) -> str | None:
    """None when the link may be used by ``user`` on ``doc`` right now."""
    if claims is None:
        return "link_invalid"
    if claims.document_id != doc["id"]:  # AUTHZ-CHECK[link-matches-document]
        return "link_wrong_document"
    if claims.recipient_id != user["id"]:  # AUTHZ-CHECK[link-bound-to-recipient]
        return "link_wrong_recipient"
    if claims.expires_at <= now_ts:  # AUTHZ-CHECK[link-not-expired]
        return "link_expired"
    if claims.access_version != doc["access_version"]:  # AUTHZ-CHECK[link-not-revoked]
        return "link_revoked"
    creator = conn.execute("SELECT id, is_active FROM users WHERE id = ?", (claims.creator_id,)).fetchone()
    lost = creator is None or not creator["is_active"] or doc["owner_id"] != claims.creator_id
    if lost:  # AUTHZ-CHECK[link-creator-still-owner]
        return "link_owner_changed"
    return None


def check_access(conn: sqlite3.Connection, keyring, user: dict, doc_id: str, action: Action, *,
                 version_id: str | None = None, link_token: str | None = None, require_link: bool = False,
                 now: datetime | None = None) -> Decision:
    """Decide - without side effects - whether ``user`` may do ``action`` on ``doc_id``.

    ``link_token``   a share link presented with the request (X-Link-Token header).
    ``require_link`` the request is *about* the link (opening it): a link that
                     cannot be used is refused even if a grant would allow access.
    ``version_id``   the request targets this version, which must belong to the document.
    """
    now = now or utcnow()
    now_s = iso(now)

    def deny(reason: str, **kw) -> Decision:
        return Decision(False, reason, action, **kw)

    doc = None
    if is_valid_id(doc_id):
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:  # AUTHZ-CHECK[document-must-exist]
        return deny("document_not_found" if is_valid_id(doc_id) else "invalid_document_id")
    doc = dict(doc)
    if doc["purged_at"] is not None:  # AUTHZ-CHECK[destroyed-document-unreachable]
        return deny("document_destroyed", doc=doc)
    if not user["is_active"]:  # AUTHZ-CHECK[inactive-user-has-no-access]
        return deny("user_inactive", doc=doc)
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-has-no-content-access]
        return deny("admin_never_reads_content", doc=doc)

    # 1. The person's own access: ownership, or a grant that has not expired.
    base_perm, base_reason, grant = None, None, None
    if doc["owner_id"] == user["id"]:
        base_perm = "owner"
    else:
        row = conn.execute(_GRANT_LOOKUP_SQL, {"doc_id": doc["id"], "user_id": user["id"]}).fetchone()
        if row is None:
            base_reason = "grant_revoked" if _was_revoked(conn, doc["id"], user["id"]) else "no_grant"
        elif row["expires_at"] <= now_s:  # AUTHZ-CHECK[expired-grant-ignored]
            base_reason, grant = "grant_expired", dict(row)
        else:
            base_perm, grant = row["permission"], dict(row)

    # 2. A share link, if one was presented.
    claims, link_problem, link_perm = None, None, None
    if link_token:
        claims = _parse_link(keyring, link_token)
        link_problem = _link_problem(conn, claims, doc, user, now.timestamp())
        if link_problem is None:
            link_perm = claims.permission
    if require_link and (not link_token or link_problem is not None):
        return deny(link_problem or "link_invalid", doc=doc, link=claims, link_problem=link_problem, grant=grant)

    # The better of the two wins: a link never lowers what a grant allows.
    if _RANK[link_perm] > _RANK[base_perm]:
        perm, via = link_perm, "link"
    else:
        perm, via = base_perm, ("owner" if base_perm == "owner" else "grant" if base_perm else None)
    if perm is None:  # AUTHZ-CHECK[no-permission-no-access]
        return deny(link_problem or base_reason, doc=doc, link=claims, link_problem=link_problem, grant=grant)

    common = dict(doc=doc, permission=perm, via=via, grant=grant, link=claims, link_problem=link_problem)
    if doc["deleted_at"] is not None and (perm != "owner" or action not in TRASH_ACTIONS):  # AUTHZ-CHECK[trashed-document-locked]
        return deny("document_in_trash", **common)
    if action not in PERMISSION_ACTIONS.get(perm, frozenset()):  # AUTHZ-CHECK[permission-allows-action]
        return deny(f"{perm}_cannot_{action.value}", **common)

    version = None
    if version_id is not None:
        row = conn.execute("SELECT * FROM document_versions WHERE id = ?", (version_id,)).fetchone() \
            if is_valid_id(version_id) else None
        # A version id from another document must not ride on this document's access.
        if row is None or row["document_id"] != doc["id"]:  # AUTHZ-CHECK[version-belongs-to-document]
            return deny("version_not_in_document", **common)
        version = dict(row)
    return Decision(True, "ok", action, version=version, **common)


def record_denial(conn: sqlite3.Connection, ctx: AppContext, audit_ctx, decision: Decision, requested_id: str,
                  audit_action: str, *, version_id: str | None = None) -> None:
    """Write the refusal, with its internal reason, to the audit trail."""
    details = {"reason": decision.reason, "requested_id": (requested_id or "")[:64]}
    if version_id is not None:
        details["requested_version"] = version_id[:64]
    if decision.link is not None:
        details["link_id"] = decision.link.link_id
    if decision.link_problem and decision.link_problem != decision.reason:
        details["link_problem"] = decision.link_problem
    if decision.permission:
        details["permission"] = decision.permission
    doc_id = decision.doc["id"] if decision.doc else None
    if decision.reason == "grant_expired" and decision.grant:
        log_expired_grants(conn, ctx.audit, grant_id=decision.grant["id"])
    with transaction(conn) as tx:
        ctx.audit.append(tx, audit_ctx, audit_action, "denied", document_id=doc_id, details=details)


def require_access(conn: sqlite3.Connection, ctx: AppContext, principal, doc_id: str, action: Action, *,
                   version_id: str | None = None, link_token: str | None = None, require_link: bool = False,
                   audit_action: str | None = None) -> Decision:
    """check_access() + audit the refusal + the uniform 403. Returns the Decision when allowed."""
    decision = check_access(conn, ctx.keyring, principal.user, doc_id, action, version_id=version_id,
                            link_token=link_token, require_link=require_link)
    if not decision.allowed:
        record_denial(conn, ctx, principal.audit_ctx, decision, doc_id, audit_action or f"document.{action.value}",
                      version_id=version_id)
        raise no_access()
    return decision


def visible_documents_clause(user: dict) -> str | None:
    """SQL clause restricting a document query to what ``user`` may see, or
    None when the user may see nothing at all."""
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-search-sees-nothing]
        return None
    return ACCESS_SCOPE_SQL
