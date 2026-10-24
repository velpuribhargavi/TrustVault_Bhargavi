"""Document storage operations shared by the API and the seed script."""
from __future__ import annotations

import secrets
import sqlite3
from urllib.parse import quote

from .context import AppContext
from .crypto import IntegrityError, aad_for, sha256_hex
from .db import Tx
from .utils import new_id, now_iso
from .validation import FileType


def new_blob_id() -> str:
    return secrets.token_urlsafe(24)


def store_version(tx: Tx, ctx: AppContext, *, document_id: str, filename: str, file_type: FileType,
                  data: bytes, uploaded_by: str) -> dict:
    """Encrypt ``data`` and record it as the next version of ``document_id``.

    The blob is written before the row; if the surrounding transaction rolls
    back, the after-rollback cleanup in the caller removes the orphan blob.
    """
    last = tx.execute("SELECT COALESCE(MAX(version_no), 0) AS n FROM document_versions WHERE document_id = ?",
                      (document_id,)).fetchone()
    version_no = last["n"] + 1
    version_id = new_id()
    blob_id = new_blob_id()
    blob, wrapped = ctx.keyring.encrypt(data, aad_for(document_id, version_id))
    ctx.blobs.write(blob_id, blob)
    try:
        tx.execute(
            """INSERT INTO document_versions (id, document_id, version_no, original_filename, extension, mime_type,
                                              size_bytes, sha256, blob_id, wrapped_key, uploaded_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (version_id, document_id, version_no, filename, file_type.extension, file_type.mime,
             len(data), sha256_hex(data), blob_id, wrapped, uploaded_by, now_iso()),
        )
        tx.execute("UPDATE documents SET current_version_id = ?, updated_at = ? WHERE id = ?",
                   (version_id, now_iso(), document_id))
    except BaseException:
        ctx.blobs.delete(blob_id)
        raise
    return {"id": version_id, "version_no": version_no, "blob_id": blob_id, "size_bytes": len(data),
            "sha256": sha256_hex(data)}


def read_version(ctx: AppContext, version: dict) -> bytes:
    """Decrypt a version and check it against the hash recorded at upload."""
    try:
        blob = ctx.blobs.read(version["blob_id"])
    except FileNotFoundError as exc:
        raise IntegrityError("blob missing") from exc
    data = ctx.keyring.decrypt(blob, version["wrapped_key"], aad_for(version["document_id"], version["id"]))
    if sha256_hex(data) != version["sha256"]:
        raise IntegrityError("content hash mismatch")
    return data


def crypto_shred_document(tx: Tx, ctx: AppContext, document_id: str) -> int:
    """Destroy every content key of a document and delete its blobs."""
    versions = tx.execute("SELECT id, blob_id FROM document_versions WHERE document_id = ?", (document_id,)).fetchall()
    tx.execute("UPDATE document_versions SET wrapped_key = NULL WHERE document_id = ?", (document_id,))
    now = now_iso()
    tx.execute("UPDATE documents SET purged_at = ?, access_version = access_version + 1 WHERE id = ?",
               (now, document_id))
    tx.execute("DELETE FROM grants WHERE document_id = ?", (document_id,))
    blob_ids = [v["blob_id"] for v in versions]
    tx.after_commit(lambda: [ctx.blobs.delete(b) for b in blob_ids])
    return len(versions)


def content_disposition(filename: str) -> str:
    """RFC 6266 attachment header with an ASCII fallback and a UTF-8 form."""
    fallback = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\;' else "_" for ch in filename) or "download"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


def get_version(conn: sqlite3.Connection, version_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM document_versions WHERE id = ?", (version_id,)).fetchone()
    return dict(row) if row else None


def purge_expired_trash(conn: sqlite3.Connection, ctx: AppContext) -> int:
    """Retention: crypto-shred documents that sat in the trash too long."""
    from datetime import timedelta

    from .audit import AuditContext
    from .db import transaction
    from .utils import iso, utcnow

    cutoff = iso(utcnow() - timedelta(days=ctx.settings.trash_retention_days))
    rows = conn.execute("SELECT id FROM documents WHERE deleted_at IS NOT NULL AND purged_at IS NULL AND deleted_at < ?",
                        (cutoff,)).fetchall()
    system = AuditContext(actor_id=None, actor_name="system:retention", ip=None, user_agent=None)
    for row in rows:
        with transaction(conn) as tx:
            n = crypto_shred_document(tx, ctx, row["id"])
            ctx.audit.append(tx, system, "document.purge", "allowed", document_id=row["id"],
                             details={"reason": "retention", "versions_shredded": n})
    return len(rows)
