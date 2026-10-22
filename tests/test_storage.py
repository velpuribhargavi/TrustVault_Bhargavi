"""How files are stored and served.  THREATS.md: T29, T30, T31, T33, T36, T49."""
from __future__ import annotations

from conftest import PDF_A, audit_rows, make_pdf
from trustvault.db import transaction


def _blob_path(world, db, version_id):
    blob_id = db.execute("SELECT blob_id FROM document_versions WHERE id = ?", (version_id,)).fetchone()[0]
    return world.app.state.ctx.blobs._path(blob_id)


def test_files_are_encrypted_at_rest(world, db):
    raw = _blob_path(world, db, world.version_a1).read_bytes()
    assert b"Confidential salary letter" not in raw
    assert b"%PDF" not in raw
    # Nothing in the instance directory holds the plaintext (db, wal, blobs).
    inst = world.app.state.ctx.settings.instance_dir
    for f in inst.rglob("*"):
        if f.is_file() and not f.name.endswith(".key"):
            assert b"Confidential salary letter" not in f.read_bytes(), f


def test_storage_is_not_served_over_http(world):
    anon = world.anon()
    for path in ["/instance/trustvault.db", "/static/../instance/trustvault.db", "/static/../../trustvault/config.py",
                 "/blobs/", "/static/", "/instance/keys/master.key"]:
        r = anon.get(path)
        assert r.status_code in (404, 405), path
        assert b"SQLite" not in r.content


def test_swapped_blob_is_detected_not_served(world, db):
    """Copying another document's ciphertext over this one fails AES-GCM
    authentication (the document and version ids are bound as AAD)."""
    _blob_path(world, db, world.version_a1).write_bytes(_blob_path(world, db, world.version_b1).read_bytes())
    r = world["alice"].get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 500
    assert b"PNG" not in r.content
    assert audit_rows(db, action="document.download", outcome="error")
    alerts = world["admin"].get("/api/admin/alerts").json()["items"]
    assert any(a["rule"] == "integrity_failure" and a["severity"] == "critical" for a in alerts)


def test_wrapped_key_swap_is_detected(world, db):
    wb = db.execute("SELECT wrapped_key FROM document_versions WHERE id = ?", (world.version_b1,)).fetchone()[0]
    with transaction(db) as tx:
        tx.execute("UPDATE document_versions SET wrapped_key = ? WHERE id = ?", (wb, world.version_a1))
    assert world["alice"].get(f"/api/documents/{world.doc_a}/download").status_code == 500


def test_download_headers_force_attachment_and_sandbox(world):
    r = world["carol"].get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 200 and r.content == PDF_A
    assert r.headers["content-disposition"].startswith("attachment;")
    assert "sandbox" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in r.headers["cache-control"]


def test_versions_are_kept_and_each_downloadable(world):
    r = world["dave"].post(f"/api/documents/{world.doc_a}/versions",
                           files={"file": ("v2.pdf", make_pdf(b"version two"), "application/pdf")})
    assert r.status_code == 201 and r.json()["version_no"] == 2
    doc = world["carol"].get(f"/api/documents/{world.doc_a}").json()
    assert [v["version_no"] for v in doc["versions"]] == [2, 1]
    assert b"version two" in world["carol"].get(f"/api/documents/{world.doc_a}/download").content
    old = world["carol"].get(f"/api/documents/{world.doc_a}/versions/{world.version_a1}/download")
    assert old.content == PDF_A


def test_purge_crypto_shreds(world, db):
    path = _blob_path(world, db, world.version_a1)
    assert world["alice"].delete(f"/api/documents/{world.doc_a}/purge").status_code == 409  # must trash first
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    r = world["alice"].delete(f"/api/documents/{world.doc_a}/purge")
    assert r.status_code == 200
    assert db.execute("SELECT wrapped_key FROM document_versions WHERE id = ?", (world.version_a1,)).fetchone()[0] is None
    assert not path.exists()
    assert db.execute("SELECT COUNT(*) FROM grants WHERE document_id = ?", (world.doc_a,)).fetchone()[0] == 0
    assert world["alice"].get(f"/api/documents/{world.doc_a}").status_code == 403
    assert world["alice"].post(f"/api/documents/{world.doc_a}/restore").status_code == 403


def test_retention_purges_old_trash(world, db):
    from trustvault.services import purge_expired_trash
    from trustvault.utils import iso_in
    with transaction(db) as tx:
        tx.execute("UPDATE documents SET deleted_at = ? WHERE id = ?", (iso_in(days=-31), world.doc_a))
    assert purge_expired_trash(db, world.app.state.ctx) == 1
    assert db.execute("SELECT purged_at FROM documents WHERE id = ?", (world.doc_a,)).fetchone()[0] is not None


def test_audit_failure_means_no_download(world, db, monkeypatch):
    """Fail closed: if the download cannot be recorded, it does not happen."""
    def broken(*a, **k):
        raise RuntimeError("audit store unavailable")
    monkeypatch.setattr(world.app.state.ctx.audit, "append", broken)
    r = world["carol"].get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 500
    assert PDF_A not in r.content
