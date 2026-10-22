"""Unit tests of the permission function itself.

Some checks in authz.py are defence in depth: the HTTP layer would already
stop the request (e.g. a deactivated user has no session). These tests call
the policy directly so that *each* check is proven to matter on its own.
"""
from __future__ import annotations

from trustvault.authz import effective_permission
from trustvault.db import transaction
from trustvault.utils import iso_in, new_id, now_iso


def _user(db, uid):
    return dict(db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())


def _doc(db, doc_id):
    return dict(db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone())


def test_owner_read_and_edit_levels(world, db):
    doc = _doc(db, world.doc_a)
    assert effective_permission(db, _user(db, world.ids["alice"]), doc) == "owner"
    assert effective_permission(db, _user(db, world.ids["dave"]), doc) == "edit"
    assert effective_permission(db, _user(db, world.ids["carol"]), doc) == "download"
    assert effective_permission(db, _user(db, world.ids["gina"]), doc) == "view"
    assert effective_permission(db, _user(db, world.ids["bob"]), doc) is None


def test_inactive_user_gets_nothing_even_with_a_grant(world, db):
    carol = _user(db, world.ids["carol"])
    carol["is_active"] = 0
    assert effective_permission(db, carol, _doc(db, world.doc_a)) is None


def test_inactive_owner_gets_nothing(world, db):
    alice = _user(db, world.ids["alice"])
    alice["is_active"] = 0
    assert effective_permission(db, alice, _doc(db, world.doc_a)) is None


def test_admin_gets_nothing_even_with_a_grant_row(world, db):
    # The API refuses to grant to an admin; simulate a grant written some other way.
    with transaction(db) as tx:
        tx.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) "
                   "VALUES (?, ?, ?, 'edit', ?, ?)", (new_id(), world.doc_a, world.ids["admin"], world.ids["alice"], now_iso()))
    assert effective_permission(db, _user(db, world.ids["admin"]), _doc(db, world.doc_a)) is None
    # and over HTTP
    assert world["admin"].get(f"/api/documents/{world.doc_a}/download").status_code == 404
    assert world["admin"].get("/api/documents").json()["items"] == []


def test_expired_grant_is_ignored(world, db):
    assert effective_permission(db, _user(db, world.ids["erin"]), _doc(db, world.doc_a)) is None


def test_grant_expiring_in_future_works_until_it_passes(world, db):
    with transaction(db) as tx:
        tx.execute("UPDATE grants SET expires_at = ? WHERE id = ?", (iso_in(minutes=5), world.grant_carol))
    assert effective_permission(db, _user(db, world.ids["carol"]), _doc(db, world.doc_a)) == "download"
    with transaction(db) as tx:
        tx.execute("UPDATE grants SET expires_at = ? WHERE id = ?", (iso_in(seconds=-1), world.grant_carol))
    assert effective_permission(db, _user(db, world.ids["carol"]), _doc(db, world.doc_a)) is None
    assert world["carol"].get(f"/api/documents/{world.doc_a}/download").status_code == 404


def test_grant_on_one_document_does_not_open_another(world, db):
    # carol holds a grant on DOC_A only.
    assert effective_permission(db, _user(db, world.ids["carol"]), _doc(db, world.doc_b)) is None
    assert world["carol"].get(f"/api/documents/{world.doc_b}").status_code == 404


def test_someone_elses_grant_does_not_apply_to_me(world, db):
    assert effective_permission(db, _user(db, world.ids["frank"]), _doc(db, world.doc_a)) is None
