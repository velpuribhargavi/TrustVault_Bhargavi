"""Cross-object references: authorising document X must not unlock objects
that belong to document Y (versions, grants, share links, suggestions).

THREATS.md: T02 (version IDOR), T03 (grant/link IDOR), T05 (mass assignment).
"""
from __future__ import annotations

import json

from conftest import PNG_B, audit_rows
from trustvault.errors import NO_ACCESS_MESSAGE


def test_version_of_another_document_is_refused(world, db):
    # carol may read DOC_A. She asks for DOC_B's version *through* DOC_A.
    r = world["carol"].get(f"/api/documents/{world.doc_a}/versions/{world.version_b1}/download")
    assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS_MESSAGE
    assert PNG_B not in r.content
    row = audit_rows(db, action="document.version_download", outcome="denied")[-1]
    assert row["actor_id"] == world.ids["carol"]
    assert json.loads(row["details"])["reason"] == "version_not_in_document"


def test_owner_cannot_reach_foreign_version_through_own_document(world):
    r = world["alice"].get(f"/api/documents/{world.doc_a}/versions/{world.version_b1}/download")
    assert r.status_code == 403 and PNG_B not in r.content


def test_cannot_revoke_a_grant_of_another_document_through_own_document(world, db):
    # bob shares DOC_B with carol; alice tries to delete that grant via DOC_A.
    r = world["bob"].post(f"/api/documents/{world.doc_b}/grants", json={"username": "carol", "permission": "download"})
    grant_b = r.json()["id"]
    r = world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{grant_b}")
    assert r.status_code == 404
    assert db.execute("SELECT COUNT(*) FROM grants WHERE id = ?", (grant_b,)).fetchone()[0] == 1
    assert audit_rows(db, action="access.revoked", outcome="denied")


def test_cannot_extend_a_grant_of_another_document_through_own_document(world, db):
    r = world["bob"].post(f"/api/documents/{world.doc_b}/grants", json={"username": "carol", "permission": "view"})
    grant_b, before = r.json()["id"], r.json()["expires_at"]
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants/{grant_b}/extend", json={"minutes": 600})
    assert r.status_code == 404
    assert db.execute("SELECT expires_at FROM grants WHERE id = ?", (grant_b,)).fetchone()[0] == before
    assert audit_rows(db, action="access.extended", outcome="denied")


def test_a_link_for_one_document_cannot_open_another(world, db):
    # alice makes bob a link to DOC_A; bob presents it while asking for... his own DOC_B is fine,
    # so instead carol (download on DOC_A) gets a link for DOC_A and tries it on DOC_B.
    token = world["alice"].post(f"/api/documents/{world.doc_a}/links", json={"username": "carol"}).json()["token"]
    r = world["carol"].get(f"/api/documents/{world.doc_b}", headers={"X-Link-Token": token})
    assert r.status_code == 403 and PNG_B not in r.content
    row = audit_rows(db, action="document.view", outcome="denied")[-1]
    assert json.loads(row["details"])["reason"] == "link_wrong_document"


def test_suggestion_of_another_document_cannot_be_used_to_grant(world, db):
    # Give bob some history so a suggestion exists for DOC_B.
    extra = world["bob"].upload("Bridge drawing rev C.png", PNG_B, category="engineering")
    world["bob"].post(f"/api/documents/{extra}/grants", json={"username": "frank", "permission": "view"})
    sugs = world["bob"].get(f"/api/documents/{world.doc_b}/suggestions").json()["items"]
    assert sugs and sugs[0]["username"] == "frank"
    # alice tries to accept bob's suggestion on her own document.
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": "frank", "permission": "view", "suggestion_id": sugs[0]["suggestion_id"]})
    assert r.status_code == 400
    assert db.execute("SELECT COUNT(*) FROM grants WHERE document_id = ? AND user_id = ?",
                      (world.doc_a, world.ids["frank"])).fetchone()[0] == 0
    assert db.execute("SELECT status FROM suggestions WHERE id = ?", (sugs[0]["suggestion_id"],)).fetchone()[0] == "pending"


def test_cannot_dismiss_suggestion_of_another_document(world, db):
    extra = world["bob"].upload("Bridge drawing rev D.png", PNG_B, category="engineering")
    world["bob"].post(f"/api/documents/{extra}/grants", json={"username": "frank", "permission": "view"})
    sug = world["bob"].get(f"/api/documents/{world.doc_b}/suggestions").json()["items"][0]
    r = world["alice"].post(f"/api/documents/{world.doc_a}/suggestions/{sug['suggestion_id']}/dismiss")
    assert r.status_code == 404
    assert db.execute("SELECT status FROM suggestions WHERE id = ?", (sug["suggestion_id"],)).fetchone()[0] == "pending"


def test_mass_assignment_fields_are_rejected(world, db):
    r = world["dave"].patch(f"/api/documents/{world.doc_a}", json={"name": "x", "owner_id": world.ids["dave"]})
    assert r.status_code == 422
    owner = db.execute("SELECT owner_id FROM documents WHERE id = ?", (world.doc_a,)).fetchone()[0]
    assert owner == world.ids["alice"]
    r = world["carol"].post("/api/auth/change-password",
                            json={"current_password": "x", "new_password": "y", "role": "admin"})
    assert r.status_code == 422


def test_garbage_and_traversal_ids_get_the_same_answer_as_everything_else(world):
    for bad in ["..%2F..%2Fetc%2Fpasswd", "' OR 1=1 --", "a" * 300, "%00"]:
        r = world["carol"].get(f"/api/documents/{bad}")
        assert r.status_code in (403, 404), bad  # 404 only when the router itself cannot match the path
        if r.status_code == 403:
            assert r.json()["detail"] == NO_ACCESS_MESSAGE
