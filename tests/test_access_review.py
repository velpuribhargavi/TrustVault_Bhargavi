"""Access review: grants nobody has used for UNUSED_GRANT_DAYS (30) are flagged,
and an administrator can revoke them in bulk. Every bulk revoke raises the
access_version of each affected document once, so outstanding share links die
too. "Used" is read from the audit trail. THREATS.md: T80.
"""
from __future__ import annotations

import json

from conftest import audit_rows
from trustvault.errors import NO_ACCESS_MESSAGE

SIXTY_DAYS = 60 * 24 * 60


def long_grant(world, username: str, permission: str = "view") -> str:
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": username, "permission": permission, "duration_minutes": SIXTY_DAYS})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def review(admin, **params) -> dict:
    r = admin.get("/api/admin/access-review", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def access_version(db, doc_id: str) -> int:
    return db.execute("SELECT access_version FROM documents WHERE id = ?", (doc_id,)).fetchone()[0]


def test_grants_unused_for_30_days_are_flagged_and_used_ones_are_not(world, clock):
    gina = long_grant(world, "gina")
    carol = long_grant(world, "carol", "download")
    clock.advance(days=20)
    assert world.fresh("carol").get(f"/api/documents/{world.doc_a}/download").status_code == 200   # used on day 20
    clock.advance(days=11)                                                                         # day 31
    data = review(world.fresh("admin"))
    rows = {i["grant_id"]: i for i in data["items"]}
    assert data["unused_days"] == 30
    assert rows[gina]["flagged"] is True and rows[gina]["days_unused"] == 31 and rows[gina]["last_used_at"] is None
    assert rows[carol]["flagged"] is False and rows[carol]["days_unused"] == 11 and rows[carol]["last_used_at"]
    assert data["items"][0]["grant_id"] == gina                       # flagged first
    assert data["flagged"] == sum(i["flagged"] for i in data["items"])
    # Only live grants: the 30-minute grants of the fixture have long expired.
    assert all(i["expires_at"] > data["server_time"] for i in data["items"])
    # The threshold can be asked for explicitly.
    assert {i["grant_id"] for i in review(world.fresh("admin"), unused_days=10)["items"] if i["flagged"]} == {gina, carol}


def test_use_through_a_share_link_counts_as_use(world, clock):
    gina = long_grant(world, "gina")
    clock.advance(days=29)
    alice = world.fresh("alice")
    token = alice.post(f"/api/documents/{world.doc_a}/links", json={"username": "gina", "permission": "view"}).json()["token"]
    assert world.fresh("gina").post("/api/links/open", json={"token": token}).status_code == 200
    clock.advance(days=2)
    row = next(i for i in review(world.fresh("admin"))["items"] if i["grant_id"] == gina)
    assert row["flagged"] is False and row["days_unused"] == 2


def test_bulk_revoke_removes_the_grants_and_bumps_each_document_once(world, db):
    gina, carol = long_grant(world, "gina"), long_grant(world, "carol", "download")
    before = access_version(db, world.doc_a)
    r = world["admin"].post("/api/admin/access-review/revoke", json={"grant_ids": [gina, carol, gina]})
    assert r.status_code == 200 and r.json() == {"revoked": 2, "documents": 1, "not_found": 1}
    assert access_version(db, world.doc_a) == before + 1               # once per document, not once per grant
    assert db.execute("SELECT COUNT(*) FROM grants WHERE id IN (?, ?)", (gina, carol)).fetchone()[0] == 0
    refused = world["gina"].get(f"/api/documents/{world.doc_a}")
    assert refused.status_code == 403 and refused.json()["detail"] == NO_ACCESS_MESSAGE
    revoked = [json.loads(r["details"]) for r in audit_rows(db, action="access.revoked")[-2:]]
    assert all(d["bulk"] and d["by_admin"] and "unused_days" in d for d in revoked)
    summary = audit_rows(db, action="access.bulk_revoked")[-1]
    assert summary["actor_name"] == "admin" and json.loads(summary["details"])["grants"] == 2
    assert json.loads(summary["details"])["documents"] == [world.doc_a]


def test_bulk_revoke_kills_outstanding_share_links_of_the_document(world):
    """Dave keeps his own access, but the link he was sent is cancelled with the rest."""
    gina = long_grant(world, "gina")
    token = world["alice"].post(f"/api/documents/{world.doc_a}/links",
                                json={"username": "dave", "permission": "view"}).json()["token"]
    assert world["admin"].post("/api/admin/access-review/revoke", json={"grant_ids": [gina]}).status_code == 200
    assert world["dave"].post("/api/links/open", json={"token": token}).status_code == 403
    assert world["dave"].get(f"/api/documents/{world.doc_a}").status_code == 200       # his grant is untouched


def test_only_administrators_can_review_or_bulk_revoke(world, db):
    gina = long_grant(world, "gina")
    for who in ("alice", "carol"):
        assert world[who].get("/api/admin/access-review").status_code == 403
        assert world[who].post("/api/admin/access-review/revoke", json={"grant_ids": [gina]}).status_code == 403
    assert db.execute("SELECT COUNT(*) FROM grants WHERE id = ?", (gina,)).fetchone()[0] == 1
    assert len(audit_rows(db, action="auth.forbidden")) == 4


def test_bulk_revoke_input_is_checked_and_misses_are_recorded(world, db):
    admin = world["admin"]
    assert admin.post("/api/admin/access-review/revoke", json={"grant_ids": []}).status_code == 422
    assert admin.post("/api/admin/access-review/revoke", json={"grant_ids": ["x"] * 501}).status_code == 422
    r = admin.post("/api/admin/access-review/revoke", json={"grant_ids": ["AAAAAAAAAAAAAAAAAAAAAA", "' OR 1=1 --"]})
    assert r.status_code == 404
    row = audit_rows(db, action="access.bulk_revoked")[-1]
    assert row["outcome"] == "denied" and json.loads(row["details"])["reason"] == "not_found"
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 4       # nothing touched
