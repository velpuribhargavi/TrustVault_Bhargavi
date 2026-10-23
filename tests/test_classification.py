"""Classification labels: Public, Internal (default), Confidential. Chosen at
upload, changed later by the owner only, every change audited. Confidential:
previews marked CONFIDENTIAL, new access View only for 1 hour. A label never
grants access. THREATS.md: T85, T86.
"""
from __future__ import annotations

import json

from conftest import PNG_B, audit_rows, make_pdf
from trustvault.errors import NO_ACCESS_MESSAGE
from trustvault.utils import parse_iso, utcnow


def label_of(world, client, doc_id) -> str:
    return client.get(f"/api/documents/{doc_id}").json()["classification"]


def classify(client, doc_id, label):
    return client.put(f"/api/documents/{doc_id}/classification", json={"classification": label})


def minutes_left(expires_at: str) -> float:
    return (parse_iso(expires_at) - utcnow()).total_seconds() / 60


def test_uploads_are_internal_unless_the_owner_picks(world, db):
    alice = world["alice"]
    assert label_of(world, alice, world.doc_a) == "internal"
    secret = alice.upload("Merger plan.pdf", make_pdf(b"merger"), category="legal")
    assert alice.get(f"/api/documents/{secret}").json()["classification"] == "internal"
    r = alice.post("/api/documents", files={"file": ("Board pack.pdf", make_pdf(b"board"), "application/pdf")},
                   data={"category": "legal", "classification": "confidential"})
    assert r.status_code == 201 and r.json()["classification"] == "confidential"
    assert json.loads(audit_rows(db, action="document.upload")[-1]["details"])["classification"] == "confidential"
    bad = alice.post("/api/documents", files={"file": ("x.png", PNG_B, "image/png")},
                     data={"category": "general", "classification": "top-secret"})
    assert bad.status_code == 400
    assert json.loads(audit_rows(db, action="document.upload", outcome="denied")[-1]["details"])["reason"] == "validation"


def test_the_owner_changes_the_label_and_every_change_is_audited(world, db):
    alice = world["alice"]
    assert classify(alice, world.doc_a, "public").json() == {"ok": True, "classification": "public", "changed": True}
    assert classify(alice, world.doc_a, "public").json()["changed"] is False          # no change, no event
    assert classify(alice, world.doc_a, "confidential").status_code == 200
    rows = audit_rows(db, action="document.classified")
    assert [(json.loads(r["details"])["from"], json.loads(r["details"])["to"]) for r in rows] == \
        [("internal", "public"), ("public", "confidential")]
    assert all(r["actor_name"] == "alice" and r["outcome"] == "allowed" for r in rows)
    assert classify(alice, world.doc_a, "secret").status_code == 422


def test_only_the_owner_can_change_it(world, db):
    for who, reason in (("dave", "edit_cannot_classify"), ("carol", "download_cannot_classify"),
                        ("gina", "view_only"), ("bob", "no_grant"), ("admin", "admin_never_reads_content")):
        r = classify(world[who], world.doc_a, "public")
        assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS_MESSAGE, who
        assert json.loads(audit_rows(db, action="document.classified")[-1]["details"])["reason"] == reason
    assert label_of(world, world["alice"], world.doc_a) == "internal"


def test_raising_a_document_to_confidential_cancels_its_share_links(world, db):
    alice = world["alice"]
    token = alice.post(f"/api/documents/{world.doc_a}/links", json={"username": "gina", "permission": "view"}).json()["token"]
    classify(alice, world.doc_a, "public")                                     # lowering: links keep working
    assert world["gina"].post("/api/links/open", json={"token": token}).status_code == 200
    classify(alice, world.doc_a, "confidential")
    assert world["gina"].post("/api/links/open", json={"token": token}).status_code == 403
    assert json.loads(audit_rows(db, action="document.classified")[-1]["details"])["links_invalidated"] is True
    assert world["gina"].get(f"/api/documents/{world.doc_a}").status_code == 200   # her own grant is untouched


def test_confidential_previews_are_marked_confidential(world):
    gina = world["gina"]
    assert "CONFIDENTIAL" not in gina.get(f"/api/documents/{world.doc_a}/preview").json()["watermark"]
    classify(world["alice"], world.doc_a, "confidential")
    preview = gina.get(f"/api/documents/{world.doc_a}/preview").json()
    assert preview["watermark"].startswith("CONFIDENTIAL · gina · ") and preview["classification"] == "confidential"
    owner_view = world["alice"].get(f"/api/documents/{world.doc_a}/preview").json()
    assert owner_view["watermark"].startswith("CONFIDENTIAL · alice · ")       # the owner's own view too
    page = gina.get(f"/api/documents/{world.doc_a}/preview/pages/1")
    assert page.status_code == 200 and page.content.startswith(b"\x89PNG")


def test_new_access_to_a_confidential_document_is_view_only_for_one_hour(world):
    alice = world["alice"]
    classify(alice, world.doc_a, "confidential")
    g = alice.post(f"/api/documents/{world.doc_a}/grants", json={"username": "frank"}).json()
    assert g["permission"] == "view" and 59 < minutes_left(g["expires_at"]) <= 60
    listing = alice.get(f"/api/documents/{world.doc_a}/grants").json()
    assert listing["default_grant_minutes"] == 60 and listing["default_permission"] == "view"
    # The owner can still choose more, explicitly.
    g = alice.post(f"/api/documents/{world.doc_a}/grants",
                   json={"username": "bob", "permission": "download", "duration_minutes": 240}).json()
    assert g["permission"] == "download" and 239 < minutes_left(g["expires_at"]) <= 240


def test_other_labels_keep_the_normal_defaults(world):
    g = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "frank"}).json()
    assert g["permission"] == "view" and 29 < minutes_left(g["expires_at"]) <= 30


def test_the_label_shows_in_every_document_list(world):
    alice = world["alice"]
    classify(alice, world.doc_a, "confidential")
    items = {i["id"]: i for i in alice.get("/api/documents").json()["items"]}
    assert items[world.doc_a]["classification"] == "confidential"
    assert {i["classification"] for i in world["carol"].get("/api/documents").json()["items"]} == {"confidential"}
    alice.delete(f"/api/documents/{world.doc_a}")
    assert alice.get("/api/documents/trash").json()["items"][0]["classification"] == "confidential"
    assert world["bob"].get(f"/api/documents/{world.doc_b}").json()["classification"] == "internal"


def test_public_does_not_mean_anyone_can_open_it(world):
    classify(world["bob"], world.doc_b, "public")
    for who in ("carol", "alice", "admin"):
        r = world[who].get(f"/api/documents/{world.doc_b}")
        assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS_MESSAGE, who
    assert world.anon().get(f"/api/documents/{world.doc_b}").status_code == 401
    assert world["carol"].get("/api/documents").json()["total"] == 1                # still only what was shared
