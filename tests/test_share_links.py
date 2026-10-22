"""External share links.  THREATS.md: T13-T17."""
from __future__ import annotations

import json
import threading

from conftest import PDF_A, audit_rows
from trustvault.db import transaction
from trustvault.utils import iso_in


def make_link(world, hours=1, uses=3, doc=None):
    r = world["alice"].post(f"/api/documents/{doc or world.doc_a}/share-links",
                            json={"expires_in_hours": hours, "max_uses": uses, "label": "for auditor"})
    assert r.status_code == 201, r.text
    return r.json()


def info(world, token):
    return world.anon().post("/api/public/share/info", json={"token": token})


def download(world, token):
    return world.anon().post("/api/public/share/download", json={"token": token})


def test_link_works_without_an_account_and_is_audited(world, db):
    link = make_link(world)
    assert link["path"].startswith("/share#")  # token in the fragment, never in the request line
    r = info(world, link["token"])
    assert r.status_code == 200 and r.json()["uses_left"] == 3
    r = download(world, link["token"])
    assert r.status_code == 200 and r.content == PDF_A
    rows = audit_rows(db, action="share_link.download", outcome="allowed")
    assert rows and json.loads(rows[-1]["details"])["link_id"] == link["id"]


def test_token_is_stored_hashed(world, db):
    link = make_link(world)
    stored = db.execute("SELECT token_hash FROM share_links WHERE id = ?", (link["id"],)).fetchone()[0]
    assert link["token"] != stored and len(stored) == 64
    listed = world["alice"].get(f"/api/documents/{world.doc_a}/share-links").json()["items"]
    assert "token" not in listed[0]  # shown once at creation, never again


def test_revoked_link_stops_immediately(world):
    link = make_link(world)
    assert download(world, link["token"]).status_code == 200
    assert world["alice"].delete(f"/api/documents/{world.doc_a}/share-links/{link['id']}").status_code == 200
    assert info(world, link["token"]).status_code == 404
    assert download(world, link["token"]).status_code == 404


def test_expired_link_refused(world, db):
    link = make_link(world)
    with transaction(db) as tx:
        tx.execute("UPDATE share_links SET expires_at = ? WHERE id = ?", (iso_in(seconds=-1), link["id"]))
    assert info(world, link["token"]).status_code == 404
    assert download(world, link["token"]).status_code == 404


def test_use_limit(world):
    link = make_link(world, uses=2)
    assert download(world, link["token"]).status_code == 200
    assert download(world, link["token"]).status_code == 200
    assert info(world, link["token"]).status_code == 404
    assert download(world, link["token"]).status_code == 404


def test_last_use_cannot_be_taken_twice_concurrently(world):
    link = make_link(world, uses=1)
    results = []

    def go():
        results.append(download(world, link["token"]).status_code)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(200) == 1, results


def test_link_dies_with_the_document(world):
    link = make_link(world)
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    assert info(world, link["token"]).status_code == 404
    assert download(world, link["token"]).status_code == 404
    world["alice"].post(f"/api/documents/{world.doc_a}/restore")
    assert download(world, link["token"]).status_code == 200


def test_link_dies_when_creator_is_no_longer_owner(world, db):
    link = make_link(world)
    with transaction(db) as tx:  # ownership moved to bob (e.g. hand-over)
        tx.execute("UPDATE documents SET owner_id = ? WHERE id = ?", (world.ids["bob"], world.doc_a))
    assert info(world, link["token"]).status_code == 404


def test_link_dies_when_creator_deactivated(world):
    link = make_link(world)
    world["admin"].patch(f"/api/admin/users/{world.ids['alice']}", json={"is_active": False})
    assert info(world, link["token"]).status_code == 404


def test_lifetime_and_use_caps(world):
    r = world["alice"].post(f"/api/documents/{world.doc_a}/share-links", json={"expires_in_hours": 24 * 30, "max_uses": 1})
    assert r.status_code == 400
    r = world["alice"].post(f"/api/documents/{world.doc_a}/share-links", json={"expires_in_hours": 1, "max_uses": 5000})
    assert r.status_code == 400


def test_guessed_tokens_are_refused_and_audited(world, db):
    for _ in range(3):
        assert download(world, "A" * 43).status_code == 404
    assert len([r for r in audit_rows(db, outcome="denied") if '"unknown_token"' in r["details"]]) == 3


def test_link_is_read_only(world):
    link = make_link(world)
    anon = world.anon()
    for method, url in [("PATCH", f"/api/documents/{world.doc_a}"), ("DELETE", f"/api/documents/{world.doc_a}"),
                        ("POST", f"/api/documents/{world.doc_a}/versions")]:
        r = anon.request(method, url, headers={"Authorization": f"Bearer {link['token']}"})
        assert r.status_code in (401, 422), (method, url, r.status_code)
