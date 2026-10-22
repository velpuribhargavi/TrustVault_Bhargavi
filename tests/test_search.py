"""Search must never reveal documents the caller cannot open - not by name,
owner filter, wildcard, count or trash.  THREATS.md: T06."""
from __future__ import annotations

from datetime import date, timedelta

from conftest import PDF_A, make_pdf
from trustvault.db import transaction


def names(resp):
    assert resp.status_code == 200, resp.text
    return {d["name"] for d in resp.json()["items"]}


def test_search_by_name_owner_category_and_date(world):
    alice = world["alice"]
    alice.upload("Q3 contract Acme.pdf", make_pdf(b"acme"), category="contract")
    assert names(alice.get("/api/documents", params={"q": "acme"})) == {"Q3 contract Acme.pdf"}
    assert names(alice.get("/api/documents", params={"category": "hr"})) == {"Salary letter - Carol.pdf"}
    assert names(alice.get("/api/documents", params={"owner": "alice"})) == {"Salary letter - Carol.pdf", "Q3 contract Acme.pdf"}
    today = date.today()
    assert len(names(alice.get("/api/documents", params={"date_from": str(today - timedelta(days=1)),
                                                           "date_to": str(today + timedelta(days=1))}))) == 2
    assert names(alice.get("/api/documents", params={"date_to": str(today - timedelta(days=2))})) == set()
    assert names(alice.get("/api/documents", params={"scope": "shared"})) == set()


def test_outsider_finds_nothing_of_others(world):
    bob = world["bob"]
    assert names(bob.get("/api/documents", params={"q": "Salary"})) == set()
    assert names(bob.get("/api/documents", params={"owner": "alice"})) == set()
    assert names(bob.get("/api/documents", params={"category": "hr"})) == set()
    resp = bob.get("/api/documents")
    assert names(resp) == {"Bridge drawing rev B.png"}
    assert resp.json()["total"] == 1  # the count does not leak either


def test_like_wildcards_are_literal(world):
    for q in ["%", "_", "%%", "\\", "'", "' OR '1'='1"]:
        assert "Salary letter - Carol.pdf" not in names(world["bob"].get("/api/documents", params={"q": q})), q


def test_grantee_sees_shared_document(world):
    assert names(world["carol"].get("/api/documents")) == {"Salary letter - Carol.pdf"}
    shared = world["carol"].get("/api/documents", params={"scope": "shared"}).json()["items"]
    assert shared[0]["my_permission"] == "download"
    assert world["gina"].get("/api/documents").json()["items"][0]["my_permission"] == "view"


def test_expired_grant_disappears_from_search(world):
    assert names(world["erin"].get("/api/documents")) == set()
    assert names(world["erin"].get("/api/documents", params={"q": "Salary"})) == set()


def test_trashed_document_disappears_from_grantee_search(world):
    assert world["alice"].delete(f"/api/documents/{world.doc_a}").status_code == 200
    assert names(world["carol"].get("/api/documents")) == set()
    assert names(world["alice"].get("/api/documents")) == set()
    assert {d["name"] for d in world["alice"].get("/api/documents/trash").json()["items"]} == {"Salary letter - Carol.pdf"}
    # carol cannot list alice's trash at all (viewer role)
    assert world["carol"].get("/api/documents/trash").status_code == 403


def test_admin_search_sees_nothing_even_with_grant_row(world, db):
    from trustvault.utils import new_id, now_iso
    with transaction(db) as tx:
        tx.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) "
                   "VALUES (?, ?, ?, 'view', ?, ?)", (new_id(), world.doc_a, world.ids["admin"], world.ids["alice"], now_iso()))
    assert names(world["admin"].get("/api/documents")) == set()


def test_search_paging_and_sorting(world):
    for i in range(3):
        world["frank"].upload(f"Doc {i}.pdf", make_pdf(bytes([65 + i])), category="general")
    r = world["frank"].get("/api/documents", params={"page_size": 2, "sort": "name_asc"}).json()
    assert r["total"] == 3 and [d["name"] for d in r["items"]] == ["Doc 0.pdf", "Doc 1.pdf"]
    r = world["frank"].get("/api/documents", params={"page_size": 2, "page": 2, "sort": "name_asc"}).json()
    assert [d["name"] for d in r["items"]] == ["Doc 2.pdf"]
    assert world["frank"].get("/api/documents", params={"sort": "name; DROP TABLE users"}).status_code == 422
    assert world["frank"].get("/api/documents", params={"page_size": 1000}).status_code == 422
    assert PDF_A  # fixture sanity
