"""AI-assisted sharing: suggestions help, but the machine never widens access
on its own, never leaks other owners' sharing, and everything is audited.
THREATS.md: T18."""
from __future__ import annotations

import json

from conftest import audit_rows, make_pdf


def _history(world):
    """alice has shared two other HR documents with frank before."""
    for n in ("Salary letter - Bob.pdf", "Salary review 2026.pdf"):
        d = world["alice"].upload(n, make_pdf(n.encode()), category="hr")
        assert world["alice"].post(f"/api/documents/{d}/grants",
                                   json={"username": "frank", "permission": "view"}).status_code == 201


def _grant_count(db):
    return db.execute("SELECT COUNT(*) FROM grants").fetchone()[0]


def test_suggestions_never_grant_by_themselves(world, db):
    _history(world)
    before = _grant_count(db)
    items = world["alice"].get(f"/api/documents/{world.doc_a}/suggestions").json()["items"]
    assert [i["username"] for i in items] == ["frank"]
    assert items[0]["permission"] == "view" and items[0]["reasons"]  # least privilege: never download/edit
    assert _grant_count(db) == before  # nothing changed
    assert world["frank"].get(f"/api/documents/{world.doc_a}").status_code == 403


def test_confirmed_suggestion_records_both_suggestion_and_decision(world, db):
    _history(world)
    sug = world["alice"].get(f"/api/documents/{world.doc_a}/suggestions").json()["items"][0]
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": "frank", "permission": "view", "suggestion_id": sug["suggestion_id"]})
    assert r.status_code == 201 and r.json()["source"] == "suggestion"
    generated = audit_rows(db, action="ai.suggestion.generated", document_id=world.doc_a)
    assert generated and json.loads(generated[-1]["details"])["suggestions"][0]["username"] == "frank"
    accepted = audit_rows(db, action="ai.suggestion.accepted", document_id=world.doc_a)
    assert accepted and accepted[-1]["actor_name"] == "alice"
    grant = audit_rows(db, action="access.granted", document_id=world.doc_a)[-1]
    assert json.loads(grant["details"])["suggestion_id"] == sug["suggestion_id"]
    assert world["frank"].get(f"/api/documents/{world.doc_a}").status_code == 200
    # a suggestion can only be used once
    again = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                                json={"username": "frank", "permission": "view", "suggestion_id": sug["suggestion_id"]})
    assert again.status_code == 400


def test_suggestion_cannot_be_redirected_to_another_person(world, db):
    _history(world)
    sug = world["alice"].get(f"/api/documents/{world.doc_a}/suggestions").json()["items"][0]
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": "bob", "permission": "view", "suggestion_id": sug["suggestion_id"]})
    assert r.status_code == 400


def test_dismissal_is_audited(world, db):
    _history(world)
    sug = world["alice"].get(f"/api/documents/{world.doc_a}/suggestions").json()["items"][0]
    assert world["alice"].post(f"/api/documents/{world.doc_a}/suggestions/{sug['suggestion_id']}/dismiss").status_code == 200
    assert audit_rows(db, action="ai.suggestion.dismissed", document_id=world.doc_a)


def test_suggestions_do_not_leak_other_owners_sharing(world):
    """bob shares lots of HR documents with dave. That must not make dave
    appear in *alice's* suggestions - it would reveal bob's sharing."""
    for i in range(3):
        d = world["bob"].upload(f"Salary letter {i}.pdf", make_pdf(bytes([i])), category="hr")
        world["bob"].post(f"/api/documents/{d}/grants", json={"username": "frank", "permission": "view"})
    doc = world["alice"].upload("Salary letter - Frank.pdf", make_pdf(b"f"), category="hr")
    items = world["alice"].get(f"/api/documents/{doc}/suggestions").json()["items"]
    assert "frank" not in {i["username"] for i in items}


def test_only_owner_may_ask_for_suggestions(world):
    assert world["dave"].get(f"/api/documents/{world.doc_a}/suggestions").status_code == 403
    assert world["bob"].get(f"/api/documents/{world.doc_a}/suggestions").status_code == 403


def test_never_suggests_admins_inactive_or_existing(world):
    _history(world)
    world["admin"].patch(f"/api/admin/users/{world.ids['frank']}", json={"is_active": False})
    items = world["alice"].get(f"/api/documents/{world.doc_a}/suggestions").json()["items"]
    names = {i["username"] for i in items}
    assert not names & {"frank", "admin", "carol", "dave", "alice"}
