"""The core promise: a document is reachable only by someone who was granted it.

Every document endpoint is called by every kind of caller and the status
code is checked against the permission model. Every refusal must also leave
(a) no side effect and (b) a 'denied' row in the audit trail.

THREATS.md: T01 (IDOR), T04 (privilege escalation), T07 (admin reads content),
T10 (expired grant), T39 (refusals recorded), T60 (view-only cannot download).
"""
from __future__ import annotations

import pytest

from conftest import PDF_A, audit_rows, make_pdf

OK = "ok"

# action -> (method, url template, request kwargs, mutates?)
ACTIONS = {
    "view": ("GET", "/api/documents/{doc}", {}, False),
    "preview": ("GET", "/api/documents/{doc}/preview", {}, False),
    "preview_page": ("GET", "/api/documents/{doc}/preview/pages/{page}", {}, False),
    "download": ("GET", "/api/documents/{doc}/download", {}, False),
    "version_download": ("GET", "/api/documents/{doc}/versions/{ver}/download", {}, False),
    "rename": ("PATCH", "/api/documents/{doc}", {"json": {"name": "Renamed by attacker"}}, True),
    "new_version": ("POST", "/api/documents/{doc}/versions",
                    {"files": {"file": ("v2.pdf", make_pdf(b"v2"), "application/pdf")}}, True),
    "list_grants": ("GET", "/api/documents/{doc}/grants", {}, False),
    "grant": ("POST", "/api/documents/{doc}/grants", {"json": {"username": "frank", "permission": "edit"}}, True),
    "revoke": ("DELETE", "/api/documents/{doc}/grants/{grant}", {}, True),
    "list_links": ("GET", "/api/documents/{doc}/share-links", {}, False),
    "create_link": ("POST", "/api/documents/{doc}/share-links", {"json": {"expires_in_hours": 1, "max_uses": 1}}, True),
    "suggestions": ("GET", "/api/documents/{doc}/suggestions", {}, False),
    "activity": ("GET", "/api/documents/{doc}/activity", {}, False),
    "delete": ("DELETE", "/api/documents/{doc}", {}, True),
}

VIEW_OK = {"view", "preview", "preview_page"}
DOWNLOAD_OK = VIEW_OK | {"download", "version_download"}
EDIT_OK = DOWNLOAD_OK | {"rename", "new_version"}

# caller -> expected status per action (OK = 2xx)
EXPECTED = {
    "alice": {a: OK for a in ACTIONS},                                 # owner
    "dave": {a: OK if a in EDIT_OK else 403 for a in ACTIONS},         # edit grant
    "carol": {a: OK if a in DOWNLOAD_OK else 403 for a in ACTIONS},    # download grant
    "gina": {a: OK if a in VIEW_OK else 403 for a in ACTIONS},         # view-only grant
    "bob": {a: 404 for a in ACTIONS},                                  # another owner, no grant
    "frank": {a: 404 for a in ACTIONS},                                # owner with no documents at all
    "erin": {a: 404 for a in ACTIONS},                                 # grant expired yesterday
    "admin": {a: 404 for a in ACTIONS},                                # admins never get content
    "anonymous": {a: 401 for a in ACTIONS},
}

CASES = [(caller, action) for caller in EXPECTED for action in ACTIONS]


def _snapshot(db, doc_id):
    doc = dict(db.execute("SELECT name, deleted_at, current_version_id FROM documents WHERE id = ?", (doc_id,)).fetchone())
    doc["grants"] = sorted(tuple(r) for r in db.execute(
        "SELECT user_id, permission FROM grants WHERE document_id = ?", (doc_id,)))
    doc["links"] = db.execute("SELECT COUNT(*) FROM share_links WHERE document_id = ?", (doc_id,)).fetchone()[0]
    doc["versions"] = db.execute("SELECT COUNT(*) FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()[0]
    return doc


@pytest.mark.parametrize("caller,action", CASES, ids=[f"{c}-{a}" for c, a in CASES])
def test_document_access_matrix(world, db, caller, action):
    method, template, kwargs, mutates = ACTIONS[action]
    url = template.format(doc=world.doc_a, ver=world.version_a1, grant=world.grant_carol, page=1)
    client = world.anon() if caller == "anonymous" else world[caller]
    before = _snapshot(db, world.doc_a)
    denied_before = len(audit_rows(db, outcome="denied"))

    response = client.request(method, url, **kwargs)
    expected = EXPECTED[caller][action]

    if expected == OK:
        assert 200 <= response.status_code < 300, f"{caller} should be able to {action}: {response.status_code} {response.text}"
        if action in ("download", "version_download"):
            assert response.content == PDF_A
        if action == "preview_page":  # a rendering, never the original file
            assert response.content.startswith(b"\x89PNG") and PDF_A not in response.content
        return

    assert response.status_code == expected, f"{caller} must not {action}: got {response.status_code} {response.text}"
    # A refusal must not leak the document's content or name ...
    assert PDF_A not in response.content
    assert b"Salary" not in response.content
    # ... must not change anything ...
    if mutates:
        assert _snapshot(db, world.doc_a) == before, f"denied {action} by {caller} still changed state"
    # ... and must be on the record (anonymous callers have no identity to record).
    if caller != "anonymous":
        denied = audit_rows(db, outcome="denied")
        assert len(denied) > denied_before, f"refused {action} by {caller} was not audited"
        assert denied[-1]["actor_id"] == world.ids[caller]


def test_matrix_covers_every_document_route(app):
    """If someone adds a document route, this fails until the matrix covers it."""
    covered = {(m, t.replace("{doc}", "{doc_id}").replace("{ver}", "{version_id}").replace("{grant}", "{grant_id}")
                .replace("{page}", "{page_no}"))
               for m, t, _, _ in ACTIONS.values()}
    covered |= {
        ("GET", "/api/documents"), ("POST", "/api/documents"), ("GET", "/api/documents/trash"),
        ("POST", "/api/documents/{doc_id}/restore"), ("DELETE", "/api/documents/{doc_id}/purge"),
        ("DELETE", "/api/documents/{doc_id}/share-links/{link_id}"),
        ("POST", "/api/documents/{doc_id}/suggestions/{suggestion_id}/dismiss"),
    }  # these are covered by dedicated tests (search, trash, share links, suggestions)
    routes = set()
    for path, ops in app.openapi()["paths"].items():
        if path.startswith("/api/documents"):
            for method in ops:
                routes.add((method.upper(), path))
    missing = routes - covered
    assert not missing, f"document routes without authorization tests: {missing}"
