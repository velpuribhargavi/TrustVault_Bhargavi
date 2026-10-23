"""Unit tests of check_access() - the one function that decides document access.

Some checks are defence in depth: the HTTP layer would already stop the
request (a deactivated user has no session). These tests call check_access()
directly so that *each* check is proven to matter on its own, and they pin the
internal reason recorded for every kind of refusal, in order.

THREATS.md: T01, T04, T07, T10, T64 (uniform refusal), T66 (links).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from trustvault.authz import DENIAL_REASONS, Action, check_access
from trustvault.db import transaction
from trustvault.links import issue
from trustvault.utils import iso_in, new_id, now_iso, utcnow


def _user(db, uid):
    return dict(db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())


def _check(world, db, who, doc_id, action=Action.VIEW, **kw):
    return check_access(db, world.app.state.ctx.keyring, _user(db, world.ids[who]), doc_id, action, **kw)


def _link(world, db, recipient="frank", doc=None, permission="view", creator="alice", ttl=300, now=None):
    doc_id = doc or world.doc_a
    av = db.execute("SELECT access_version FROM documents WHERE id = ?", (doc_id,)).fetchone()[0]
    token, _ = issue(world.app.state.ctx.keyring, document_id=doc_id, recipient_id=world.ids[recipient],
                     creator_id=world.ids[creator], permission=permission, access_version=av,
                     now_ts=int((now or utcnow()).timestamp()), ttl_seconds=ttl)
    return token


def test_levels_owner_edit_download_view(world, db):
    expected = {"alice": "owner", "dave": "edit", "carol": "download", "gina": "view"}
    for who, level in expected.items():
        d = _check(world, db, who, world.doc_a)
        assert d.allowed and d.permission == level, who
    assert _check(world, db, "alice", world.doc_a).via == "owner"
    assert _check(world, db, "carol", world.doc_a).via == "grant"


def test_inactive_user_gets_nothing_even_with_a_grant(world, db):
    carol = _user(db, world.ids["carol"])
    carol["is_active"] = 0
    d = check_access(db, world.app.state.ctx.keyring, carol, world.doc_a, Action.VIEW)
    assert not d.allowed and d.reason == "user_inactive"


def test_inactive_owner_gets_nothing(world, db):
    alice = _user(db, world.ids["alice"])
    alice["is_active"] = 0
    assert check_access(db, world.app.state.ctx.keyring, alice, world.doc_a, Action.VIEW).reason == "user_inactive"


def test_admin_gets_nothing_even_with_a_grant_row_or_a_link(world, db):
    # The API refuses to grant to an admin; simulate a grant written some other way.
    with transaction(db) as tx:
        tx.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at) "
                   "VALUES (?, ?, ?, 'edit', ?, ?, ?)",
                   (new_id(), world.doc_a, world.ids["admin"], world.ids["alice"], now_iso(), iso_in(days=1)))
    d = _check(world, db, "admin", world.doc_a, link_token=_link(world, db, recipient="admin"))
    assert not d.allowed and d.reason == "admin_never_reads_content"
    # and over HTTP
    assert world["admin"].get(f"/api/documents/{world.doc_a}/download").status_code == 403
    assert world["admin"].get("/api/documents").json()["items"] == []


def test_expired_grant_is_ignored(world, db):
    d = _check(world, db, "erin", world.doc_a)
    assert not d.allowed and d.reason == "grant_expired"


def test_grant_expiring_in_future_works_until_it_passes(world, db, clock):
    with transaction(db) as tx:
        tx.execute("UPDATE grants SET expires_at = ? WHERE id = ?", (iso_in(minutes=5), world.grant_carol))
    assert _check(world, db, "carol", world.doc_a).permission == "download"
    clock.advance(minutes=5, seconds=1)
    assert _check(world, db, "carol", world.doc_a).reason == "grant_expired"
    assert world["carol"].get(f"/api/documents/{world.doc_a}/download").status_code == 403


def test_grant_on_one_document_does_not_open_another(world, db):
    # carol holds a grant on DOC_A only.
    assert _check(world, db, "carol", world.doc_b).reason == "no_grant"
    assert world["carol"].get(f"/api/documents/{world.doc_b}").status_code == 403


def test_someone_elses_grant_does_not_apply_to_me(world, db):
    assert _check(world, db, "frank", world.doc_a).reason == "no_grant"


def test_revoked_grant_is_recorded_as_revoked_not_never_shared(world, db):
    assert world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{world.grant_carol}").status_code == 200
    assert _check(world, db, "carol", world.doc_a).reason == "grant_revoked"


def test_document_reasons(world, db):
    assert _check(world, db, "alice", "../../etc/passwd").reason == "not_found"
    assert _check(world, db, "alice", new_id()).reason == "not_found"
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    assert _check(world, db, "dave", world.doc_a).reason == "in_trash"
    assert _check(world, db, "bob", world.doc_a).reason == "in_trash"
    assert _check(world, db, "alice", world.doc_a).allowed  # the owner may still look at it in the trash
    assert _check(world, db, "alice", world.doc_a, Action.DOWNLOAD).reason == "in_trash"
    world["alice"].delete(f"/api/documents/{world.doc_a}/purge")
    assert _check(world, db, "alice", world.doc_a).reason == "not_found"
    assert world["alice"].get(f"/api/documents/{world.doc_a}").status_code == 403  # destroyed = gone, even for its owner


def test_level_reasons(world, db):
    assert _check(world, db, "gina", world.doc_a, Action.DOWNLOAD).reason == "view_only"
    assert _check(world, db, "gina", world.doc_a, Action.EDIT).reason == "view_only"
    assert _check(world, db, "carol", world.doc_a, Action.EDIT).reason == "download_cannot_edit"
    assert _check(world, db, "dave", world.doc_a, Action.SHARE).reason == "edit_cannot_share"


def test_version_must_belong_to_the_document(world, db):
    d = _check(world, db, "carol", world.doc_a, Action.DOWNLOAD, version_id=world.version_b1)
    assert not d.allowed and d.reason == "version_not_in_document"
    assert _check(world, db, "carol", world.doc_a, Action.DOWNLOAD, version_id=world.version_a1).allowed


# ------------------------------------------------------------------ links
def test_a_link_works_for_its_recipient_who_holds_a_grant(world, db):
    d = _check(world, db, "gina", world.doc_a, link_token=_link(world, db, recipient="gina"))
    assert d.allowed and d.via == "link" and d.permission == "view"
    # through a link, access ends when the link (5 min) or the grant ends, whichever is first
    assert d.access_expires_at < d.grant["expires_at"]


def test_a_link_never_gives_access_on_its_own(world, db):
    d = _check(world, db, "frank", world.doc_a, link_token=_link(world, db, recipient="frank"))
    assert not d.allowed and d.reason == "no_grant"
    d = _check(world, db, "erin", world.doc_a, link_token=_link(world, db, recipient="erin"))
    assert not d.allowed and d.reason == "grant_expired"


def test_link_reasons_in_order(world, db):
    good = _link(world, db, recipient="gina")
    head, body, sig = good.split(".")
    tampered = f"{head}.{body}.{'A' * len(sig)}"
    assert _check(world, db, "gina", world.doc_a, link_token=tampered).reason == "link_invalid"
    assert _check(world, db, "gina", world.doc_a, link_token="garbage").reason == "link_invalid"
    assert _check(world, db, "gina", world.doc_b, link_token=good).reason == "link_wrong_document"
    assert _check(world, db, "carol", world.doc_a, link_token=good).reason == "wrong_user"  # even with her own grant
    old = _link(world, db, recipient="gina", now=utcnow() - timedelta(seconds=301))
    assert _check(world, db, "gina", world.doc_a, link_token=old).reason == "link_expired"
    by_bob = _link(world, db, recipient="gina", creator="bob")  # bob does not own DOC_A
    assert _check(world, db, "gina", world.doc_a, link_token=by_bob).reason == "link_owner_changed"
    with transaction(db) as tx:
        tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (world.doc_a,))
    assert _check(world, db, "gina", world.doc_a, link_token=good).reason == "link_revoked"


def test_a_request_through_a_bad_link_is_refused_even_with_a_grant(world, db):
    """If the request came through a link, the link must be valid (spec step 6)."""
    d = _check(world, db, "carol", world.doc_a, Action.DOWNLOAD, link_token="garbage")
    assert not d.allowed and d.reason == "link_invalid"
    assert _check(world, db, "carol", world.doc_a, Action.DOWNLOAD).allowed  # without the link: her grant


def test_a_link_caps_the_level_and_never_raises_it(world, db):
    view_link = _link(world, db, recipient="dave", permission="view")
    d = _check(world, db, "dave", world.doc_a, Action.DOWNLOAD, link_token=view_link)
    assert not d.allowed and d.reason == "view_only"
    d = _check(world, db, "dave", world.doc_a, Action.VIEW, link_token=view_link)
    assert d.allowed and d.permission == "view"
    # a forged-looking "download" link for a View-only person still cannot download
    d = _check(world, db, "gina", world.doc_a, Action.DOWNLOAD, link_token=_link(world, db, recipient="gina",
                                                                                 permission="download"))
    assert not d.allowed and d.reason == "view_only"
    with pytest.raises(ValueError):
        _link(world, db, permission="edit")


def test_every_reason_is_documented():
    """The reasons check_access can produce are exactly the documented, ordered list."""
    seen = {"not_found", "user_inactive", "admin_never_reads_content", "in_trash", "link_invalid",
            "link_wrong_document", "wrong_user", "no_grant", "grant_revoked", "grant_expired", "view_only",
            "link_expired", "link_revoked", "link_owner_changed", "version_not_in_document"}
    assert set(DENIAL_REASONS) == seen
