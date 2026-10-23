"""Administrator powers and their limits, and the alert rules.
THREATS.md: T07, T46, T66."""
from __future__ import annotations

import pytest

from trustvault.alerts import compute_alerts
from trustvault.audit import AuditContext
from trustvault.db import transaction

ADMIN_GETS = ["/api/admin/users", "/api/admin/audit", "/api/admin/audit/verify", "/api/admin/alerts",
              "/api/admin/stats", "/api/admin/documents"]


@pytest.mark.parametrize("who", ["alice", "carol", "erin"])
def test_non_admins_cannot_use_admin_api(world, who):
    c = world[who]
    for url in ADMIN_GETS:
        assert c.get(url).status_code == 403, url
    assert c.post("/api/admin/users", json={"username": "mallory", "display_name": "M", "role": "admin",
                                            "password": "Mallory-pass-2026"}).status_code == 403
    assert c.patch(f"/api/admin/users/{world.ids[who]}", json={"role": "admin"}).status_code == 403
    assert c.delete(f"/api/admin/grants/{world.grant_carol}").status_code == 403


def test_admin_sees_metadata_but_never_content(world):
    admin = world["admin"]
    docs = admin.get("/api/admin/documents").json()["items"]
    assert {d["name"] for d in docs} == {"Salary letter - Carol.pdf", "Bridge drawing rev B.png"}
    access = admin.get(f"/api/admin/documents/{world.doc_a}/access").json()
    assert {g["username"] for g in access["grants"]} == {"carol", "dave", "erin", "gina"}
    assert {g["username"] for g in access["grants"] if g["expired"]} == {"erin"}
    assert admin.get(f"/api/documents/{world.doc_a}/download").status_code == 403
    assert admin.get(f"/api/documents/{world.doc_a}/versions/{world.version_a1}/download").status_code == 403


def test_admin_cannot_grant_and_cannot_be_granted(world):
    assert world["admin"].post(f"/api/documents/{world.doc_a}/grants",
                               json={"username": "admin", "permission": "view"}).status_code == 403
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "admin", "permission": "view"})
    assert r.status_code == 400
    r = world["alice"].post(f"/api/documents/{world.doc_a}/links", json={"username": "admin"})
    assert r.status_code == 400  # no share link for an admin either


def test_admin_emergency_revoke_is_reduce_only(world, db):
    assert world["admin"].delete(f"/api/admin/grants/{world.grant_carol}").status_code == 200
    assert world["carol"].get(f"/api/documents/{world.doc_a}").status_code == 403
    row = db.execute("SELECT details FROM audit_log WHERE action = 'access.revoked' ORDER BY seq DESC").fetchone()
    assert '"by_admin":true' in row[0]


def test_admin_can_kill_every_share_link_of_a_document(world):
    link = world["alice"].post(f"/api/documents/{world.doc_a}/links", json={"username": "gina"}).json()
    gina = world["gina"]
    assert gina.post("/api/links/open", json={"token": link["token"]}).status_code == 200
    assert world["admin"].post(f"/api/admin/documents/{world.doc_a}/links/revoke-all").status_code == 200
    assert gina.post("/api/links/open", json={"token": link["token"]}).status_code == 403
    assert world["alice"].post(f"/api/admin/documents/{world.doc_a}/links/revoke-all").status_code == 403


def test_admin_cannot_lock_themselves_out(world, db):
    me = world.ids["admin"]
    assert world["admin"].patch(f"/api/admin/users/{me}", json={"is_active": False}).status_code == 400
    assert world["admin"].patch(f"/api/admin/users/{me}", json={"role": "viewer"}).status_code == 400


def test_another_admin_can_remove_an_admin_and_its_session_dies(world):
    from conftest import Client
    r = world["admin"].post("/api/admin/users", json={"username": "admin2", "display_name": "Second Admin",
                                                       "role": "admin", "password": "Second-admin-2026"})
    assert r.status_code == 201
    second = Client(world.app)
    assert second.login("admin2", "Second-admin-2026").status_code == 200
    assert second.patch(f"/api/admin/users/{world.ids['admin']}", json={"is_active": False}).status_code == 200
    assert world["admin"].get("/api/admin/users").status_code == 401
    # admin2 is now the only admin and - like every admin - cannot remove itself.
    assert second.patch(f"/api/admin/users/{r.json()['id']}", json={"is_active": False}).status_code == 400


def test_user_lifecycle_is_audited(world, db):
    admin = world["admin"]
    uid = admin.post("/api/admin/users", json={"username": "grace", "display_name": "Grace", "role": "viewer",
                                               "password": "Fresh-start-2026!"}).json()["id"]
    admin.patch(f"/api/admin/users/{uid}", json={"role": "owner"})
    admin.patch(f"/api/admin/users/{uid}", json={"is_active": False})
    actions = [r["action"] for r in db.execute("SELECT action FROM audit_log WHERE target_user_id = ?", (uid,))]
    assert actions == ["user.create", "user.update", "user.update"]
    assert admin.post("/api/admin/users", json={"username": "grace", "display_name": "G", "role": "viewer",
                                                "password": "Fresh-start-2026!"}).status_code == 409
    assert admin.post("/api/admin/users", json={"username": "weak", "display_name": "W", "role": "viewer",
                                                "password": "short"}).status_code == 400


def test_directory_is_for_owners_only(world):
    assert world["alice"].get("/api/users/directory").status_code == 200
    names = {u["username"] for u in world["alice"].get("/api/users/directory").json()["items"]}
    assert "admin" not in names and "alice" not in names
    assert world["carol"].get("/api/users/directory").status_code == 403
    assert world["erin"].get("/api/users/directory").status_code == 403


def test_grant_to_inactive_user_refused(world):
    world["admin"].patch(f"/api/admin/users/{world.ids['frank']}", json={"is_active": False})
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "frank", "permission": "view"})
    assert r.status_code == 400


def test_grant_validation(world):
    a = world["alice"]
    assert a.post(f"/api/documents/{world.doc_a}/grants", json={"username": "ghost", "permission": "view"}).status_code == 404
    assert a.post(f"/api/documents/{world.doc_a}/grants", json={"username": "alice", "permission": "view"}).status_code == 400
    assert a.post(f"/api/documents/{world.doc_a}/grants", json={"username": "bob", "permission": "owner"}).status_code == 422
    assert a.post(f"/api/documents/{world.doc_a}/grants",
                  json={"username": "bob", "permission": "view", "expires_at": "2000-01-01T00:00:00Z"}).status_code == 400


# --------------------------------------------------------------------- alerts
def _emit(world, db, n, action, outcome, actor=("u1", "mallory"), ip="1.2.3.4", **kw):
    audit = world.app.state.ctx.audit
    for i in range(n):
        with transaction(db) as tx:
            audit.append(tx, AuditContext(actor[0], actor[1], ip if isinstance(ip, str) else ip[i], "pytest"),
                         action, outcome, **{k: (v(i) if callable(v) else v) for k, v in kw.items()})


def rules(db, world):
    return {a["rule"] for a in compute_alerts(db, 24, world.app.state.ctx.audit.verify(db).as_dict())}


def test_alert_on_access_probing(world, db):
    _emit(world, db, 6, "document.download", "denied", details={"reason": "no_permission"})
    assert "access_probing" in rules(db, world)


def test_rejected_uploads_are_not_reported_as_probing(world, db):
    """Regression: the first version of the rule counted an owner's rejected
    uploads (wrong file type) as 'refused document access' and raised a
    false 'possible id probing' alert against them."""
    for i in range(6):
        world["alice"].post("/api/documents", files={"file": (f"bad{i}.html", b"<b>x</b>", "text/html")},
                            data={"category": "general"})
    assert "access_probing" not in rules(db, world)


def test_alert_on_bulk_download(world, db):
    _emit(world, db, 12, "document.download", "allowed", document_id=lambda i: f"doc-{i:04d}-xxxxxxxxxxxx")
    assert "bulk_download" in rules(db, world)


def test_alert_on_credential_stuffing_and_guessing(world, db):
    _emit(world, db, 6, "auth.login", "denied", actor=(None, "carol"), details={"reason": "bad_password"})
    _emit(world, db, 11, "auth.login", "denied", actor=(None, "someone"), ip="6.6.6.6",
          details={"reason": "unknown_user"})
    got = rules(db, world)
    assert "password_guessing" in got and "credential_stuffing" in got


def test_alert_on_forwarded_and_tampered_links(world, db):
    link = world["alice"].post(f"/api/documents/{world.doc_a}/links", json={"username": "gina"}).json()
    assert world["bob"].post("/api/links/open", json={"token": link["token"]}).status_code == 403
    assert "forwarded_link" in rules(db, world)
    head, body, sig = link["token"].split(".")
    for i in range(3):
        forged = f"{head}.{body}.{'B' * (len(sig) - 1)}{i}"
        assert world["bob"].post("/api/links/open", json={"token": forged}).status_code == 403
    assert "link_tampering" in rules(db, world)


def test_alert_on_new_admin_and_external_edit(world, db):
    world["admin"].post("/api/admin/users", json={"username": "boss", "display_name": "Boss", "role": "admin",
                                                  "password": "Corner-office-2026"})
    world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "erin", "permission": "edit"})
    got = rules(db, world)
    assert "privilege_change" in got and "external_edit_grant" in got


def test_admin_impersonation_after_password_reset_is_flagged(world, db):
    """The one route by which an admin could reach content: reset a user's
    password and sign in as them. It cannot be prevented without an
    out-of-band channel, so it is made loud."""
    from conftest import Client
    r = world["admin"].post(f"/api/admin/users/{world.ids['carol']}/reset-password",
                            json={"new_password": "Admin-chosen-2026"})
    assert r.status_code == 200
    assert Client(world.app).login("carol", "Admin-chosen-2026").status_code == 200  # same test client IP
    got = rules(db, world)
    assert "admin_password_reset" in got and "possible_impersonation" in got


def test_quiet_system_raises_no_alerts(world, db):
    assert rules(db, world) == set()


# ------------------------------------------------------------- deleting users
def test_admin_deletes_a_user_everything_ends_and_it_is_final(world, db):
    from conftest import Client
    other = world.fresh("carol")
    r = world["admin"].delete(f"/api/admin/users/{world.ids['carol']}")
    assert r.status_code == 200 and r.json()["grants_removed"] == 1
    assert world["carol"].get("/api/auth/me").status_code == 401           # sessions gone
    assert other.get("/api/auth/me").status_code == 401
    assert Client(world.app).login("carol").status_code == 401             # cannot sign in
    assert db.execute("SELECT COUNT(*) FROM grants WHERE user_id = ?", (world.ids["carol"],)).fetchone()[0] == 0
    assert "carol" not in {u["username"] for u in world["alice"].get("/api/users/directory").json()["items"]}
    # Final: cannot be re-activated, re-roled, given a password or unlocked ...
    admin = world["admin"]
    assert admin.patch(f"/api/admin/users/{world.ids['carol']}", json={"is_active": True}).status_code == 409
    assert admin.post(f"/api/admin/users/{world.ids['carol']}/reset-password",
                      json={"new_password": "Comeback-attempt-2026"}).status_code == 409
    assert admin.post(f"/api/admin/users/{world.ids['carol']}/unlock").status_code == 409
    assert admin.delete(f"/api/admin/users/{world.ids['carol']}").status_code == 409
    assert Client(world.app).login("carol").status_code == 401
    # ... and the username cannot be re-used to impersonate them in the audit trail.
    assert admin.post("/api/admin/users", json={"username": "carol", "display_name": "Fake Carol", "role": "viewer",
                                                "password": "Brand-new-pass-2026"}).status_code == 409
    # The audit trail still names them.
    row = db.execute("SELECT details FROM audit_log WHERE action = 'user.delete'").fetchone()
    assert '"username":"carol"' in row[0]
    listed = {u["username"]: u for u in admin.get("/api/admin/users").json()["items"]}
    assert listed["carol"]["deleted_at"] and listed["carol"]["is_active"] is False


def test_admin_cannot_delete_themselves(world):
    assert world["admin"].delete(f"/api/admin/users/{world.ids['admin']}").status_code == 400
    assert world["admin"].get("/api/admin/users").status_code == 200


def test_owner_with_documents_cannot_be_deleted(world):
    r = world["admin"].delete(f"/api/admin/users/{world.ids['alice']}")
    assert r.status_code == 409 and "owns" in r.json()["detail"]
    assert world["alice"].get("/api/auth/me").status_code == 200


def test_only_admins_can_delete_users(world):
    for who in ("alice", "carol", "gina"):
        assert world[who].delete(f"/api/admin/users/{world.ids['dave']}").status_code == 403
    assert world["dave"].get("/api/auth/me").status_code == 200
