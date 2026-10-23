"""Attack a RUNNING TrustVault the way a judge would, and report what held.

    python -m trustvault                      # in one terminal
    python scripts/attack_selftest.py         # in another
    python scripts/attack_selftest.py --base http://127.0.0.1:8000

Uses the three seeded demo logins (admin, owner, viewer); the admin and owner
sign in with two-step codes computed from the published demo keys. Every attempt is a
real HTTP request, so the refusals also show up in the audit trail and on the
admin "Worth noticing" panel. The script cleans up the grants and links it
creates.

Every refusal must be the same answer - 403 "You don't have access to this
file." - whether the document is missing, not shared, expired or too low a level.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustvault import totp  # noqa: E402

PASSWORDS = {"admin": "Keeper!Vault2026", "owner": "Author!Vault2026", "viewer": "Reader!Vault2026"}
NO_ACCESS = "You don't have access to this file."

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{'  - got ' + detail if detail and not ok else ''}")


def demo_keys() -> dict[str, str]:
    """The published two-step keys of the demo admin and owner (scripts/init_db.py)."""
    spec = importlib.util.spec_from_file_location("init_db", ROOT / "scripts" / "init_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DEMO_TOTP_KEYS


class User:
    def __init__(self, base: str, username: str):
        self.c = httpx.Client(base_url=base, timeout=30)
        r = self.c.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
        if r.status_code != 200:
            sys.exit(f"Cannot sign in as {username} ({r.status_code}). Did you run scripts/init_db.py --seed?")
        body = r.json()
        if body.get("two_factor") == "enroll":
            sys.exit(f"{username} has no two-step sign-in yet: run scripts/init_db.py --reset --seed for the demo keys.")
        if body.get("two_factor") == "verify":
            body = self._second_step(username, body["challenge"])
        self.csrf = body["csrf_token"]

    def _second_step(self, username: str, challenge: str) -> dict:
        key = demo_keys()[username]
        for _ in range(2):  # a code works once: if someone just used it, wait for the next one
            r = self.c.post("/api/auth/login/verify", json={"challenge": challenge, "code": totp.code_at(key, time.time())})
            if r.status_code == 200:
                return r.json()
            time.sleep(totp.STEP_SECONDS - time.time() % totp.STEP_SECONDS + 1)
        sys.exit(f"Two-step sign-in for {username} failed ({r.status_code}): is this computer's clock right?")

    def req(self, method: str, url: str, csrf: bool = True, **kw):
        headers = kw.pop("headers", {})
        if csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        return self.c.request(method, url, headers=headers, **kw)

    def code(self, method: str, url: str, **kw) -> int:
        return self.req(method, url, **kw).status_code

    def refused(self, method: str, url: str, **kw) -> bool:
        """True only for the one uniform refusal."""
        r = self.req(method, url, **kw)
        return r.status_code == 403 and r.headers.get("content-type", "").startswith("application/json") \
            and r.json().get("detail") == NO_ACCESS


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    base = ap.parse_args().base
    try:
        httpx.get(base + "/api/health", timeout=5)
    except httpx.HTTPError:
        sys.exit(f"TrustVault is not reachable at {base}. Start it with: python -m trustvault")

    anon = httpx.Client(base_url=base, timeout=30)
    print("\nSigning in (two-step sign-in for admin and owner)")
    r = anon.post("/api/auth/login", json={"username": "admin", "password": PASSWORDS["admin"]})
    step = r.json()
    check("the admin's right password alone opens no session", step.get("two_factor") == "verify"
          and "csrf_token" not in step and anon.get("/api/auth/me").status_code == 401)
    near = {totp.code_at(demo_keys()["admin"], time.time() + k * 30) for k in (-1, 0, 1)}
    bad = next(c for c in ("000000", "111111", "222222") if c not in near)
    r = anon.post("/api/auth/login/verify", json={"challenge": step.get("challenge", ""), "code": bad})
    check("a wrong two-step code is refused", r.status_code == 401 and anon.get("/api/auth/me").status_code == 401)
    owner, viewer, admin = User(base, "owner"), User(base, "viewer"), User(base, "admin")
    cookie = httpx.post(f"{base}/api/auth/login", json={"username": "viewer", "password": PASSWORDS["viewer"]}
                        ).headers.get("set-cookie", "").lower()
    check("the session cookie is HttpOnly and SameSite=Strict", "httponly" in cookie and "samesite=strict" in cookie)
    headers = anon.get("/").headers
    check("security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy",
          "frame-ancestors 'none'" in headers.get("content-security-policy", "")
          and headers.get("x-frame-options") == "DENY" and headers.get("x-content-type-options") == "nosniff"
          and headers.get("referrer-policy") == "no-referrer")

    docs = {d["name"]: d["id"] for d in owner.req("GET", "/api/documents").json()["items"]}
    salary = docs["Salary letter - Vikram"]            # viewer: view only
    contract = docs["Q3 services contract - Acme Corp"]  # viewer: view + download
    budget = docs["Budget 2026"]                         # viewer: edit
    private = docs["Board minutes - private"]            # viewer: nothing
    audit_papers = docs["Audit papers FY2025-26"]        # viewer: nothing
    private_version = owner.req("GET", f"/api/documents/{private}").json()["versions"][0]["id"]

    print("\nDirect object access (IDOR)")
    check("viewer cannot open the private board minutes by id", viewer.refused("GET", f"/api/documents/{private}"))
    check("viewer cannot download them", viewer.refused("GET", f"/api/documents/{private}/download"))
    check("viewer cannot render them in the viewer", viewer.refused("GET", f"/api/documents/{private}/preview"))
    check("viewer cannot pull the private file through a document they CAN see",
          viewer.refused("GET", f"/api/documents/{contract}/versions/{private_version}/download"))
    check("a made-up id gets exactly the same answer (nothing to learn by probing)",
          viewer.refused("GET", "/api/documents/AAAAAAAAAAAAAAAAAAAAAA"))
    check("anonymous gets 401", anon.get(f"/api/documents/{private}/download").status_code == 401)
    check("admin cannot read content", admin.refused("GET", f"/api/documents/{private}/download"))
    check("admin cannot render content", admin.refused("GET", f"/api/documents/{private}/preview"))

    print("\nView only means view only")
    check("viewer CAN read the view-only salary letter in the browser",
          viewer.code("GET", f"/api/documents/{salary}/preview") == 200)
    page = viewer.req("GET", f"/api/documents/{salary}/preview/pages/1")
    check("what the viewer gets is a watermarked PNG, not the PDF",
          page.status_code == 200 and page.content.startswith(b"\x89PNG") and b"%PDF" not in page.content)
    check("viewer CANNOT download the view-only file", viewer.refused("GET", f"/api/documents/{salary}/download"))
    v1 = viewer.req("GET", f"/api/documents/{salary}").json()["versions"][0]["id"]
    check("viewer CANNOT download it through the versions endpoint either",
          viewer.refused("GET", f"/api/documents/{salary}/versions/{v1}/download"))

    print("\nEach level allows exactly what it says")
    check("download level: can download", viewer.code("GET", f"/api/documents/{contract}/download") == 200)
    check("download level: cannot edit", viewer.code("PATCH", f"/api/documents/{contract}", json={"name": "x"}) == 403)
    check("edit level: can edit", viewer.code("PATCH", f"/api/documents/{budget}", json={"description": "checked"}) == 200)
    check("edit level: cannot delete", viewer.code("DELETE", f"/api/documents/{budget}") == 403)
    check("edit level: cannot re-share",
          viewer.code("POST", f"/api/documents/{budget}/grants", json={"username": "admin", "permission": "view"}) == 403)
    check("viewer role cannot upload",
          viewer.code("POST", "/api/documents", files={"file": ("x.txt", b"hi")}, data={"category": "general"}) == 403)
    check("mass assignment of owner_id rejected", viewer.code("PATCH", f"/api/documents/{budget}", json={"owner_id": "me"}) == 422)
    check("viewer cannot use the admin API", viewer.code("GET", "/api/admin/users") == 403)
    check("owner cannot use the admin API", owner.code("GET", "/api/admin/users") == 403)

    print("\nSearch leakage")
    names = {d["name"] for d in viewer.req("GET", "/api/documents", params={"q": "%"}).json()["items"]}
    check("viewer's wildcard search never shows the private minutes", "Board minutes - private" not in names)
    check("search by owner shows only what was shared",
          "Board minutes - private" not in {d["name"] for d in viewer.req(
              "GET", "/api/documents", params={"owner": "owner"}).json()["items"]})

    print("\nCSRF")
    check("state change without CSRF token refused", owner.code("DELETE", f"/api/documents/{private}", csrf=False) == 403)

    print("\nTaking access away is immediate")
    g = owner.req("POST", f"/api/documents/{private}/grants", json={"username": "viewer", "permission": "download"}).json()
    before = viewer.code("GET", f"/api/documents/{private}/download")
    owner.req("DELETE", f"/api/documents/{private}/grants/{g['id']}")
    after = viewer.code("GET", f"/api/documents/{private}/download")
    check("granted -> 200, revoked -> 403 on the same session", (before, after) == (200, 403), f"{before}->{after}")
    g = owner.req("POST", f"/api/documents/{contract}/grants", json={"username": "viewer", "permission": "view"}).json()
    after = viewer.code("GET", f"/api/documents/{contract}/download")
    # Put the demo data back as it was (the seed gives the viewer a week).
    owner.req("POST", f"/api/documents/{contract}/grants",
              json={"username": "viewer", "permission": "download", "duration_minutes": 7 * 24 * 60})
    check("lowering download -> view stops downloads at once", after == 403, str(after))

    print("\nShare links (5 minutes, one named person who already has access)")
    check("no link for someone without access (a link never gives access on its own)",
          owner.code("POST", f"/api/documents/{private}/links", json={"username": "viewer"}) == 400)
    check("no download link for a View-only person",
          owner.code("POST", f"/api/documents/{salary}/links", json={"username": "viewer", "permission": "download"}) == 400)
    link = owner.req("POST", f"/api/documents/{salary}/links", json={"username": "viewer"}).json()
    token = link["token"]
    check("a link is useless without signing in", anon.post("/api/links/open", json={"token": token}).status_code == 401)
    check("a forwarded link is useless to someone else, even an admin",
          admin.refused("POST", "/api/links/open", json={"token": token}))
    used = viewer.code("POST", "/api/links/open", json={"token": token})
    peek = viewer.code("GET", f"/api/documents/{salary}/preview", headers={"X-Link-Token": token})
    check("the named person can open it and read it", (used, peek) == (200, 200), f"{used}, {peek}")
    check("a view link cannot download",
          viewer.refused("GET", f"/api/documents/{salary}/download", headers={"X-Link-Token": token}))
    head, body, sig = token.split(".")
    check("an edited link (bad signature) is refused",
          viewer.refused("POST", "/api/links/open", json={"token": f"{head}.{body}.{sig[::-1]}"}))
    check("a link for one document cannot open another",
          viewer.refused("GET", f"/api/documents/{private}", headers={"X-Link-Token": token}))
    check("a link in the URL gives nothing (header only, never logged)",
          viewer.refused("GET", f"/api/documents/{private}?link={token}"))
    owner.req("POST", f"/api/documents/{salary}/links/revoke-all")
    check("'Revoke all links' kills it before its 5 minutes are up",
          viewer.refused("POST", "/api/links/open", json={"token": token}))

    print("\nMalicious uploads")
    for fname, data in [("x.html", b"<script>alert(1)</script>"), ("x.svg", b"<svg onload=alert(1)>"),
                        ("evil.pdf", b"MZ\x90\x00"), ("js.pdf", b"%PDF-1.4\n/OpenAction <</S /JavaScript /JS (x)>>\n%%EOF"),
                        ("f.csv", b"a,b\n=cmd|' /C calc'!A0,1\n")]:
        r = owner.req("POST", "/api/documents", files={"file": (fname, data)}, data={"category": "general"})
        check(f"{fname} rejected", r.status_code == 400, str(r.status_code))

    print("\nAudit trail")
    v = admin.req("GET", "/api/admin/audit/verify").json()
    check(f"hash chain intact ({v['entries_checked']} entries, {v['anchors_checked']} anchors)", v["ok"])
    denied = admin.req("GET", "/api/admin/audit", params={"outcome": "denied", "actor": "viewer"}).json()["total"]
    check("viewer's refused attempts are on the record", denied > 0, str(denied))
    views = admin.req("GET", "/api/admin/audit", params={"action": "document.preview_page", "actor": "viewer"}).json()["total"]
    check("every page the viewer looked at is on the record", views > 0, str(views))
    probes = admin.req("GET", "/api/admin/audit", params={"action": "auth.forbidden", "actor": "viewer"}).json()["items"]
    check("the viewer's attempt on the admin API is on the record, with its reason",
          bool(probes) and probes[0]["details"].get("reason") == "role_required")
    check("viewer cannot export the audit trail", viewer.code("GET", "/api/admin/audit/export") == 403)
    check("owner cannot read single audit events", owner.code("GET", "/api/admin/audit/events/1") == 403)
    evil = '=HYPERLINK("http://evil.example/","Click me")'
    anon.post("/api/auth/login", json={"username": evil, "password": "not-the-password"})
    r = admin.req("GET", "/api/admin/audit/export", params={"action": "auth.login", "outcome": "denied"})
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"), newline="")))
    check("a formula typed as a username is exported as text, never as a formula",
          any(row["actor"] == "'" + evil for row in rows) and not any(
              v.startswith(("=", "+", "-", "@")) for row in rows for v in row.values()))
    digest = hashlib.sha256(r.content).hexdigest()
    logged = admin.req("GET", "/api/admin/audit", params={"action": "audit.export"}).json()["items"][0]["details"]
    check("the export's SHA-256 is in the response and in the audit trail",
          r.headers.get("x-content-sha256") == digest == logged.get("sha256"))

    print("\nSessions, two-step sign-in, access review")
    ref = admin.req("GET", "/api/auth/sessions").json()["items"][0]["id"]
    check("a viewer cannot sign out the admin's session", viewer.code("DELETE", f"/api/auth/sessions/{ref}") == 404
          and admin.code("GET", "/api/auth/me") == 200)
    check("a viewer cannot bulk-revoke grants", viewer.code("POST", "/api/admin/access-review/revoke",
                                                            json={"grant_ids": ["AAAAAAAAAAAAAAAAAAAAAA"]}) == 403)
    owner_id = next(u["id"] for u in admin.req("GET", "/api/admin/users").json()["items"] if u["username"] == "owner")
    check("a viewer cannot reset anyone's two-step sign-in",
          viewer.code("POST", f"/api/admin/users/{owner_id}/reset-2fa") == 403)
    check("an owner cannot turn off the two-step sign-in their role requires",
          owner.code("POST", "/api/auth/2fa/disable", json={"password": PASSWORDS["owner"], "code": "000000"}) == 403)
    users = admin.req("GET", "/api/admin/users").json()["items"]
    check("no two-step secret ever leaves the server, not even to an admin",
          not any(k.startswith("totp_s") or k == "totp_pending" for u in users for k in u))

    print("\nRequests for access and classification labels")
    floor_plan = docs["Office floor plan"]                  # labelled Public; viewer: view only
    made_up = "ZZZZZZZZZZZZZZZZZZZZZZ"
    before = {r["document_id"] for r in viewer.req("GET", "/api/access-requests/mine").json()["items"]
              if r["status"] == "pending"}
    real = viewer.req("POST", "/api/access-requests", json={"document_id": private, "permission": "view"})
    fake = viewer.req("POST", "/api/access-requests", json={"document_id": made_up, "permission": "view"})

    def answer(r):
        body = r.json()
        return r.status_code, body.get("status"), body.get("message")

    check("asking for a made-up id gets the same answer as asking for the private minutes",
          real.status_code == 202 and answer(real) == answer(fake), f"{answer(real)} vs {answer(fake)}")
    request_id = real.json().get("id", "AAAAAAAAAAAAAAAAAAAAAA")
    check("a viewer cannot approve their own request (only the document's owner decides)",
          viewer.refused("POST", f"/api/access-requests/{request_id}/approve", json={})
          and viewer.refused("GET", f"/api/documents/{private}"))
    for doc_id, r in ((private, real), (made_up, fake)):   # clean up, keeping any request made before this run
        if doc_id not in before and r.status_code == 202:
            viewer.req("POST", f"/api/access-requests/{r.json()['id']}/withdraw")
    check("Edit access cannot change a document's label (owner only)",
          viewer.refused("PUT", f"/api/documents/{budget}/classification", json={"classification": "public"}))
    check("a Public label opens nothing by itself (the admin is still refused)",
          admin.refused("GET", f"/api/documents/{floor_plan}"))
    mark = viewer.req("GET", f"/api/documents/{salary}/preview").json().get("watermark", "")
    check("a Confidential document's pages are marked CONFIDENTIAL with the reader's name",
          mark.startswith("CONFIDENTIAL · viewer"), mark)

    v = admin.req("GET", "/api/admin/audit/verify").json()
    check(f"after all of that: {v['message']}", v["ok"] and v["message"].startswith("Chain intact ("))

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks held.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
