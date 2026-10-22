"""Attack a RUNNING TrustVault the way a judge would, and report what held.

    python -m trustvault                      # in one terminal
    python scripts/attack_selftest.py         # in another
    python scripts/attack_selftest.py --base http://127.0.0.1:8000

Uses the three seeded demo logins (admin, owner, viewer). Every attempt is a
real HTTP request, so the refusals also show up in the audit trail and on the
admin "Worth noticing" panel. The script cleans up the grants and links it
creates.
"""
from __future__ import annotations

import argparse
import sys

import httpx

PASSWORDS = {"admin": "Keeper!Vault2026", "owner": "Author!Vault2026", "viewer": "Reader!Vault2026"}

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{'  - got ' + detail if detail and not ok else ''}")


class User:
    def __init__(self, base: str, username: str):
        self.c = httpx.Client(base_url=base, timeout=30)
        r = self.c.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
        if r.status_code != 200:
            sys.exit(f"Cannot sign in as {username} ({r.status_code}). Did you run scripts/init_db.py --seed?")
        self.csrf = r.json()["csrf_token"]

    def req(self, method: str, url: str, csrf: bool = True, **kw):
        headers = kw.pop("headers", {})
        if csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        return self.c.request(method, url, headers=headers, **kw)

    def code(self, method: str, url: str, **kw) -> int:
        return self.req(method, url, **kw).status_code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    base = ap.parse_args().base
    try:
        httpx.get(base + "/api/health", timeout=5)
    except httpx.HTTPError:
        sys.exit(f"TrustVault is not reachable at {base}. Start it with: python -m trustvault")

    owner, viewer, admin = User(base, "owner"), User(base, "viewer"), User(base, "admin")
    anon = httpx.Client(base_url=base, timeout=30)

    docs = {d["name"]: d["id"] for d in owner.req("GET", "/api/documents").json()["items"]}
    salary = docs["Salary letter - Vikram"]            # viewer: view only
    contract = docs["Q3 services contract - Acme Corp"]  # viewer: view + download
    budget = docs["Budget 2026"]                         # viewer: edit
    private = docs["Board minutes - private"]            # viewer: nothing
    private_version = owner.req("GET", f"/api/documents/{private}").json()["versions"][0]["id"]

    print("\nDirect object access (IDOR)")
    check("viewer cannot open the private board minutes by id", viewer.code("GET", f"/api/documents/{private}") == 404)
    check("viewer cannot download them", viewer.code("GET", f"/api/documents/{private}/download") == 404)
    check("viewer cannot render them in the viewer", viewer.code("GET", f"/api/documents/{private}/preview") == 404)
    check("viewer cannot pull the private file through a document they CAN see",
          viewer.code("GET", f"/api/documents/{contract}/versions/{private_version}/download") == 404)
    check("anonymous gets 401", anon.get(f"/api/documents/{private}/download").status_code == 401)
    check("admin cannot read content", admin.code("GET", f"/api/documents/{private}/download") == 404)
    check("admin cannot render content", admin.code("GET", f"/api/documents/{private}/preview") == 404)

    print("\nView only means view only")
    check("viewer CAN read the view-only salary letter in the browser",
          viewer.code("GET", f"/api/documents/{salary}/preview") == 200)
    page = viewer.req("GET", f"/api/documents/{salary}/preview/pages/1")
    check("what the viewer gets is a watermarked PNG, not the PDF",
          page.status_code == 200 and page.content.startswith(b"\x89PNG") and b"%PDF" not in page.content)
    check("viewer CANNOT download the view-only file", viewer.code("GET", f"/api/documents/{salary}/download") == 403)
    v1 = viewer.req("GET", f"/api/documents/{salary}").json()["versions"][0]["id"]
    check("viewer CANNOT download it through the versions endpoint either",
          viewer.code("GET", f"/api/documents/{salary}/versions/{v1}/download") == 403)

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
    check("granted -> 200, revoked -> 404 on the same session", (before, after) == (200, 404), f"{before}->{after}")
    g = owner.req("POST", f"/api/documents/{contract}/grants", json={"username": "viewer", "permission": "view"}).json()
    after = viewer.code("GET", f"/api/documents/{contract}/download")
    owner.req("POST", f"/api/documents/{contract}/grants", json={"username": "viewer", "permission": "download"})
    check("lowering download -> view stops downloads at once", after == 403, str(after))

    link = owner.req("POST", f"/api/documents/{private}/share-links", json={"expires_in_hours": 1, "max_uses": 3}).json()
    used = anon.post("/api/public/share/download", json={"token": link["token"]}).status_code
    owner.req("DELETE", f"/api/documents/{private}/share-links/{link['id']}")
    dead = anon.post("/api/public/share/download", json={"token": link["token"]}).status_code
    check("share link works, then dies when revoked", (used, dead) == (200, 404), f"{used}->{dead}")
    check("guessed share token refused", anon.post("/api/public/share/download", json={"token": "A" * 43}).status_code == 404)

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

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks held.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
