"""Browser-facing hardening.  THREATS.md: T21, T31, T33, T40, T41, T42."""
from __future__ import annotations

from conftest import ROLES


def test_security_headers_on_pages_and_api(world):
    for url in ["/", "/api/health"]:
        r = world.anon().get(url)
        h = r.headers
        assert h["x-frame-options"] == "DENY", url
        assert h["x-content-type-options"] == "nosniff", url
        assert h["referrer-policy"] == "no-referrer", url
        csp = h["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp, url
    # The anonymous share page is gone: links need a signed-in recipient now.
    assert world.anon().get("/share").status_code == 404


def test_api_responses_are_not_cached(world):
    r = world["carol"].get(f"/api/documents/{world.doc_a}")
    assert "no-store" in r.headers["cache-control"]


def test_errors_do_not_leak_internals(world, monkeypatch):
    import trustvault.routes.documents as docs

    def boom(*a, **k):
        raise RuntimeError("secret internal detail /home/app/db password=hunter2")
    monkeypatch.setattr(docs, "get_version", boom)
    r = world["carol"].get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 500
    assert "hunter2" not in r.text and "Traceback" not in r.text and r.json()["detail"] == "Internal error"


def test_validation_errors_do_not_echo_input(world):
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": "bob", "permission": "<script>alert(1)</script>"})
    assert r.status_code == 422 and "<script>" not in r.text


def test_sql_injection_strings_are_just_data(world, db):
    from conftest import Client
    for payload in ["' OR '1'='1", "admin'--", "\"; DROP TABLE users; --"]:
        assert Client(world.app).login(payload, payload + "xxxxxxxxxxx").status_code == 401
        assert world["bob"].get("/api/documents", params={"q": payload, "owner": payload}).json()["total"] == 0
    assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == len(ROLES)


def test_body_size_limit(world):
    r = world["alice"].post("/api/documents", content=b"x" * (3 * 1024 * 1024),
                            headers={"content-type": "application/octet-stream"})
    assert r.status_code == 413


def test_frontend_never_uses_innerhtml_with_data():
    """The SPA builds DOM nodes with textContent only, so stored names such as
    '<img onerror=...>' can never execute."""
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / "trustvault" / "static" / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js
    assert "eval(" not in js and "new Function" not in js
