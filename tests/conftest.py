"""Shared fixtures.

``world`` builds the same small company for every test:

    alice  (owner)   owns  DOC_A "Salary letter - Carol.pdf"  (hr)
                     gina: view    carol: download    dave: edit    erin: download but EXPIRED
                     (the live grants use the default duration, DEFAULT_GRANT_MINUTES)
    bob    (owner)   owns  DOC_B "Bridge drawing rev B.png"   (engineering), shared with nobody
    frank  (owner)   owns nothing
    admin  (admin)
    erin is an external viewer.

Every user gets their own HTTP client (own cookie jar) and is signed in.

``clock`` moves the server's clock forward (utils.utcnow) so time limits -
5-minute links, 30-minute grants, 15-minute idle sessions - are tested
without sleeping.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import trustvault.utils as tv_utils
from trustvault.config import Settings
from trustvault.db import connect, transaction
from trustvault.main import create_app
from trustvault.utils import iso_in, new_id, now_iso

PASSWORDS = {
    "admin": "Admin!Vault2026", "alice": "Alice!Vault2026", "bob": "Bob!Vault2026x", "carol": "Carol!Vault2026",
    "dave": "Dave!Vault2026x", "erin": "Erin!Vault2026x", "frank": "Frank!Vault2026", "gina": "Gina!Vault2026x",
}
ROLES = {"admin": "admin", "alice": "owner", "bob": "owner", "frank": "owner",
         "carol": "viewer", "dave": "viewer", "erin": "viewer", "gina": "viewer"}


# --------------------------------------------------------------- sample files
def make_pdf(body: bytes = b"Confidential salary letter for Carol: 1,00,000 INR") -> bytes:
    """A real one-page PDF whose page shows ``body`` (so it can be rendered)."""
    text = body.replace(b"\\", b"/").replace(b"(", b"[").replace(b")", b"]")
    stream = b"BT /F1 12 Tf 72 720 Td (" + text + b") Tj ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def make_png(width: int = 1, height: int = 1) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def make_docx(extra: dict[str, bytes] | None = None, content_types: bytes | None = None,
              body: bytes = b"<w:p><w:r><w:t>Contract</w:t></w:r></w:p>") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types or (
            b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            b'<Default Extension="xml" ContentType="application/xml"/>'
            b'<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.'
            b'wordprocessingml.document.main+xml"/></Types>'))
        zf.writestr("_rels/.rels",
                    b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
                    b'relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
                    b'2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        zf.writestr("word/document.xml",
                    b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/'
                    b'2006/main"><w:body>' + body + b'</w:body></w:document>')
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return buf.getvalue()


PDF_A = make_pdf()
PNG_B = make_png(2, 2)


# -------------------------------------------------------------------- client
class Client:
    """Wraps TestClient; remembers the CSRF token and sends it on unsafe calls."""

    def __init__(self, app, username: str | None = None):
        self.http = TestClient(app, raise_server_exceptions=False)
        self.username = username
        self.csrf: str | None = None
        self.user: dict | None = None

    def login(self, username: str, password: str | None = None, **extra):
        r = self.http.post("/api/auth/login", json={"username": username,
                                                    "password": password or PASSWORDS[username], **extra})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
            self.user = r.json()["user"]
            self.username = username
        return r

    def request(self, method: str, url: str, csrf: bool = True, **kw):
        headers = dict(kw.pop("headers", {}) or {})
        if csrf and self.csrf and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            headers.setdefault("X-CSRF-Token", self.csrf)
        return self.http.request(method, url, headers=headers, **kw)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def patch(self, url, **kw):
        return self.request("PATCH", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def upload(self, filename: str, content: bytes, category: str = "general", name: str = "", expect: int = 201):
        r = self.post("/api/documents", files={"file": (filename, content, "application/octet-stream")},
                      data={"category": category, "name": name})
        assert r.status_code == expect, r.text
        return r.json().get("id") if r.status_code == 201 else r


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def settings(tmp_path, monkeypatch):
    for var in ("TRUSTVAULT_MASTER_KEY", "TRUSTVAULT_AUDIT_KEY"):
        monkeypatch.delenv(var, raising=False)
    return Settings(
        instance_dir=tmp_path / "instance",
        argon2_time_cost=1, argon2_memory_kib=1024, argon2_parallelism=1,
        login_rate_per_ip_per_minute=1000, link_rate_per_user_per_minute=1000,
        office_renderer="off",  # tests that need LibreOffice switch it on themselves
        max_upload_bytes=1024 * 1024,
        durable_writes=False,  # skip fsync: tests do not need power-cut durability
    )


class Clock:
    """Moves the server clock forward. Every server-side "now" goes through
    trustvault.utils.utcnow(), which adds this offset."""

    def __init__(self, monkeypatch):
        self._mp = monkeypatch
        self.offset = timedelta(0)

    def advance(self, **delta) -> None:
        self.offset += timedelta(**delta)
        self._mp.setattr(tv_utils, "_CLOCK_OFFSET", self.offset)


@pytest.fixture
def clock(monkeypatch) -> Clock:
    return Clock(monkeypatch)


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def db(app):
    conn = connect(app.state.ctx.settings.db_path, durable=False)
    yield conn
    conn.close()


def create_user(app, username: str, role: str, external: bool = False, active: bool = True) -> str:
    ctx = app.state.ctx
    conn = connect(ctx.settings.db_path, durable=False)
    try:
        uid = new_id()
        with transaction(conn) as tx:
            tx.execute(
                """INSERT INTO users (id, username, display_name, password_hash, role, is_active, is_external,
                                      created_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (uid, username, username.title(), ctx.passwords.hash(PASSWORDS[username]), role, int(active),
                 int(external), now_iso(), now_iso()),
            )
        return uid
    finally:
        conn.close()


@dataclass
class World:
    app: object
    ids: dict = field(default_factory=dict)
    clients: dict = field(default_factory=dict)
    doc_a: str = ""
    doc_b: str = ""
    version_a1: str = ""
    version_b1: str = ""
    grant_carol: str = ""
    grant_dave: str = ""
    grant_gina: str = ""

    def __getitem__(self, name) -> Client:
        return self.clients[name]

    def anon(self) -> Client:
        return Client(self.app)

    def fresh(self, username: str) -> Client:
        c = Client(self.app)
        assert c.login(username).status_code == 200
        return c


@pytest.fixture
def world(app, db) -> World:
    w = World(app=app)
    for name, role in ROLES.items():
        w.ids[name] = create_user(app, name, role, external=(name == "erin"))
    for name in ROLES:
        c = Client(app)
        assert c.login(name).status_code == 200, name
        w.clients[name] = c

    w.doc_a = w["alice"].upload("Salary letter - Carol.pdf", PDF_A, category="hr")
    w.doc_b = w["bob"].upload("Bridge drawing rev B.png", PNG_B, category="engineering")
    w.version_a1 = w["alice"].get(f"/api/documents/{w.doc_a}").json()["versions"][0]["id"]
    w.version_b1 = w["bob"].get(f"/api/documents/{w.doc_b}").json()["versions"][0]["id"]

    r = w["alice"].post(f"/api/documents/{w.doc_a}/grants", json={"username": "carol", "permission": "download"})
    assert r.status_code == 201, r.text
    w.grant_carol = r.json()["id"]
    r = w["alice"].post(f"/api/documents/{w.doc_a}/grants", json={"username": "gina", "permission": "view"})
    assert r.status_code == 201, r.text
    w.grant_gina = r.json()["id"]
    r = w["alice"].post(f"/api/documents/{w.doc_a}/grants", json={"username": "dave", "permission": "edit"})
    assert r.status_code == 201, r.text
    w.grant_dave = r.json()["id"]
    # An expired grant cannot be created through the API (it rejects past
    # expiry), so write it directly - this is what a grant looks like a day
    # after it ran out.
    with transaction(db) as tx:
        tx.execute("""INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at)
                      VALUES (?, ?, ?, 'download', ?, ?, ?)""",
                   (new_id(), w.doc_a, w.ids["erin"], w.ids["alice"], now_iso(), iso_in(days=-1)))
    return w


def audit_rows(db, **filters) -> list[dict]:
    clauses, params = ["1=1"], []
    for k, v in filters.items():
        clauses.append(f"{k} = ?")
        params.append(v)
    return [dict(r) for r in db.execute(f"SELECT * FROM audit_log WHERE {' AND '.join(clauses)} ORDER BY seq", params)]
