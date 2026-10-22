"""The three access levels an owner can give: view, download, edit.

View-only must really mean the person never receives the file: the server
renders it (watermarked pages / extracted text) instead.  THREATS.md: T60, T61.
"""
from __future__ import annotations

import io
import json
import time
import zipfile

import pytest
from PIL import Image

from conftest import PDF_A, audit_rows, make_docx, make_pdf
from trustvault import preview


def share(world, doc_id, who, level):
    r = world["alice"].post(f"/api/documents/{doc_id}/grants", json={"username": who, "permission": level})
    assert r.status_code == 201, r.text


# ------------------------------------------------------------- the levels
def test_view_only_can_read_but_never_receives_the_file(world, db):
    gina = world["gina"]
    p = gina.get(f"/api/documents/{world.doc_a}/preview")
    assert p.status_code == 200
    body = p.json()
    assert body["kind"] == "pages" and body["pages"] == 1 and body["can_download"] is False
    assert "gina" in body["watermark"]
    page = gina.get(f"/api/documents/{world.doc_a}/preview/pages/1")
    assert page.status_code == 200 and page.headers["content-type"] == "image/png"
    assert page.content.startswith(b"\x89PNG")
    assert b"%PDF" not in page.content and b"Confidential salary letter" not in page.content
    assert "no-store" in page.headers["cache-control"] and "sandbox" in page.headers["content-security-policy"]
    Image.open(io.BytesIO(page.content)).verify()  # a real image


def test_view_only_cannot_download_any_way(world, db):
    gina = world["gina"]
    for url in [f"/api/documents/{world.doc_a}/download",
                f"/api/documents/{world.doc_a}/versions/{world.version_a1}/download"]:
        r = gina.get(url)
        assert r.status_code == 403 and PDF_A not in r.content
    denied = [r for r in audit_rows(db, outcome="denied") if r["actor_id"] == world.ids["gina"]]
    assert len(denied) == 2 and all('"view_cannot_download"' in r["details"] for r in denied)


def test_view_only_ui_flag_and_metadata(world):
    doc = world["gina"].get(f"/api/documents/{world.doc_a}").json()
    assert doc["my_permission"] == "view"


def test_download_level_gets_the_exact_original(world):
    r = world["carol"].get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 200 and r.content == PDF_A
    assert world["carol"].get(f"/api/documents/{world.doc_a}/preview").json()["can_download"] is True


def test_download_level_cannot_edit_and_edit_level_cannot_delete_or_share(world):
    assert world["carol"].patch(f"/api/documents/{world.doc_a}", json={"name": "x"}).status_code == 403
    assert world["carol"].post(f"/api/documents/{world.doc_a}/versions",
                               files={"file": ("v.pdf", make_pdf(b"v"), "application/pdf")}).status_code == 403
    assert world["dave"].patch(f"/api/documents/{world.doc_a}", json={"name": "Renamed"}).status_code == 200
    assert world["dave"].delete(f"/api/documents/{world.doc_a}").status_code == 403
    assert world["dave"].post(f"/api/documents/{world.doc_a}/grants",
                              json={"username": "frank", "permission": "view"}).status_code == 403


def test_old_read_level_and_unknown_levels_are_rejected(world):
    for level in ("read", "owner", "admin", "VIEW", ""):
        r = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "frank", "permission": level})
        assert r.status_code == 422, level


def test_every_view_is_audited(world, db):
    world["gina"].get(f"/api/documents/{world.doc_a}/preview")
    world["gina"].get(f"/api/documents/{world.doc_a}/preview/pages/1")
    assert audit_rows(db, action="document.preview", actor_id=world.ids["gina"])
    rows = audit_rows(db, action="document.preview_page", actor_id=world.ids["gina"])
    assert rows and json.loads(rows[-1]["details"])["page"] == 1


def test_page_numbers_out_of_range(world):
    for n in (0, 2, 999):
        assert world["gina"].get(f"/api/documents/{world.doc_a}/preview/pages/{n}").status_code == 404, n
    assert world["gina"].get(f"/api/documents/{world.doc_a}/preview/pages/abc").status_code == 422


def test_trashed_document_cannot_be_viewed_by_grantee(world):
    world["alice"].delete(f"/api/documents/{world.doc_a}")
    assert world["gina"].get(f"/api/documents/{world.doc_a}/preview").status_code == 403
    assert world["gina"].get(f"/api/documents/{world.doc_a}/preview/pages/1").status_code == 403


def test_image_preview_is_reencoded_without_metadata(world):
    from PIL import Image as PILImage
    buf = io.BytesIO()
    img = PILImage.new("RGB", (40, 30), (10, 120, 200))
    info = __import__("PIL.PngImagePlugin", fromlist=["PngInfo"]).PngInfo()
    info.add_text("Author", "secret-author-name")
    img.save(buf, format="PNG", pnginfo=info)
    doc = world["alice"].upload("diagram.png", buf.getvalue(), category="engineering")
    share(world, doc, "gina", "view")
    page = world["gina"].get(f"/api/documents/{doc}/preview/pages/1")
    assert page.status_code == 200 and b"secret-author-name" not in page.content
    assert world["gina"].get(f"/api/documents/{doc}/preview/pages/2").status_code == 404


# ---------------------------------------------------------------- text kinds
def _xlsx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("xl/workbook.xml", '<workbook><sheets><sheet name="Budget" sheetId="1"/></sheets></workbook>')
        z.writestr("xl/sharedStrings.xml", "<sst><si><t>Dept</t></si><si><t>Sales &amp; Ops</t></si></sst>")
        z.writestr("xl/worksheets/sheet1.xml",
                   '<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>2026</v></c></row>'
                   '<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>450000</v></c></row></sheetData></worksheet>')
    return buf.getvalue()


def _pptx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("ppt/presentation.xml", "<p:presentation/>")
        for n, text in [(2, "Second slide"), (1, "Quarterly results"), (10, "Tenth slide")]:
            z.writestr(f"ppt/slides/slide{n}.xml", f"<p:sld><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>")
    return buf.getvalue()


@pytest.mark.parametrize("filename,content,expected", [
    ("notes.txt", "Plain notes ✓\nline two".encode(), ["Plain notes ✓", "line two"]),
    ("table.csv", b"name,amount\nAcme,12\n", ["name,amount", "Acme,12"]),
    ("contract.docx", make_docx(body=b"<w:p><w:r><w:t>Clause 1: fees</w:t></w:r></w:p>"
                                     b"<w:p><w:r><w:t xml:space=\"preserve\">Tom &amp; Jerry &lt;b&gt;</w:t></w:r></w:p>"),
     ["Clause 1: fees", "Tom & Jerry <b>"]),
    ("budget.xlsx", _xlsx(), ["--- Budget ---", "Dept\t2026", "Sales & Ops\t450000"]),
    ("deck.pptx", _pptx(), ["--- Slide 1 ---\nQuarterly results", "--- Slide 2 ---", "--- Slide 10 ---"]),
])
def test_text_previews(world, filename, content, expected):
    doc = world["alice"].upload(filename, content, category="general")
    share(world, doc, "gina", "view")
    r = world["gina"].get(f"/api/documents/{doc}/preview")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kind"] == "text" and "gina" in body["watermark"]
    for piece in expected:
        assert piece in body["text"], (piece, body["text"])
    if filename.endswith(".pptx"):  # slides in numeric, not alphabetical, order
        assert body["text"].index("Slide 2") < body["text"].index("Slide 10")


def test_entity_expansion_bomb_in_docx_is_not_expanded(world):
    bomb_dtd = (b'<?xml version="1.0"?><!DOCTYPE w [<!ENTITY a "AAAAAAAAAA">'
                + b"".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">'.encode() for i in range(8))
                + b"]>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", bomb_dtd + b"<w:document><w:body><w:p><w:r><w:t>&i;</w:t></w:r></w:p></w:body></w:document>")
    doc = world["alice"].upload("bomb.docx", buf.getvalue())
    share(world, doc, "gina", "view")
    started = time.time()
    r = world["gina"].get(f"/api/documents/{doc}/preview")
    assert r.status_code == 200 and time.time() - started < 5
    assert len(r.json()["text"]) < 100  # "&i;" stays literal text; nothing was expanded


# ------------------------------------------------------------ the watermark
def test_rendered_page_carries_a_visible_watermark():
    plain = Image.open(io.BytesIO(preview.render_page("pdf", PDF_A, 1, " "))).convert("RGB")
    marked = Image.open(io.BytesIO(preview.render_page("pdf", PDF_A, 1, "gina · 2026-10-22 · TrustVault view-only")))
    marked = marked.convert("RGB")
    assert plain.size == marked.size
    # Footer bar is dark brand colour, and the page body has extra (reddish) ink from the tiled mark.
    r, g, b = marked.getpixel((5, marked.height - 5))
    assert r < 80 and g < 110 and b < 110
    diff = sum(1 for p, q in zip(plain.getdata(), marked.getdata()) if p != q)
    assert diff > plain.width * plain.height * 0.01


def test_corrupt_or_unsupported_documents_fail_cleanly():
    with pytest.raises(preview.PreviewError):
        preview.render_page("pdf", b"%PDF-1.4 garbage %%EOF", 1, "x")
    with pytest.raises(preview.PreviewError):
        preview.kind_for("exe")
