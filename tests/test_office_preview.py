"""View-only reading of Word / PowerPoint / Excel files.

With LibreOffice installed the server converts the file to PDF and sends
watermarked page images - the reader sees the real layout, never the file.
Without it, the server sends the extracted text. Either way the original
bytes never reach a view-only reader.

THREATS.md: T60 (view-only), T69 (converter on untrusted files).
"""
from __future__ import annotations

import json

import pytest

from conftest import audit_rows, make_docx, make_pdf
from trustvault.preview import OfficeRenderer, PreviewError, find_soffice

DOCX = make_docx(body=b"<w:p><w:r><w:t>Q3 contract: fees INR 12,00,000</w:t></w:r></w:p>")


class FakeOffice:
    """Stands in for LibreOffice: 'converts' by returning a one-page PDF."""
    available = True

    def __init__(self, fail=False):
        self.fail, self.calls = fail, 0

    def pdf_for(self, version_id, extension, data):
        self.calls += 1
        if self.fail:
            raise PreviewError("conversion failed")
        return make_pdf(b"Rendered by the office converter")


def shared_docx(world, level="view"):
    doc = world["alice"].upload("contract.docx", DOCX, category="contract")
    r = world["alice"].post(f"/api/documents/{doc}/grants", json={"username": "gina", "permission": level})
    assert r.status_code == 201
    return doc


def test_without_libreoffice_office_files_are_shown_as_text(world):
    doc = shared_docx(world)
    p = world["gina"].get(f"/api/documents/{doc}/preview").json()
    assert p["kind"] == "text" and p["renderer"] == "builtin" and "INR 12,00,000" in p["text"]
    assert p["can_download"] is False


def test_with_a_converter_office_files_become_watermarked_pages(world, db):
    fake = FakeOffice()
    world.app.state.ctx.office = fake
    doc = shared_docx(world)
    gina = world["gina"]
    p = gina.get(f"/api/documents/{doc}/preview").json()
    assert p["kind"] == "pages" and p["pages"] == 1 and p["renderer"] == "libreoffice"
    page = gina.get(f"/api/documents/{doc}/preview/pages/1")
    assert page.status_code == 200 and page.content.startswith(b"\x89PNG")
    assert DOCX not in page.content and b"PK\x03\x04" not in page.content  # never the .docx itself
    assert gina.get(f"/api/documents/{doc}/download").status_code == 403    # still view-only
    row = audit_rows(db, action="document.preview", outcome="allowed")[-1]
    assert json.loads(row["details"])["renderer"] == "libreoffice"


def test_a_failed_conversion_falls_back_to_text(world):
    world.app.state.ctx.office = FakeOffice(fail=True)
    doc = shared_docx(world)
    p = world["gina"].get(f"/api/documents/{doc}/preview").json()
    assert p["kind"] == "text" and "INR 12,00,000" in p["text"]


def test_converter_is_not_reached_without_access(world):
    fake = FakeOffice()
    world.app.state.ctx.office = fake
    doc = shared_docx(world)
    assert world["bob"].get(f"/api/documents/{doc}/preview").status_code == 403
    assert world["bob"].get(f"/api/documents/{doc}/preview/pages/1").status_code == 403
    assert fake.calls == 0  # the access check runs before any file is decrypted or converted


def test_renderer_setting():
    assert find_soffice("off") is None
    assert find_soffice("/no/such/soffice") is None
    assert OfficeRenderer(None).available is False
    with pytest.raises(PreviewError):
        OfficeRenderer(None).pdf_for("v", "docx", DOCX)


@pytest.mark.skipif(find_soffice("auto") is None, reason="LibreOffice is not installed here")
def test_real_libreoffice_conversion(world):
    world.app.state.ctx.office = OfficeRenderer(find_soffice("auto"), timeout_seconds=120)
    doc = shared_docx(world)
    p = world["gina"].get(f"/api/documents/{doc}/preview").json()
    assert p["kind"] == "pages" and p["renderer"] == "libreoffice" and p["pages"] >= 1
    page = world["gina"].get(f"/api/documents/{doc}/preview/pages/1")
    assert page.status_code == 200 and page.content.startswith(b"\x89PNG")
