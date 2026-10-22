"""Watermarked in-browser viewing for the ``view`` permission level.

Someone with *view* access must be able to read a document without being
handed the file. So the server never sends the original bytes to them; it
sends a rendering:

* PDF        -> one PNG per page, rendered with PDFium (pypdfium2)
* PNG / JPEG -> a re-encoded PNG (EXIF and other metadata dropped)
* TXT / CSV  -> the text
* DOCX / PPTX / XLSX -> the text, extracted with regular expressions over the
  XML parts (no XML parser, so no entity-expansion tricks)

Every rendered image carries a tiled watermark plus a footer with the
viewer's username and the time; text previews carry the same watermark line.

Honest limit (THREATS.md T60): what a screen shows can be photographed or
screenshotted. View-only guarantees the original file - its exact bytes, text
layer, metadata, embedded content - is never delivered, and that any leaked
picture names the person it was rendered for.
"""
from __future__ import annotations

import html
import io
import re
import threading
import zipfile

from PIL import Image, ImageDraw, ImageFont

MAX_PAGES = 200            # pages a viewer can page through
MAX_RENDER_PX = 1600       # longest side of a rendered page/image
MAX_TEXT_CHARS = 200_000   # text previews are truncated beyond this
MAX_PART_BYTES = 20 * 1024 * 1024  # largest single Office XML part we will read
MAX_XLSX_ROWS = 2000

Image.MAX_IMAGE_PIXELS = 40_000_000  # same limit as upload validation

PAGE_TYPES = {"pdf", "png", "jpg", "jpeg"}
TEXT_TYPES = {"txt", "csv", "docx", "pptx", "xlsx"}

# PDFium is not thread-safe; FastAPI runs sync endpoints in a thread pool.
_pdfium_lock = threading.Lock()


class PreviewError(Exception):
    """The document cannot be rendered (corrupt, encrypted, unsupported)."""


class NoSuchPage(PreviewError):
    """Requested page number is outside the document."""


def kind_for(extension: str) -> str:
    if extension in PAGE_TYPES:
        return "pages"
    if extension in TEXT_TYPES:
        return "text"
    raise PreviewError("no preview for this file type")


# --------------------------------------------------------------------- pages
def page_count(extension: str, data: bytes) -> int:
    if extension != "pdf":
        return 1
    import pypdfium2 as pdfium
    with _pdfium_lock:
        try:
            pdf = pdfium.PdfDocument(data)
        except Exception as exc:  # PdfiumError and friends: corrupt or password-protected
            raise PreviewError("PDF cannot be opened for preview") from exc
        try:
            return min(len(pdf), MAX_PAGES)
        finally:
            pdf.close()


def render_page(extension: str, data: bytes, page_no: int, watermark: str) -> bytes:
    """Return a watermarked PNG of page ``page_no`` (1-based)."""
    if extension == "pdf":
        image = _render_pdf_page(data, page_no)
    elif extension in ("png", "jpg", "jpeg"):
        if page_no != 1:
            raise NoSuchPage("images have a single page")
        image = _load_image(data)
    else:
        raise PreviewError("no page rendering for this file type")
    image = _apply_watermark(image, watermark)
    out = io.BytesIO()
    image.save(out, format="PNG", optimize=False)
    return out.getvalue()


def _render_pdf_page(data: bytes, page_no: int) -> Image.Image:
    import pypdfium2 as pdfium
    with _pdfium_lock:
        try:
            pdf = pdfium.PdfDocument(data)
        except Exception as exc:
            raise PreviewError("PDF cannot be opened for preview") from exc
        try:
            if not 1 <= page_no <= min(len(pdf), MAX_PAGES):
                raise NoSuchPage("no such page")
            page = pdf[page_no - 1]
            try:
                width, height = page.get_size()
                scale = min(2.0, MAX_RENDER_PX / max(width, height, 1))
                image = page.render(scale=scale).to_pil()
            finally:
                page.close()
        except PreviewError:  # includes NoSuchPage
            raise
        except Exception as exc:
            raise PreviewError("PDF page cannot be rendered") from exc
        finally:
            pdf.close()
    return image.convert("RGB")


def _load_image(data: bytes) -> Image.Image:
    try:
        image = Image.open(io.BytesIO(data))
        image.draft("RGB", (MAX_RENDER_PX, MAX_RENDER_PX))  # cheap downscale for JPEG
        image.load()
    except (Image.DecompressionBombError, OSError, ValueError) as exc:
        raise PreviewError("image cannot be rendered") from exc
    image = image.convert("RGB")  # drops alpha, palettes and all metadata
    image.thumbnail((MAX_RENDER_PX, MAX_RENDER_PX))
    return image


def _font(size: int):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # Pillow < 10.1 without sized default font
        return ImageFont.load_default()


def _apply_watermark(image: Image.Image, text: str) -> Image.Image:
    base = image.convert("RGBA")
    width, height = base.size
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))

    # Diagonal tiles across the whole page.
    size = max(14, min(width, height) // 28)
    font = _font(size)
    probe = ImageDraw.Draw(overlay)
    left, top, right, bottom = probe.textbbox((0, 0), text, font=font)
    tile = Image.new("RGBA", (right - left + size * 2, bottom - top + size), (0, 0, 0, 0))
    ImageDraw.Draw(tile).text((size, size // 2 - top), text, font=font, fill=(190, 30, 30, 64))
    tile = tile.rotate(28, expand=True)
    step_x, step_y = tile.width + size * 2, tile.height + size * 2
    for y in range(-step_y // 2, height, step_y):
        offset = (y // step_y % 2) * (step_x // 2)
        for x in range(-step_x + offset, width, step_x):
            overlay.paste(tile, (x, y), tile)

    # Solid footer that cannot be cropped without losing page content.
    footer_font = _font(max(12, size * 2 // 3))
    footer_h = max(22, size + 10)
    draw = ImageDraw.Draw(overlay)
    draw.rectangle([0, height - footer_h, width, height], fill=(15, 61, 58, 215))
    draw.text((10, height - footer_h + (footer_h - size * 2 // 3) // 2 - 2), text, font=footer_font,
              fill=(255, 255, 255, 255))
    return Image.alpha_composite(base, overlay).convert("RGB")


# ---------------------------------------------------------------------- text
_W_PARA = re.compile(rb"<w:p[ >].*?</w:p>", re.S)
_W_TEXT = re.compile(rb"<w:t(?: [^>]*)?>([^<]*)</w:t>|<w:(tab|br)\b[^>]*/>")
_A_PARA = re.compile(rb"<a:p>.*?</a:p>|<a:p [^>]*>.*?</a:p>", re.S)
_A_TEXT = re.compile(rb"<a:t>([^<]*)</a:t>")
_SI = re.compile(rb"<si>(.*?)</si>", re.S)
_T = re.compile(rb"<t(?: [^>]*)?>([^<]*)</t>")
_ROW = re.compile(rb"<row\b[^>]*>(.*?)</row>", re.S)
_CELL = re.compile(rb"<c\b([^>]*?)(?:/>|>(.*?)</c>)", re.S)
_V = re.compile(rb"<v>([^<]*)</v>")
_SHEET_NAME = re.compile(rb'<sheet\b[^>]*\bname="([^"]*)"')


def _unescape(raw: bytes) -> str:
    return html.unescape(raw.decode("utf-8", errors="replace"))


def _read_part(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > MAX_PART_BYTES:
        raise PreviewError("document part too large to preview")
    return zf.read(info)


def extract_text(extension: str, data: bytes) -> tuple[str, bool]:
    """Return (text, truncated)."""
    if extension in ("txt", "csv"):
        text = data.decode("utf-8-sig", errors="replace")
    else:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = zf.namelist()
            if extension == "docx":
                text = _docx_text(zf)
            elif extension == "pptx":
                text = _pptx_text(zf, names)
            elif extension == "xlsx":
                text = _xlsx_text(zf, names)
            else:
                raise PreviewError("no text preview for this file type")
        except (zipfile.BadZipFile, KeyError) as exc:
            raise PreviewError("document cannot be read for preview") from exc
    truncated = len(text) > MAX_TEXT_CHARS
    return text[:MAX_TEXT_CHARS], truncated


def _docx_text(zf: zipfile.ZipFile) -> str:
    xml = _read_part(zf, "word/document.xml")
    paragraphs = []
    for para in _W_PARA.findall(xml):
        parts = []
        for text, special in _W_TEXT.findall(para):
            parts.append("\t" if special == b"tab" else "\n" if special == b"br" else _unescape(text))
        paragraphs.append("".join(parts))
    return "\n".join(paragraphs).strip()


def _pptx_text(zf: zipfile.ZipFile, names: list[str]) -> str:
    slides = sorted(
        (int(m.group(1)), n) for n in names if (m := re.fullmatch(r"ppt/slides/slide(\d+)\.xml", n))
    )
    out = []
    for number, name in slides:
        xml = _read_part(zf, name)
        lines = ["".join(_unescape(t) for t in _A_TEXT.findall(p)) for p in _A_PARA.findall(xml)]
        out.append(f"--- Slide {number} ---\n" + "\n".join(line for line in lines if line))
    return "\n\n".join(out).strip()


def _xlsx_text(zf: zipfile.ZipFile, names: list[str]) -> str:
    shared = []
    if "xl/sharedStrings.xml" in names:
        shared = ["".join(_unescape(t) for t in _T.findall(si)) for si in _SI.findall(_read_part(zf, "xl/sharedStrings.xml"))]
    sheet_names = [_unescape(n) for n in _SHEET_NAME.findall(_read_part(zf, "xl/workbook.xml"))]
    sheets = sorted(
        (int(m.group(1)), n) for n in names if (m := re.fullmatch(r"xl/worksheets/sheet(\d+)\.xml", n))
    )
    out = []
    for index, (number, name) in enumerate(sheets):
        title = sheet_names[index] if index < len(sheet_names) else f"Sheet{number}"
        rows_out = []
        for row in _ROW.findall(_read_part(zf, name))[:MAX_XLSX_ROWS]:
            cells = []
            for attrs, body in _CELL.findall(row):
                value = _V.search(body or b"")
                if b't="s"' in attrs and value:
                    idx = int(value.group(1) or b"0")
                    cells.append(shared[idx] if 0 <= idx < len(shared) else "")
                elif b't="inlineStr"' in attrs:
                    cells.append("".join(_unescape(t) for t in _T.findall(body or b"")))
                else:
                    cells.append(_unescape(value.group(1)) if value else "")
            rows_out.append("\t".join(cells))
        out.append(f"--- {title} ---\n" + "\n".join(rows_out))
    return "\n\n".join(out).strip()
