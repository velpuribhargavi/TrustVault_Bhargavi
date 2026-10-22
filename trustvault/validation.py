"""Validation of uploaded files and their names.

The client's Content-Type header and file extension are both treated as
claims. A file is accepted only when its extension is on the allow-list AND
its actual bytes match that type AND it carries no active content we know how
to detect (PDF JavaScript, Office macros, remote templates, CSV formulas...).
"""
from __future__ import annotations

import csv
import io
import re
import struct
import unicodedata
import zipfile
from dataclasses import dataclass

from .utils import clean_line

CATEGORIES = ("contract", "hr", "finance", "legal", "engineering", "audit", "general")

MAX_NAME_LEN = 200
MAX_DESCRIPTION_LEN = 1000

# Zip-bomb limits for Office documents.
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024
MAX_ZIP_RATIO = 100

MAX_IMAGE_PIXELS = 40_000_000

_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class FileType:
    extension: str
    mime: str


# ---------------------------------------------------------------------------
# File names
# ---------------------------------------------------------------------------
def sanitize_filename(raw: str) -> str:
    """Reduce a client-supplied filename to a safe display name.

    The result is only ever used for display and in Content-Disposition; it
    never touches the filesystem (blobs are stored under random ids).
    """
    name = unicodedata.normalize("NFKC", raw or "")
    # Keep only the last path component, whatever separator the client used.
    name = re.split(r"[\\/]", name)[-1]
    name = clean_line(name, 255)
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name)
    name = name.strip(" .")
    if not name:
        raise ValidationError("file name is empty")
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if stem.lower() in _WINDOWS_RESERVED:
        stem = "_" + stem
    ext = ext.lower()
    stem = stem[: MAX_NAME_LEN - len(ext) - 1] if ext else stem[:MAX_NAME_LEN]
    return f"{stem}.{ext}" if ext else stem


def extension_of(filename: str) -> str:
    _, dot, ext = filename.rpartition(".")
    return ext.lower() if dot else ""


# ---------------------------------------------------------------------------
# Content checks
# ---------------------------------------------------------------------------
_PDF_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|XFA|SubmitForm|ImportData)\b")


def _check_pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-"):
        raise ValidationError("content is not a PDF")
    if b"%%EOF" not in data[-4096:]:
        raise ValidationError("PDF is truncated or malformed")
    # PDF names may hex-escape characters (/J#61vaScript == /JavaScript).
    normalised = _PDF_NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)
    if _PDF_ACTIVE.search(normalised):
        raise ValidationError("PDF contains active content (JavaScript, launch actions or embedded files)")


def _check_png(data: bytes) -> None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or data[12:16] != b"IHDR" or len(data) < 33:
        raise ValidationError("content is not a PNG image")
    width, height = struct.unpack(">II", data[16:24])
    if width == 0 or height == 0 or width * height > MAX_IMAGE_PIXELS:
        raise ValidationError("PNG dimensions are not acceptable")


def _check_jpeg(data: bytes) -> None:
    if not data.startswith(b"\xff\xd8\xff") or len(data) < 4:
        raise ValidationError("content is not a JPEG image")
    if b"\xff\xd9" not in data[-1024:]:
        raise ValidationError("JPEG is truncated or malformed")


_ALLOWED_CONTROL = {"\t", "\n", "\r", "\f"}


def _decode_text(data: bytes) -> str:
    if b"\x00" in data:
        raise ValidationError("text file contains binary data")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("text file must be UTF-8") from exc
    for ch in text:
        if unicodedata.category(ch) == "Cc" and ch not in _ALLOWED_CONTROL:
            raise ValidationError("text file contains control characters")
    return text


def _check_txt(data: bytes) -> None:
    _decode_text(data)


_NUMBER = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?%?$")


def _check_csv(data: bytes) -> None:
    text = _decode_text(data)
    try:
        for row in csv.reader(io.StringIO(text)):
            for cell in row:
                stripped = cell.lstrip()
                if stripped[:1] in ("=", "@") or (stripped[:1] in ("+", "-") and not _NUMBER.match(stripped)):
                    raise ValidationError("CSV contains a formula cell (spreadsheet formula injection)")
                if cell[:1] in ("\t", "\r"):
                    raise ValidationError("CSV cell starts with a control character")
    except csv.Error as exc:
        raise ValidationError("CSV is malformed") from exc


_OOXML_MAIN_PART = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml", "pptx": "ppt/presentation.xml"}
_DANGEROUS_REL_TYPES = re.compile(rb"/(attachedTemplate|oleObject|frame|subDocument)\"", re.IGNORECASE)


def _check_ooxml(data: bytes, ext: str) -> None:
    if not data.startswith(b"PK\x03\x04"):
        raise ValidationError(f"content is not a valid .{ext} file")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError) as exc:
        raise ValidationError(f"content is not a valid .{ext} file") from exc
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValidationError("document has too many parts")
    total = 0
    names = set()
    for info in infos:
        name = info.filename
        if name.startswith(("/", "\\")) or ".." in name.split("/"):
            raise ValidationError("document contains an unsafe path")
        if info.flag_bits & 0x1:
            raise ValidationError("encrypted documents are not accepted")
        total += info.file_size
        if total > MAX_ZIP_TOTAL_UNCOMPRESSED:
            raise ValidationError("document expands to an unsafe size (zip bomb)")
        if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO and info.file_size > 1024 * 1024:
            raise ValidationError("document has an unsafe compression ratio (zip bomb)")
        names.add(name.lower())
    if "[content_types].xml" not in names or _OOXML_MAIN_PART[ext] not in names:
        raise ValidationError(f"content is not a valid .{ext} file")
    if any(n.endswith("vbaproject.bin") for n in names):
        raise ValidationError("documents containing macros are not accepted")
    content_types = zf.read("[Content_Types].xml")
    if b"macroEnabled" in content_types or b"vbaProject" in content_types:
        raise ValidationError("documents containing macros are not accepted")
    for name in names:
        if name.endswith(".rels"):
            rels = zf.read(next(i.filename for i in infos if i.filename.lower() == name))
            if b'TargetMode="External"' in rels and _DANGEROUS_REL_TYPES.search(rels):
                raise ValidationError("document references an external template or object")


ALLOWED_TYPES: dict[str, tuple[FileType, callable]] = {
    "pdf": (FileType("pdf", "application/pdf"), _check_pdf),
    "png": (FileType("png", "image/png"), _check_png),
    "jpg": (FileType("jpg", "image/jpeg"), _check_jpeg),
    "jpeg": (FileType("jpeg", "image/jpeg"), _check_jpeg),
    "txt": (FileType("txt", "text/plain"), _check_txt),
    "csv": (FileType("csv", "text/csv"), _check_csv),
    "docx": (FileType("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
             lambda d: _check_ooxml(d, "docx")),
    "xlsx": (FileType("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
             lambda d: _check_ooxml(d, "xlsx")),
    "pptx": (FileType("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
             lambda d: _check_ooxml(d, "pptx")),
}


def validate_upload(filename: str, data: bytes, max_bytes: int) -> tuple[str, FileType]:
    """Return (safe_filename, file_type) or raise ValidationError."""
    safe_name = sanitize_filename(filename)
    if not data:
        raise ValidationError("file is empty")
    if len(data) > max_bytes:
        raise ValidationError(f"file is larger than {max_bytes // (1024 * 1024)} MB")
    ext = extension_of(safe_name)
    if ext not in ALLOWED_TYPES:
        allowed = ", ".join(sorted(ALLOWED_TYPES))
        raise ValidationError(f"file type '.{ext}' is not allowed (allowed: {allowed})")
    file_type, check = ALLOWED_TYPES[ext]
    check(data)
    return safe_name, file_type


def validate_category(category: str) -> str:
    value = (category or "").strip().lower()
    if value not in CATEGORIES:
        raise ValidationError(f"category must be one of: {', '.join(CATEGORIES)}")
    return value


def validate_doc_name(name: str) -> str:
    value = clean_line(name, MAX_NAME_LEN)
    if not value:
        raise ValidationError("name must not be empty")
    return value


def validate_description(text: str) -> str:
    from .utils import clean_text
    return clean_text(text, MAX_DESCRIPTION_LEN)
