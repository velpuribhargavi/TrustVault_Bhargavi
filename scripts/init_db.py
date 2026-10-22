"""Create the database, the encryption keys and (optionally) demo data.

    python scripts/init_db.py            # schema + keys only (safe to re-run)
    python scripts/init_db.py --seed     # also create demo users and documents
    python scripts/init_db.py --reset --seed   # wipe instance/ first (asks to confirm)

Everything is created inside the instance directory (default ./instance, or
TRUSTVAULT_INSTANCE_DIR). Seeding goes through the same storage, encryption
and audit code as the API, so the demo audit trail verifies like any other.
"""
from __future__ import annotations

import argparse
import io
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trustvault.audit import AuditContext  # noqa: E402
from trustvault.config import load_settings  # noqa: E402
from trustvault.context import AppContext  # noqa: E402
from trustvault.db import SchemaVersionError, connect, init_schema, transaction  # noqa: E402
from trustvault.services import store_version  # noqa: E402
from trustvault.utils import iso_in, new_id, now_iso  # noqa: E402
from trustvault.validation import validate_upload  # noqa: E402

# The three demo logins - one per role, as the hand-in asks. Change them for any real use.
# (Passwords deliberately do not contain the username: the password policy forbids that.)
USERS = [
    # username, display name, role, password, external?
    ("admin", "Asha Admin", "admin", "Keeper!Vault2026", False),
    ("owner", "Olivia Owner", "owner", "Author!Vault2026", False),
    ("viewer", "Vikram Viewer", "viewer", "Reader!Vault2026", False),
]


def pdf(*pages: str) -> bytes:
    """A small valid PDF with one page per string (Helvetica, wrapped lines)."""
    import textwrap
    objs: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>", b""]  # pages tree filled in below
    font_obj = 3
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    kids = []
    for text in pages:
        lines = []
        for para in text.split("\n"):
            lines.extend(textwrap.wrap(para, 80) or [""])
        ops = [b"BT /F1 13 Tf 16 TL 72 740 Td"]
        for line in lines:
            safe = line.replace("\\", "/").replace("(", "[").replace(")", "]").encode("latin-1", "replace")
            ops.append(b"(" + safe + b") Tj T*")
        ops.append(b"ET")
        stream = b"\n".join(ops)
        objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        content_obj = len(objs)
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents "
                    + str(content_obj).encode() + b" 0 R /Resources << /Font << /F1 "
                    + str(font_obj).encode() + b" 0 R >> >> >>")
        kids.append(len(objs))
    objs[1] = (b"<< /Type /Pages /Kids [" + b" ".join(f"{k} 0 R".encode() for k in kids)
               + b"] /Count " + str(len(kids)).encode() + b" >>")
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.4\n")
    for i, o in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + o + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def docx(*paragraphs: str) -> bytes:
    from xml.sax.saxutils import escape
    body = "".join(f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   f'<w:body>{body}</w:body></w:document>')
    return buf.getvalue()


def png(width: int = 480, height: int = 300) -> bytes:
    """A simple 'floor plan': rooms drawn as rectangles."""
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (width, height), (246, 248, 247))
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, width - 10, height - 10], outline=(15, 61, 58), width=4)
    for x0, y0, x1, y1, label in [(10, 10, 200, 150, "Meeting room"), (200, 10, 470, 150, "Open office"),
                                  (10, 150, 160, 290, "Server room"), (160, 150, 470, 290, "Reception")]:
        d.rectangle([x0, y0, x1, y1], outline=(15, 61, 58), width=2)
        d.text((x0 + 10, y0 + 10), label, fill=(15, 61, 58))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


SALARY = pdf(
    "SALARY LETTER - CONFIDENTIAL\n\nTo: Vikram Viewer\nFrom: People Team\n\n"
    "We are pleased to confirm your revised annual compensation of INR 18,00,000 effective 1 April 2026. "
    "This letter is shared with you as VIEW ONLY: you can read it in TrustVault but not download it.",
    "Page 2 - Terms\n\nThis letter is confidential and must not be forwarded. Every page you open in "
    "TrustVault is watermarked with your name and recorded in the audit trail.",
)

# Every grant expires (the API default is DEFAULT_GRANT_MINUTES = 30). The demo
# grants last a week so the demo data still works tomorrow; the owner can extend
# or shorten them in the UI.
SEED_GRANT_DAYS = 7

DOCUMENTS = [
    # owner, filename, display name, category, description, content, grants [(user, level, days)]
    ("owner", "salary-letter-vikram.pdf", "Salary letter - Vikram", "hr",
     "Shared with Vikram as VIEW ONLY (read in the browser, no download).", SALARY, [("viewer", "view", SEED_GRANT_DAYS)]),
    ("owner", "office-floor-plan.png", "Office floor plan", "general",
     "Shared as VIEW ONLY.", png(), [("viewer", "view", SEED_GRANT_DAYS)]),
    ("owner", "q3-contract-acme.docx", "Q3 services contract - Acme Corp", "contract",
     "Shared with Vikram as VIEW + DOWNLOAD.",
     docx("MASTER SERVICES AGREEMENT", "Between our company and Acme Corp, for Q3 2026.",
          "1. Scope: document management services.", "2. Fees: INR 12,00,000 per quarter."),
     [("viewer", "download", SEED_GRANT_DAYS)]),
    ("owner", "budget-2026.csv", "Budget 2026", "finance",
     "Shared with Vikram with EDIT access (he can upload new versions and rename it).",
     b"department,quarter,amount\nEngineering,Q1,450000\nEngineering,Q2,470000\nSales,Q1,300000\nSales,Q2,320000\n",
     [("viewer", "edit", SEED_GRANT_DAYS)]),
    ("owner", "board-minutes-private.pdf", "Board minutes - private", "legal",
     "NOT shared with anyone. Vikram must never be able to reach it.",
     pdf("BOARD MINUTES - PRIVATE\n\nDiscussion of the planned acquisition. Not for distribution."), []),
    ("owner", "audit-papers-fy2026.csv", "Audit papers FY2025-26", "audit",
     "Not shared with anyone. Try a 5-minute share link: Share link -> Vikram -> open it as viewer.",
     b"account,description,amount\n4000,Revenue,1250000.00\n5000,Cost of sales,-640000.00\n6100,Salaries,-310000.00\n",
     []),
]


def main() -> None:
    ap = argparse.ArgumentParser(description="Initialise TrustVault")
    ap.add_argument("--seed", action="store_true", help="create demo users and documents")
    ap.add_argument("--reset", action="store_true", help="delete the instance directory first")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = ap.parse_args()

    settings = load_settings()
    inst = settings.instance_dir
    if args.reset and inst.exists():
        if not args.yes and input(f"Delete {inst} (database, files, keys, audit trail)? Type YES: ") != "YES":
            print("Aborted.")
            return
        shutil.rmtree(inst)
        print(f"Removed {inst}")

    try:
        init_schema(settings.db_path)
    except SchemaVersionError as exc:
        print(f"\n{exc}\n")
        sys.exit(1)
    ctx = AppContext.build(settings, create_keys=True)
    print(f"Database : {settings.db_path}")
    print(f"Keys     : {settings.keys_dir} (keep these secret and backed up separately)")

    if not args.seed:
        print("Schema ready. Run with --seed for demo data.")
        return

    conn = connect(settings.db_path)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("Users already exist - not seeding again. Use --reset --seed to start over.")
        return

    ids: dict[str, str] = {}
    seed_ctx = AuditContext(actor_id=None, actor_name="system:seed", ip="local", user_agent="init_db.py")
    with transaction(conn) as tx:
        for username, display, role, password, external in USERS:
            uid = new_id()
            ids[username] = uid
            tx.execute(
                """INSERT INTO users (id, username, display_name, password_hash, role, is_external, created_at,
                                      password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (uid, username, display, ctx.passwords.hash(password), role, int(external), now_iso(), now_iso()),
            )
            ctx.audit.append(tx, seed_ctx, "user.create", "allowed", target_user_id=uid,
                             details={"username": username, "role": role, "is_external": external, "seeded": True})

    for owner, filename, name, category, description, content, grants in DOCUMENTS:
        safe_name, ftype = validate_upload(filename, content, settings.max_upload_bytes)
        actor = AuditContext(ids[owner], owner, "local", "init_db.py")
        doc_id = new_id()
        with transaction(conn) as tx:
            tx.execute("""INSERT INTO documents (id, owner_id, name, category, description, created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (doc_id, ids[owner], name, category, description, now_iso(), now_iso()))
            v = store_version(tx, ctx, document_id=doc_id, filename=safe_name, file_type=ftype, data=content,
                              uploaded_by=ids[owner])
            ctx.audit.append(tx, actor, "document.upload", "allowed", document_id=doc_id,
                             details={"name": name, "filename": safe_name, "category": category,
                                      "size": v["size_bytes"], "sha256": v["sha256"], "seeded": True})
            for user, perm, days in grants:
                expires = iso_in(days=days)
                gid = new_id()
                tx.execute("""INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?)""", (gid, doc_id, ids[user], perm, ids[owner], now_iso(), expires))
                ctx.audit.append(tx, actor, "access.granted", "allowed", document_id=doc_id, target_user_id=ids[user],
                                 details={"permission": perm, "expires_at": expires, "target_username": user,
                                          "target_external": False, "grant_id": gid, "seeded": True})

    print("\nThe three demo logins (change these before any real use):")
    print(f"  {'role':8} {'username':9} password")
    for username, _, role, password, external in USERS:
        print(f"  {role:8} {username:9} {password}")
    print(f"\nWhat 'viewer' can do with each of owner's documents (grants last {SEED_GRANT_DAYS} days):")
    for _, _, name, _, _, _, grants in DOCUMENTS:
        level = grants[0][1] if grants else "NO ACCESS"
        print(f"  {level:10} {name}")
    print(f"\nTime limits: new grants {settings.default_grant_minutes} min by default, share links "
          f"{settings.link_ttl_seconds // 60} min, sign-out after {settings.session_idle_minutes} min idle "
          f"or {settings.session_absolute_hours} h.")
    print("\nNext: python -m trustvault   then open http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
