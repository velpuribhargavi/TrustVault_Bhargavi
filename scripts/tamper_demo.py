"""Demo for the video / interview: show that quietly editing the audit trail
is detected. Works on a COPY of the database, never the real one.

    python scripts/tamper_demo.py

It copies instance/ to a temporary folder, plays an insider who has write
access to the database file (drops the append-only triggers, rewrites who
downloaded a document, then deletes the newest rows), and runs the verifier
after each step.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trustvault.audit import AuditLog  # noqa: E402
from trustvault.config import load_settings  # noqa: E402
from trustvault.crypto import KeyRing  # noqa: E402
from trustvault.db import connect  # noqa: E402


def show(title, audit, conn):
    r = audit.verify(conn).as_dict()
    state = "INTACT" if r["ok"] else f"TAMPERING DETECTED at entry {r['first_bad_seq']}"
    print(f"\n== {title}\n   -> {state}")
    for p in r["problems"] + r["warnings"]:
        print(f"      {p}")


def main() -> None:
    settings = load_settings()
    if not settings.db_path.exists():
        print("Run scripts/init_db.py --seed first.")
        return
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "instance"
        shutil.copytree(settings.instance_dir, copy)
        s = settings.with_overrides(instance_dir=copy)
        audit = AuditLog(KeyRing.load(s.keys_dir), s.anchor_path)
        conn = connect(s.db_path)
        show("1. Untouched copy", audit, conn)

        try:
            conn.execute("UPDATE audit_log SET actor_name = 'someone-else' WHERE seq = 2")
        except Exception as exc:
            print(f"\n== 2. Plain UPDATE through SQLite\n   -> refused: {exc}")

        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("UPDATE audit_log SET actor_name = 'someone-else' WHERE seq = 2")
        show("3. Insider drops the triggers and rewrites entry 2", audit, conn)

        conn.close()
        shutil.copy(settings.db_path, s.db_path)  # fresh copy for the next attack
        for ext in ("-wal", "-shm"):
            src = Path(str(settings.db_path) + ext)
            if src.exists():
                shutil.copy(src, Path(str(s.db_path) + ext))
        conn = connect(s.db_path)
        conn.execute("DROP TRIGGER audit_log_no_delete")
        last = conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
        conn.execute("DELETE FROM audit_log WHERE seq > ?", (last - 2,))
        show("4. Insider deletes the two newest entries (a clean truncation)", audit, conn)
        conn.close()
    print("\nThe real database was not modified.")


if __name__ == "__main__":
    main()
