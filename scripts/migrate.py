"""Upgrade the database schema in place, keeping every row and the audit chain.

    python scripts/migrate.py

The server does the same upgrade by itself at start-up; this script exists so
it can be run (and checked) on purpose. It:

1. copies the database to instance/backups/ first (SQLite online backup),
2. upgrades the schema (v3 -> v4: audit session column + audit-page indexes),
3. backfills hashes if the audit table predates the hash chain,
4. records the upgrade as an 'audit.migrated' event, and
5. verifies the whole chain and prints "Chain intact (N events)" - or the
   first broken or missing event number.

Exit code 0 = upgraded (or already current) and intact, 1 = chain broken,
2 = this database cannot be upgraded (too old: use reset.bat).
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trustvault.config import load_settings  # noqa: E402
from trustvault.context import AppContext  # noqa: E402
from trustvault.db import SCHEMA_VERSION, SchemaVersionError, connect, init_schema  # noqa: E402
from trustvault.main import record_upgrade  # noqa: E402
from trustvault.utils import utcnow  # noqa: E402


def backup(db_path: Path, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{db_path.stem}-before-v{SCHEMA_VERSION}-{utcnow():%Y%m%d-%H%M%S}.db"
    src, dst = sqlite3.connect(str(db_path)), sqlite3.connect(str(target))
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    return target


def main() -> int:
    settings = load_settings()
    if not settings.db_path.exists():
        print(f"No database at {settings.db_path} - nothing to upgrade. Run scripts/init_db.py --seed.")
        return 0
    print(f"Database : {settings.db_path}")
    print(f"Backup   : {backup(settings.db_path, settings.instance_dir / 'backups')}")
    try:
        upgrade = init_schema(settings.db_path)
    except SchemaVersionError as exc:
        print(f"\n{exc}\n")
        return 2
    ctx = AppContext.build(settings, create_keys=False)
    conn = connect(settings.db_path)
    try:
        record_upgrade(conn, ctx, upgrade)
        if upgrade is not None and upgrade.changed:
            print(f"Upgraded : schema v{upgrade.from_version} -> v{upgrade.to_version}")
            for step in upgrade.steps:
                print(f"           - {step}")
        else:
            print(f"Schema   : already v{SCHEMA_VERSION}, nothing to do")
        result = ctx.audit.verify(conn)
    finally:
        conn.close()
    print(f"Audit    : {result.message}")
    for w in result.warnings:
        print(f"Warning  : {w}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
