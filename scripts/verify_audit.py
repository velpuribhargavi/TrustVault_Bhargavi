"""Verify the audit trail offline (no server needed).

    python scripts/verify_audit.py

Checks every entry's HMAC, the chain links, sequence gaps, the external
anchors and the append-only triggers. Exit code 0 = intact, 1 = tampered.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trustvault.audit import AuditLog  # noqa: E402
from trustvault.config import load_settings  # noqa: E402
from trustvault.crypto import KeyRing  # noqa: E402
from trustvault.db import connect  # noqa: E402


def main() -> int:
    settings = load_settings()
    if not settings.db_path.exists():
        print(f"No database at {settings.db_path}")
        return 2
    keyring = KeyRing.load(settings.keys_dir, create=False)
    conn = connect(settings.db_path)
    result = AuditLog(keyring, settings.anchor_path).verify(conn).as_dict()
    print(json.dumps(result, indent=2))
    print(f"\n{result['message']}")
    print("AUDIT TRAIL INTACT" if result["ok"] else "AUDIT TRAIL HAS BEEN TAMPERED WITH")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
