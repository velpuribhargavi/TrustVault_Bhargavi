"""Print the current two-step sign-in codes of the DEMO admin and owner.

    python scripts/demo_code.py            # both, once
    python scripts/demo_code.py --watch    # keep printing as they change

The demo accounts use the published keys in scripts/init_db.py (DEMO_TOTP_KEYS),
so this works without any access to the database or the server's keys. Real
accounts have their own secret keys that never leave the server.
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from trustvault import totp  # noqa: E402


def demo_keys() -> dict[str, str]:
    spec = importlib.util.spec_from_file_location("init_db", ROOT / "scripts" / "init_db.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DEMO_TOTP_KEYS


def show(keys: dict[str, str]) -> None:
    now = time.time()
    left = totp.STEP_SECONDS - int(now) % totp.STEP_SECONDS
    print("  ".join(f"{name}: {totp.code_at(key, now)}" for name, key in keys.items()) + f"   ({left:2d} s left)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--watch", action="store_true")
    keys = demo_keys()
    if not ap.parse_args().watch:
        show(keys)
        return
    try:
        while True:
            show(keys)
            time.sleep(totp.STEP_SECONDS - int(time.time()) % totp.STEP_SECONDS + 0.2)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
