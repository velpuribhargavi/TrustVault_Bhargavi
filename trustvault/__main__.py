"""Run the server:  python -m trustvault [--host 127.0.0.1] [--port 8000]"""
from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the TrustVault server")
    parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default 127.0.0.1 = this machine only)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"TrustVault running on http://{args.host}:{args.port}  (API docs: /api/docs)")
    # One worker on purpose: rate limiting and the audit anchor writer are in-process.
    uvicorn.run("trustvault.main:create_app", factory=True, host=args.host, port=args.port,
                workers=1, proxy_headers=False, server_header=False, log_level="info")


if __name__ == "__main__":
    main()
