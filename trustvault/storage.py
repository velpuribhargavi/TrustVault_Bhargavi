"""Encrypted blob store on the local filesystem.

Blobs are named by a server-generated random id - never by anything the user
sent - and live under ``instance/blobs``, which is not served by any route.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

_BLOB_ID = re.compile(r"^[A-Za-z0-9_-]{20,64}$")


class BlobStore:
    def __init__(self, root: Path, durable: bool = True):
        self.root = root
        self.durable = durable
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, blob_id: str) -> Path:
        if not _BLOB_ID.match(blob_id):
            raise ValueError("invalid blob id")
        path = (self.root / blob_id[:2] / blob_id).resolve()
        if self.root.resolve() not in path.parents:
            raise ValueError("blob path escapes store")
        return path

    def write(self, blob_id: str, data: bytes) -> None:
        path = self._path(blob_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                if self.durable:
                    os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def read(self, blob_id: str) -> bytes:
        return self._path(blob_id).read_bytes()

    def delete(self, blob_id: str) -> None:
        try:
            self._path(blob_id).unlink()
        except FileNotFoundError:
            pass

    def exists(self, blob_id: str) -> bool:
        return self._path(blob_id).exists()
