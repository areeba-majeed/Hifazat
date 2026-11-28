"""Blob store for encrypted document data.
Blobs are named with random hex only: the storage area reveals nothing about
owners, titles or filenames. Content is already encrypted before it gets here.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

_NAME_RE = re.compile(r"^[0-9a-f]{32}$")


class BlobStore:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        if not _NAME_RE.fullmatch(name):  # blocks path traversal
            raise ValueError("invalid blob name")
        return self.root / name

    @staticmethod
    def new_name() -> str:
        return secrets.token_hex(16)

    def write(self, name: str, data: bytes) -> None:
        path = self._path(name)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)  # atomic: never a half-written blob

    def read(self, name: str) -> bytes | None:
        path = self._path(name)
        return path.read_bytes() if path.exists() else None

    def delete(self, name: str) -> None:
        path = self._path(name)
        if path.exists():
            path.unlink()
