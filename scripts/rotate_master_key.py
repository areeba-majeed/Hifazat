"""Rotate the master key
Only the small wrapped DEKs are re-encrypted; document blobs are untouched
(a benefit of envelope encryption). Stop the server before running.
    python -m scripts.rotate_master_key
"""
from __future__ import annotations

import secrets
import shutil
from datetime import datetime

from sqlalchemy import select

from app.config import Settings
from app.crypto import unwrap_dek, wrap_dek
from app.db import make_engine, make_session_factory
from app.models import DocumentVersion


def main() -> None:
    s = Settings.from_env()
    key_path = s.key_dir / "master.key"
    old_key = key_path.read_bytes()
    new_key = secrets.token_bytes(32)

    Session = make_session_factory(make_engine(s.db_path))
    with Session() as db:
        versions = db.scalars(select(DocumentVersion)).all()
        for v in versions:   # all-or-nothing: one transaction
            dek = unwrap_dek(old_key, v.wrapped_dek, v.document_id, v.version)
            v.wrapped_dek = wrap_dek(new_key, dek, v.document_id, v.version)
        # write the new key BEFORE commit, keeping a backup of the old one
        backup = key_path.with_name(f"master.key.retired-{datetime.now():%Y%m%d%H%M%S}")
        shutil.copy2(key_path, backup)
        key_path.write_bytes(new_key)
        try:
            db.commit()
        except Exception:
            shutil.copy2(backup, key_path)  # roll back key file
            raise
    print(f"Re-wrapped {len(versions)} data keys under a new master key.")
    print(f"Old key saved as {backup.name} - destroy it securely once backups are re-verified.")


if __name__ == "__main__":
    main()
