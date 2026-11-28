"""Application settings.
Storage layout:
  data/sdms.db        - metadata database (users, ACLs, wrapped keys, audit log)
  data/blobs/         - encrypted document blobs (random names, no metadata)
  keys/               - master key, signing key, audit key, audit anchor
                        
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    data_dir: Path
    key_dir: Path
    secure_cookies: bool = False          
    session_idle_minutes: int = 30
    session_absolute_hours: int = 8
    max_upload_bytes: int = 10 * 1024 * 1024
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    share_link_max_hours: int = 72

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sdms.db"

    @property
    def blob_dir(self) -> Path:
        return self.data_dir / "blobs"

    @property
    def audit_anchor_path(self) -> Path:
        # Kept with the keys, NOT in the database, so an attacker who can
        # rewrite the database cannot also silently move the anchor.
        return self.key_dir / "audit_anchor.json"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            data_dir=Path(os.environ.get("SDMS_DATA_DIR", BASE_DIR / "data")),
            key_dir=Path(os.environ.get("SDMS_KEY_DIR", BASE_DIR / "keys")),
            secure_cookies=os.environ.get("SDMS_SECURE_COOKIES", "0") == "1",
        )
