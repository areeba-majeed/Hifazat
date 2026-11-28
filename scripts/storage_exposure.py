"""Part 3, scenario 3 - STORAGE EXPOSURE.
Plays an attacker who has stolen (a) the blob folder and (b) the database file,
but NOT the keys/ folder. Prints exactly what that attacker can and cannot learn.
    python -m scripts.storage_exposure
"""
from __future__ import annotations

import sqlite3

from app.config import Settings

KNOWN_SECRET_WORDS = [b"CONFIDENTIAL", b"budget", b"salary", b"Project plan"]


def main() -> None:
    s = Settings.from_env()
    print("=" * 72)
    print("ATTACKER VIEW 1: stolen blob storage  ->", s.blob_dir)
    print("=" * 72)
    blobs = sorted(p for p in s.blob_dir.iterdir() if p.is_file())
    for p in blobs:
        data = p.read_bytes()
        hits = [w.decode() for w in KNOWN_SECRET_WORDS if w.lower() in data.lower()]
        print(f"{p.name}  {len(data):6d} bytes  first 24 bytes: {data[:24].hex()}")
        print(f"   plaintext keywords found: {hits or 'NONE'}")
    print(f"\n{len(blobs)} blobs. File names are random; no owner, title or type is visible.")
    print("Learnable: number of files, approximate sizes (ciphertext = size + 28 bytes), timestamps.")

    print()
    print("=" * 72)
    print("ATTACKER VIEW 2: stolen database  ->", s.db_path)
    print("=" * 72)
    con = sqlite3.connect(s.db_path)
    print("users (password column is Argon2id hash only):")
    for row in con.execute("SELECT id, username, role, substr(password_hash,1,40) FROM users"):
        print("  ", row)
    print("document_versions (wrapped_dek is encrypted under the master key):")
    for row in con.execute("SELECT document_id, version, blob_name, hex(substr(wrapped_dek,1,12)), "
                           "length(wrapped_dek), substr(sha256,1,16) FROM document_versions"):
        print("  ", row)
    print("documents (metadata that IS exposed - a known limitation):")
    for row in con.execute("SELECT id, owner_id, title, original_filename FROM documents"):
        print("  ", row)
    print("sessions / share links store SHA-256 of the token only:")
    for row in con.execute("SELECT 'session', substr(token_hash,1,24) FROM sessions LIMIT 3"):
        print("  ", row)
    con.close()

    print()
    print("CONCLUSION")
    print(" * Cannot learn: document contents, data keys, passwords, usable session/link tokens.")
    print(" * Can learn: usernames, titles, filenames, who-shares-with-whom, sizes, timestamps.")
    print(" * Contents become readable only if the attacker ALSO steals keys/master.key")
    print("   (in production that key would live in a KMS/HSM, not on the same server).")

if __name__ == "__main__":
    main()
