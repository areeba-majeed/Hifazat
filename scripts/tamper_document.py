"""Part 3, scenario 4 - DOCUMENT MODIFICATION outside the application.
    python -m scripts.tamper_document <document-id> [--mode blob|digest|swap]
  blob   : flip one byte of the encrypted blob on disk
  digest : overwrite the recorded SHA-256 in the database
  swap   : replace this document's blob with another document's blob
Then open the document in the app and click "Verify integrity" or "Download".
"""
from __future__ import annotations

import argparse
import sqlite3

from app.config import Settings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("doc_id")
    ap.add_argument("--mode", choices=["blob", "digest", "swap"], default="blob")
    args = ap.parse_args()
    s = Settings.from_env()
    con = sqlite3.connect(s.db_path)
    row = con.execute("SELECT blob_name, sha256 FROM document_versions WHERE document_id=? "
                      "ORDER BY version DESC LIMIT 1", (args.doc_id,)).fetchone()
    if row is None:
        raise SystemExit("No such document id.")
    blob_name, digest = row
    path = s.blob_dir / blob_name

    if args.mode == "blob":
        data = bytearray(path.read_bytes())
        i = len(data) // 2
        data[i] ^= 0x01
        path.write_bytes(bytes(data))
        print(f"Flipped one bit at offset {i} of {path.name} (attacker editing storage).")
    elif args.mode == "digest":
        fake = "f" * 64
        con.execute("UPDATE document_versions SET sha256=? WHERE blob_name=?", (fake, blob_name))
        con.commit()
        print(f"Replaced recorded SHA-256 {digest[:16]}... with {fake[:16]}... in the database.")
    else:
        other = con.execute("SELECT blob_name FROM document_versions WHERE document_id<>? LIMIT 1",
                            (args.doc_id,)).fetchone()
        if other is None:
            raise SystemExit("Need a second document to swap with.")
        path.write_bytes((s.blob_dir / other[0]).read_bytes())
        print(f"Replaced {path.name} with a copy of another document's valid ciphertext.")
    con.close()
    print("Now verify or download the document in the application.")


if __name__ == "__main__":
    main()
