"""Document protection service: encrypt-on-write, verify-on-read.
Protection happens on the server immediately after upload, before anything
touches disk. Plaintext only ever exists in memory.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from . import crypto
from .crypto import IntegrityError
from .models import Document, DocumentVersion, User


def store_version(state, db: Session, doc: Document, version: int, data: bytes,
                  user: User) -> DocumentVersion:
    keys = state.keys
    blob, wrapped = crypto.encrypt_document(keys.master_key, data, doc.id, version)
    digest = crypto.sha256_hex(data)
    sig = crypto.sign_digest(keys.signing_key, doc.id, version, digest)
    name = state.blobs.new_name()
    state.blobs.write(name, blob)
    v = DocumentVersion(document_id=doc.id, version=version, blob_name=name,
                        wrapped_dek=wrapped, sha256=digest, signature=sig,
                        size=len(data), uploaded_by=user.id)
    db.add(v)
    return v


def read_version(state, v: DocumentVersion) -> bytes:
    """Decrypt and fully verify one version. Raises IntegrityError on ANY failure,
    so tampered content is never returned to a user."""
    report = verify_version(state, v, keep_plaintext=True)
    if not report["ok"]:
        failed = next(c for c in report["checks"] if c["ok"] is False)
        raise IntegrityError(failed["name"])
    return report["plaintext"]


def verify_version(state, v: DocumentVersion, keep_plaintext: bool = False) -> dict:
    keys = state.keys
    checks: list[dict] = []
    plaintext = None

    def add(name: str, ok: bool | None, note: str = ""):
        checks.append({"name": name, "ok": ok, "note": note})

    blob = state.blobs.read(v.blob_name)
    add("Encrypted blob present in storage", blob is not None)
    dek_ok = ct_ok = False
    if blob is not None:
        try:
            dek = crypto.unwrap_dek(keys.master_key, v.wrapped_dek, v.document_id, v.version)
            dek_ok = True
        except IntegrityError:
            pass
        add("Wrapped data key authenticates (AES-256-GCM, master key)", dek_ok)
        if dek_ok:
            try:
                plaintext = crypto.decrypt_document(keys.master_key, blob, v.wrapped_dek,
                                                    v.document_id, v.version)
                ct_ok = True
            except IntegrityError:
                pass
            add("Ciphertext authenticates (AES-256-GCM tag)", ct_ok,
                "" if ct_ok else "stored bytes were altered outside the application")
    if ct_ok:
        digest = crypto.sha256_hex(plaintext)
        add("SHA-256 of content matches recorded digest", crypto.constant_eq(digest, v.sha256))
    else:
        add("SHA-256 of content matches recorded digest", None, "skipped")
    add("Ed25519 signature over digest is valid",
        crypto.verify_digest_signature(keys.verify_key, v.signature, v.document_id,
                                       v.version, v.sha256),
        "detects edits to the recorded digest in the database")

    ok = all(c["ok"] is True for c in checks)
    result = {"version": v.version, "ok": ok, "checks": checks}
    if keep_plaintext and ok:
        result["plaintext"] = plaintext
    return result


def delete_document(state, db: Session, doc: Document) -> int:
    """Removes rows (incl. wrapped DEKs) first, then blobs. Once the wrapped DEKs
    are gone, any leftover copy of a blob (e.g. in a backup) is undecryptable
    (crypto-shredding)."""
    names = [v.blob_name for v in doc.versions]
    db.delete(doc)
    db.commit()
    for n in names:
        state.blobs.delete(n)
    return len(names)
