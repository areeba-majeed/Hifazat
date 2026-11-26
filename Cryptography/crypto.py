"""All cryptography goes through the pyca `cryptography` library and
`argon2-cffi`. Nothing here implements a primitive by hand.
  * Every document version gets a fresh random 256-bit DEK.
  * Content is encrypted with AES-256-GCM(DEK). AAD binds the ciphertext
    to its document id + version, so blobs cannot be swapped between docs.
  * The DEK is wrapped with AES-256-GCM(master KEK). Only the wrapped DEK
    is stored in the database; the KEK lives in keys/ (KMS/HSM in prod).
  * SHA-256(plaintext) is signed with the server's Ed25519 key, giving an
    independently verifiable integrity record for each version.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # 96-bit nonce, as recommended for GCM


class IntegrityError(Exception):
    """Cryptographic integrity check failed (HMAC, signature, or GCM tag)."""
#keys

def _write_secret(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)  # best effort; no-op on most Windows setups
    except OSError:
        pass


def _load_or_create_raw(path: Path, length: int = 32) -> bytes:
    if path.exists():
        key = path.read_bytes()
        if len(key) != length:
            raise RuntimeError(f"Key file {path.name} is corrupt (wrong length)")
        return key
    key = secrets.token_bytes(length)
    _write_secret(path, key)
    return key


def _load_or_create_ed25519(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_secret(path, pem)
    return key


class KeyRing:
    """Holds the three independent server secrets.

    master.key  - KEK that wraps per-document DEKs (confidentiality)
    signing_key - Ed25519 key that signs document digests (integrity)
    audit.key   - HMAC key for the audit chain (log integrity)
    Separate keys => compromise of one does not silently defeat the others.
    """

    def __init__(self, key_dir: Path):
        key_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir = key_dir
        self.master_key = _load_or_create_raw(key_dir / "master.key")
        self.audit_key = _load_or_create_raw(key_dir / "audit.key")
        self.signing_key = _load_or_create_ed25519(key_dir / "signing_key.pem")
        self.verify_key: Ed25519PublicKey = self.signing_key.public_key()


# documents

def _content_aad(doc_id: str, version: int) -> bytes:
    return f"sdms:content:{doc_id}:v{version}".encode()


def _dek_aad(doc_id: str, version: int) -> bytes:
    return f"sdms:dek:{doc_id}:v{version}".encode()


def wrap_dek(master_key: bytes, dek: bytes, doc_id: str, version: int) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(master_key).encrypt(nonce, dek, _dek_aad(doc_id, version))


def unwrap_dek(master_key: bytes, wrapped: bytes, doc_id: str, version: int) -> bytes:
    try:
        return AESGCM(master_key).decrypt(wrapped[:NONCE_LEN], wrapped[NONCE_LEN:],
                                          _dek_aad(doc_id, version))
    except InvalidTag as exc:
        raise IntegrityError("wrapped key failed authentication") from exc


def encrypt_document(master_key: bytes, plaintext: bytes, doc_id: str, version: int
                     ) -> tuple[bytes, bytes]:
    """Returns (blob, wrapped_dek). blob = nonce || ciphertext || tag."""
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(NONCE_LEN)
    blob = nonce + AESGCM(dek).encrypt(nonce, plaintext, _content_aad(doc_id, version))
    return blob, wrap_dek(master_key, dek, doc_id, version)


def decrypt_document(master_key: bytes, blob: bytes, wrapped_dek: bytes, doc_id: str,
                     version: int) -> bytes:
    dek = unwrap_dek(master_key, wrapped_dek, doc_id, version)
    try:
        return AESGCM(dek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:],
                                   _content_aad(doc_id, version))
    except InvalidTag as exc:
        raise IntegrityError("document ciphertext failed authentication") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sig_message(doc_id: str, version: int, digest_hex: str) -> bytes:
    return f"sdms-doc-v1|{doc_id}|{version}|{digest_hex}".encode()


def sign_digest(key: Ed25519PrivateKey, doc_id: str, version: int, digest_hex: str) -> bytes:
    return key.sign(_sig_message(doc_id, version, digest_hex))


def verify_digest_signature(pub: Ed25519PublicKey, signature: bytes, doc_id: str,
                            version: int, digest_hex: str) -> bool:
    try:
        pub.verify(signature, _sig_message(doc_id, version, digest_hex))
        return True
    except InvalidSignature:
        return False


# tokens / misc

def new_token() -> str:
    """256-bit URL-safe random token (sessions, share links, CSRF)."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# passwords

_ph = PasswordHasher()  # Argon2id with library defaults (RFC 9106 profile)
# Pre-computed hash used to equalise timing when a username does not exist.
_DUMMY_HASH = _ph.hash("timing-equaliser-not-a-real-password")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)
