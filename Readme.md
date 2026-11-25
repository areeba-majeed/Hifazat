<div align="center">

# 🔐 SecureDocs

### Secure Document Management System

*A web application for storing confidential documents, with envelope encryption, per-document access control, controlled sharing, integrity verification and a tamper-evident audit trail.*

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Jinja2-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-SQLAlchemy%202.0-003B57?logo=sqlite&logoColor=white)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-success)
![Tests](https://img.shields.io/badge/tests-39%20pytest-brightgreen)
![Course](https://img.shields.io/badge/CS3002-Information%20Security-blueviolet)

</div>

---

> 🎯 **Goal:** a system you can *defend*, not a big one. Every security decision below is implemented in code and exercised by an automated test.

## 📑 Table of Contents

1. [Tech Stack](#-tech-stack)
2. [Setup and Run](#-setup-and-run)
3. [Architecture](#-architecture)
4. [Security Design](#-security-design)
5. [Attack Scenarios (Part 3)](#-attack-scenarios-part-3)
6. [Project Structure](#-project-structure)
7. [Known Limitations](#-known-limitations)
8. [Libraries Used](#-libraries-used)

---

## 🧰 Tech Stack

| Layer | Choice |
|---|---|
| 🐍 **Language** | Python 3.11+ (tested on 3.14) |
| 🌐 **Web framework** | FastAPI + Jinja2 server-rendered templates (no client-side JS) |
| 🗄️ **Database** | SQLite via SQLAlchemy 2.0 (parameterized queries) |
| 📦 **Document storage** | Encrypted blobs on the local filesystem (`data/blobs/`) |
| 🔑 **Cryptography** | pyca `cryptography` (AES-256-GCM, Ed25519, HMAC-SHA256), `argon2-cffi` (Argon2id) |
| 🧪 **Tests** | pytest + FastAPI TestClient |

---

## 🚀 Setup and Run

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt

python -m scripts.seed_demo       # optional: demo users + documents
python -m uvicorn app.main:app --port 8000
```

> [!TIP]
> Always start tools with `python -m ...`. On machines with Device Guard / Application Control, the `uvicorn.exe` and `pytest.exe` launchers may be blocked, but `python -m` still works.

Open **http://localhost:8000**. On first start, the app creates `data/` (database and blobs) and `keys/` (secrets).

### 👥 Demo Accounts

Created by `seed_demo`. These are **TEST values, not real secrets**.

| User | Password | Notes |
|---|---|---|
| 👑 `admin` | `Copper-Tide-Demo-2026` | Administrator (users + audit log, **no** document access) |
| 👩 `alice` | `Orchid-Lamp-Demo-2026` | Owns "Q4 Budget" (bob = viewer, carol = editor) and "Salary review notes" |
| 👨 `bob` | `Granite-Kite-Demo-2026` | Owns "Project plan" (alice = viewer) |
| 👩‍💼 `carol` | `Velvet-Moss-Demo-2026` | Editor on "Q4 Budget" |
| 🕵️ `mallory` | `Silent-Fox-Demo-2026` | Has no access to anything, use for attack demos |

- To create a real administrator: `python -m scripts.create_admin`
- To reset everything: stop the server and delete the `data/` and `keys/` folders.

### 🧪 Run the Tests

```bash
python -m pytest -v
```

The test suite has **39 tests**, which reproduce all **7 attack scenarios** from Part 3. Each test runs on a fresh, temporary database and set of keys.

<details>
<summary>🪟 <b>Troubleshooting (Windows)</b></summary>

<br>

- **`WinError 206 filename too long`** while installing: create the venv at a short path (for example `C:\venvs\sdms`).
- **`DLL load failed ... Application Control policy`**: keep SQLAlchemy on 2.0.x, as pinned in `requirements.txt`. If its C extension is blocked, SQLAlchemy 2.0 falls back to pure Python automatically.

</details>

---

## 🏗️ Architecture

```text
 Browser ──HTTPS──▶ FastAPI app ──────────────▶ SQLite  data/sdms.db
   (cookie:          │  auth (Argon2id,             users, sessions (token hashes),
    session +        │   sessions, CSRF)            documents, versions (WRAPPED keys,
    CSRF token)      │  authorize() on every        digests, signatures), permissions,
                     │   document route             share links (token hashes),
                     │  crypto (AES-GCM,            audit_log (HMAC chain)
                     │   Ed25519, HMAC)
                     │                      ────▶ data/blobs/<random>   nonce‖ciphertext‖tag
                     └─ reads secrets from  ────▶ keys/  master.key  signing_key.pem
                                                         audit.key   audit_anchor.json
```

Three trust zones are kept apart: **database**, **blob store** and **keys**. If an attacker steals one or two of them, they still cannot read documents.

---

## 🛡️ Security Design

> Summary, for the report.

### 🗃️ Storage and Confidentiality

- The server encrypts each upload **in memory**, before anything is written to disk. Plaintext is never written to a temp file.
- Each blob file is `nonce(12) ‖ AES-256-GCM ciphertext ‖ tag(16)`. File names are random hex, so the files reveal no owner, title or type.
- The database stores metadata, the wrapped DEKs, digests and signatures. It **never** stores plaintext, passwords or raw tokens.
- **What an attacker can still see:** usernames, titles, filenames, sharing relationships, sizes and timestamps. This is a documented limitation. Run `python -m scripts.storage_exposure` to see it.

### 🔑 Cryptography and Key Management (Envelope Encryption)

| Element | How it works |
|---|---|
| **Per-version DEK** | A random 256-bit key encrypts the content with AES-256-GCM. The AAD is `doc_id + version`, so a blob cannot be moved to a different document. |
| **Master KEK** (`keys/master.key`) | Wraps each DEK with AES-256-GCM. Only the wrapped DEK is stored in the database. In production, the KEK would live in a KMS or HSM. |
| **Integrity** | The GCM tag detects any change to the ciphertext. `SHA-256(plaintext)` is signed with Ed25519, which detects edits to the recorded digest. |
| **Key compromise** | `python -m scripts.rotate_master_key` re-wraps every DEK under a new KEK. Document blobs are not touched. |
| **Lost password** | An administrator unlocks the account or resets credentials, and the documents stay readable. This trade-off comes from server-side encryption. The design notes E2EE as the stronger alternative that was considered and rejected. |
| **Deletion** | Removing the wrapped DEKs *crypto-shreds* any copy of a blob left in backups. |

### 🔐 Authentication and Authorization

#### Passwords

- Hashed with **Argon2id**; minimum 12 characters, and the password may not contain the username.
- The login error message is the same for every failure, and timing is equalized when the username doesn't exist.
- The account locks for **15 minutes** after **5** failed attempts.

#### Sessions

- Each session uses a 256-bit random token. Only its SHA-256 hash is stored, and a new token is issued at every login.
- The cookie is `HttpOnly` and `SameSite=Strict`, plus `Secure` when served over HTTPS.
- Sessions expire after **30 minutes idle** or **8 hours absolute**. Logout and password changes revoke them on the server.

#### CSRF

A synchronizer token is required on every POST. Login and registration use a double-submit cookie.

#### Access-Control Model

A hybrid of two models:

- **RBAC** system roles: `admin` and `user`.
- **DAC** per document: `owner`, `editor` or `viewer`, granted by the owner.

| Action | Owner | Editor | Viewer | Admin (no grant) |
|---|:---:|:---:|:---:|:---:|
| View / download / verify | ✅ | ✅ | ✅ | ❌ |
| Upload new version | ✅ | ✅ | ❌ | ❌ |
| Share / revoke / links | ✅ | ❌ | ❌ | ❌ |
| Delete | ✅ | ❌ | ❌ | ❌ |
| Manage users, read audit log | ❌ | ❌ | ❌ | ✅ |

`authorize()` in `app/security.py` runs on **every** document route and **denies by default**. Hiding buttons in the UI is only a convenience.

A forbidden document and a non-existent one return the **identical 404**, so error messages can't be used to find out which document IDs exist.

### 🔗 Sharing and Revocation

- **User shares:** a viewer or editor role, with an optional expiry date. Permission is checked on each request, so revoking takes effect on the very next request.
- **Temporary links:**
  - Each link is a 256-bit bearer token; only its hash is stored.
  - It expires after at most **72 hours** and allows **1 to 20** downloads. The owner can revoke it.
  - `Referrer-Policy: no-referrer` stops the token from leaking.
- **Downloads:** always sent as `application/octet-stream` + `attachment` + `no-store`, so the browser never renders the content and nothing is cached.

> [!WARNING]
> Revocation cannot recall copies that were already downloaded. The audit trail shows who downloaded what and when.

### 📜 Auditing

| | |
|---|---|
| ✅ **Logged** | Logins (success, failure, lockout), uploads, downloads, verifications, grants, revocations, link creation and use, deletions, admin actions, every denied request, and integrity failures. |
| 🚫 **Never logged** | Passwords, keys, tokens or document contents. |

- **Hash chain:** every record includes the previous record's hash, and the HMAC-SHA256 key is kept separately in `keys/audit.key`. An anchor file outside the database lets the check detect deleted records at the end of the log.
- **SQLite triggers** block `UPDATE` and `DELETE` on `audit_log`. This is defence in depth; the HMAC chain is the real detection control.
- When a user is denied **5 or more times in 10 minutes**, a `SUSPICIOUS_ACTIVITY` ALERT record is written. The admin dashboard flags actors with repeated denials or failures.

---

## ⚔️ Attack Scenarios (Part 3)

| # | Scenario | Live demo | Automated test |
|:---:|---|---|---|
| 1 | 🚪 **Unauthorized access** | Log in as `mallory` and open a link to alice's document → `404`, logged as `DENIED` | `TestS1UnauthorizedAccess` |
| 2 | 🔢 **ID manipulation** | As `bob`, change the ID in `/documents/<id>/download` to alice's "Salary review notes" → `404`, same response as a random ID | `TestS2IdentifierManipulation` |
| 3 | 💾 **Storage exposure** | `python -m scripts.storage_exposure` | `TestS3StorageExposure` |
| 4 | ✏️ **Document modification** | `python -m scripts.tamper_document <doc-id> --mode blob\|digest\|swap`, then click *Verify integrity* or *Download* | `TestS4DocumentModification` |
| 5 | 🎭 **Privilege misuse** | As `bob` (viewer), try to upload a new version of "Q4 Budget"; open `/admin` as a normal user | `TestS5PrivilegeMisuse` |
| 6 | 🚫 **Permission revocation** | `alice` revokes `bob`, and bob's next download gets a `404`; create and then revoke a share link | `TestS6PermissionRevocation` |
| 7 | 🧾 **Audit tampering** | Stop the server, run `python -m scripts.tamper_audit --mode modify\|delete\|truncate`, start it again → *Admin › Audit log › Verify log integrity* | `TestS7AuditTampering` |

---

## 📁 Project Structure

```text
app/
  config.py        settings and storage layout
  crypto.py        envelope encryption, signatures, tokens, Argon2id
  models.py        database schema
  db.py            engine and append-only audit triggers
  audit.py         HMAC hash-chained audit log + anchor
  storage.py       blob store (random names, atomic writes)
  documents.py     encrypt-on-write / verify-on-read
  security.py      sessions, CSRF, authorize() access-control checks
  routes_*.py      HTTP routes (auth, documents and sharing, admin)
  templates/, static/
scripts/           seed_demo, create_admin, rotate_master_key, attack demos
tests/             pytest suite (Part 3 evidence)
```

---

## ⚠️ Known Limitations

| Limitation | Details |
|---|---|
| 🖥️ **Server-side encryption** | If the server itself is fully compromised (master key plus memory), documents are exposed. E2EE would fix this, but at the cost of harder sharing and key recovery. |
| 👀 **Exposed metadata** | Titles and filenames are stored in plaintext in the database. |
| 🗝️ **Key storage** | Keys sit on the same host as files. Production should use a KMS or HSM and separate machines. |
| 🧵 **Single process** | The audit-chain lock assumes a single server process (run uvicorn with one worker). |
| 📥 **Downloaded copies** | Revocation cannot recall copies already downloaded. Watermarking or DRM would be needed for that. |
| 🔓 **No HTTPS in dev** | Deploy behind TLS and set `SDMS_SECURE_COOKIES=1`. |

---

## 📚 Libraries Used

FastAPI, Starlette, Uvicorn, Jinja2, SQLAlchemy, pyca/cryptography, argon2-cffi, python-multipart, pytest, HTTPX.

All cryptographic primitives come from these libraries. **None are implemented by hand.**

---

<div align="center">

Made for **CS3002 Information Security** 🛡️

</div>