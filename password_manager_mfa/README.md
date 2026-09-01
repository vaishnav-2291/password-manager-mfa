# Password Manager with MFA-Protected Login

A local password manager that requires two factors to unlock your vault:
your master password, plus a 6-digit TOTP code from an authenticator app
(Google Authenticator, Authy, etc.) — just like real production login systems.

## Features

| Feature | Description |
|---|---|
| **Master Password** | Unlocks the vault; never stored on disk |
| **TOTP-based MFA** | RFC 6238 standard, compatible with any authenticator app |
| **AES Encryption (Fernet)** | All stored credentials encrypted with a key derived from your master password |
| **Add / View / Search / Delete** | Full CRUD for stored site credentials |
| **SQLite Storage** | Local, portable, single-file vault database |

## Security Design (worth explaining in interviews)

- The encryption key is **derived** from your master password using
  PBKDF2-HMAC-SHA256 (200,000 iterations) — the key itself is never stored.
- Your master password is also never stored. Instead, a "canary" token is
  encrypted at setup time; login only succeeds if the password you enter
  derives a key that correctly decrypts that canary. This is the same
  principle real password managers like KeePass use.
- MFA is a second, independent factor — even if your master password leaks,
  an attacker still needs your authenticator app to get in.

## Tech Stack

Python 3, `cryptography` (Fernet/AES), `pyotp` (TOTP/MFA), `sqlite3` (stdlib), `hashlib` (PBKDF2)

## Setup

```bash
pip install cryptography pyotp
```

## Usage

```bash
python3 password_manager_mfa.py
```

**First run:** creates your vault — set a master password, then scan/enter
the printed MFA secret into your authenticator app.

**Every run after:** enter master password → enter the 6-digit code from
your authenticator app → vault unlocks → menu to add/view/search/delete
credentials.

## Example Flow

```
Create a master password: ********
[+] Vault created successfully.
[!] Your MFA secret key: JBSWY3DPEHPK3PXP
...
Master password: ********
Enter 6-digit MFA code from your authenticator app: 784682
[+] MFA verified. Vault unlocked.

1) Add credential
2) View all credentials
3) Search credential
4) Delete credential
5) Exit
```

## What This Demonstrates

- Password-based key derivation (PBKDF2) vs storing plaintext/hashed secrets
- Symmetric encryption (AES via Fernet) for data at rest
- Multi-factor authentication (TOTP/RFC 6238) implementation
- SQLite schema design and CRUD operations
- Secure input handling (`getpass` to avoid shell-history / echo leaks)

## Resume Bullet

> Built a local password manager requiring master-password + TOTP-based MFA
> to unlock; derived the AES encryption key via PBKDF2-HMAC-SHA256 (never
> storing the password or key on disk) and validated a canary-token scheme
> for secure authentication without plaintext password storage.
