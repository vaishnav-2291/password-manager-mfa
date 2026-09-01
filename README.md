# 🔐 Password Manager with MFA-Protected Login

A secure, command-line password manager built in Python that combines master-password-based key derivation, a canary integrity check, and TOTP-based multi-factor authentication (MFA) with strong symmetric encryption for all stored credentials.

## Features

- **Master Password Key Derivation** — derives an encryption key from your master password using a salted key-derivation function, so the raw password is never stored.
- **Canary Verification** — validates that the correct master password was entered *before* attempting to decrypt the vault, preventing corrupted or garbage decrypts on a wrong password.
- **TOTP-Based MFA** — every login requires a live 6-digit time-based one-time code from an authenticator app (Google Authenticator, Authy, etc.), generated via `pyotp`.
- **Encrypted Vault** — all credentials are encrypted at rest using the `cryptography` library.
- **Credential Management** — add, view, search, and delete stored credentials through a simple CLI menu.

## Tech Stack

- Python 3
- [`cryptography`](https://pypi.org/project/cryptography/) — key derivation and encryption/decryption
- [`pyotp`](https://pypi.org/project/pyotp/) — TOTP MFA code generation and verification

## How It Works

1. **First run** — you create a master password. A salt is generated and an encryption key is derived from your password + salt. A canary value is encrypted and stored to validate future logins. An MFA secret is generated and printed for you to add to an authenticator app.
2. **Every login after that** — you enter your master password (checked against the canary) followed by a live 6-digit TOTP code from your authenticator app before the vault unlocks.
3. **Once unlocked** — credentials are decrypted on demand and can be added, viewed, searched, or deleted from the CLI menu.

## Setup

```bash
git clone <repo-url>
cd password-manager-mfa
pip install -r requirements.txt
python password_manager_mfa.py
```

## First-Time Use

1. Run the script — you'll be prompted to create a master password.
2. An MFA secret key (and an `otpauth://` URI) is printed. Add it to Google Authenticator / Authy via manual entry or a QR code.
3. Save the secret somewhere safe — it's required for every future login.

## Usage

```
1) Add credential
2) View all credentials
3) Search credential
4) Delete credential
5) Exit
```

## Security Notes

- Master passwords are never stored — only a derived key and a canary value.
- Vault data is encrypted at rest; without the correct master password *and* a valid MFA code, credentials cannot be decrypted.
- This project is built for educational and portfolio purposes to demonstrate core authentication and encryption concepts. Review and harden it further before using it to store real, sensitive credentials.

## Part of a Security Portfolio

This project is one of five covering different security domains:

| # | Project | Domain |
|---|---------|--------|
| 1 | CryptoScope AI | Blockchain |
| 2 | Web App Vulnerability Scanner | Application Security |
| 3 | Network Recon & Intrusion Detection Toolkit | Network Security |
| 4 | IoT Device Security Scanner | IoT Security |
| 5 | **Password Manager with MFA** | Authentication / Identity Security |
