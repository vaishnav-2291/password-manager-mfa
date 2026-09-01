#!/usr/bin/env python3
"""
Password Manager with MFA-Protected Login
-------------------------------------------
A secure local password manager that requires TWO factors to unlock:
  1. Something you know  - your master password
  2. Something you have  - a 6-digit TOTP code from an authenticator app

Design notes (worth mentioning in interviews):
  - Credentials are encrypted with a key DERIVED from the master password
    (PBKDF2-HMAC-SHA256) - the key is never stored on disk.
  - The master password itself is never stored either. Instead, a "canary"
    token is encrypted at setup time; login succeeds only if the entered
    password derives a key that correctly decrypts the canary. This is the
    same principle real password managers (e.g. KeePass) use.
  - MFA uses TOTP (RFC 6238) - compatible with Google Authenticator / Authy.

Author: Vaishnav | Cybersecurity mini-project
"""

import sqlite3
import base64
import os
import getpass
import sys
import hashlib

from cryptography.fernet import Fernet, InvalidToken
import pyotp

DB_PATH = "vault.db"
CANARY_TEXT = "vault-unlocked-ok"


# --------------------------------------------------------------------------
# DATABASE
# --------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL,
            canary BLOB NOT NULL,
            totp_secret TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL
        )"""
    )
    conn.commit()
    return conn


def is_vault_initialized(conn):
    return conn.execute("SELECT 1 FROM vault_meta WHERE id = 1").fetchone() is not None


# --------------------------------------------------------------------------
# KEY DERIVATION / ENCRYPTION
# --------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return base64.urlsafe_b64encode(key)


def encrypt(fernet: Fernet, plaintext: str) -> bytes:
    return fernet.encrypt(plaintext.encode())


def decrypt(fernet: Fernet, token: bytes) -> str:
    return fernet.decrypt(token).decode()


# --------------------------------------------------------------------------
# SETUP (first run)
# --------------------------------------------------------------------------
def setup_vault(conn):
    print("\n[+] No vault found. Let's set one up.\n")
    while True:
        pwd1 = getpass.getpass("Create a master password: ")
        pwd2 = getpass.getpass("Confirm master password: ")
        if pwd1 == pwd2 and len(pwd1) >= 8:
            break
        print("Passwords didn't match or are too short (min 8 chars). Try again.\n")

    salt = os.urandom(16)
    key = derive_key(pwd1, salt)
    fernet = Fernet(key)
    canary = encrypt(fernet, CANARY_TEXT)

    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name="vaishnav-vault", issuer_name="PasswordManagerMFA")

    conn.execute(
        "INSERT INTO vault_meta (id, salt, canary, totp_secret) VALUES (1, ?, ?, ?)",
        (salt, canary, totp_secret),
    )
    conn.commit()

    print("\n[+] Vault created successfully.")
    print(f"[!] Your MFA secret key (add this to Google Authenticator / Authy):\n    {totp_secret}")
    print(f"[!] Or scan this URI as a QR code with any QR generator:\n    {uri}\n")
    print("Save this secret somewhere safe - you'll need your authenticator app every login.\n")


# --------------------------------------------------------------------------
# LOGIN
# --------------------------------------------------------------------------
def login(conn):
    row = conn.execute("SELECT salt, canary, totp_secret FROM vault_meta WHERE id = 1").fetchone()
    salt, canary, totp_secret = row

    for attempt in range(3):
        pwd = getpass.getpass("Master password: ")
        key = derive_key(pwd, salt)
        fernet = Fernet(key)
        try:
            decrypted = decrypt(fernet, canary)
            if decrypted == CANARY_TEXT:
                break
        except InvalidToken:
            pass
        print("Incorrect master password.\n")
    else:
        print("Too many failed attempts. Exiting.")
        sys.exit(1)

    totp = pyotp.TOTP(totp_secret)
    for attempt in range(3):
        code = input("Enter 6-digit MFA code from your authenticator app: ").strip()
        if totp.verify(code):
            print("\n[+] MFA verified. Vault unlocked.\n")
            return fernet
        print("Incorrect or expired code.\n")

    print("Too many failed MFA attempts. Exiting.")
    sys.exit(1)


# --------------------------------------------------------------------------
# CREDENTIAL OPERATIONS
# --------------------------------------------------------------------------
def add_credential(conn, fernet):
    site = input("Site/app name: ").strip()
    username = input("Username/email: ").strip()
    pwd = getpass.getpass("Password to store: ")
    enc = encrypt(fernet, pwd)
    conn.execute(
        "INSERT INTO credentials (site, username, encrypted_password) VALUES (?, ?, ?)",
        (site, username, enc),
    )
    conn.commit()
    print(f"[+] Saved credentials for '{site}'.\n")


def list_credentials(conn, fernet, search_term=None):
    rows = conn.execute("SELECT id, site, username, encrypted_password FROM credentials").fetchall()
    if search_term:
        rows = [r for r in rows if search_term.lower() in r[1].lower()]

    if not rows:
        print("No credentials found.\n")
        return

    print(f"\n{'ID':<5}{'SITE':<20}{'USERNAME':<25}{'PASSWORD'}")
    for row_id, site, username, enc in rows:
        pwd = decrypt(fernet, enc)
        print(f"{row_id:<5}{site:<20}{username:<25}{pwd}")
    print()


def delete_credential(conn, cred_id):
    conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    conn.commit()
    print(f"[+] Deleted credential ID {cred_id}.\n")


# --------------------------------------------------------------------------
# MAIN MENU
# --------------------------------------------------------------------------
def main():
    print("=" * 60)
    print(" Password Manager with MFA-Protected Login")
    print("=" * 60)

    conn = init_db()
    if not is_vault_initialized(conn):
        setup_vault(conn)

    fernet = login(conn)

    while True:
        print("1) Add credential\n2) View all credentials\n3) Search credential\n4) Delete credential\n5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            add_credential(conn, fernet)
        elif choice == "2":
            list_credentials(conn, fernet)
        elif choice == "3":
            term = input("Search site name: ").strip()
            list_credentials(conn, fernet, term)
        elif choice == "4":
            cred_id = input("Credential ID to delete: ").strip()
            if cred_id.isdigit():
                delete_credential(conn, int(cred_id))
        elif choice == "5":
            print("Vault locked. Goodbye!")
            break
        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    main()
