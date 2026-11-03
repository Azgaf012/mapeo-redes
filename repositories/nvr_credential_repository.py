"""Per-NVR credentials, stored in SQLite with the password encrypted (Fernet).

The key file lives next to the database (``nvr_secret.key``) and is created on first use.
A row is keyed by the NVR's MAC (or ``ip:<ip>`` when the MAC is unknown) so the same
recorder keeps its credentials across scans and across sites that reuse the same IPs.
"""

import os
import re

from cryptography.fernet import Fernet, InvalidToken

from database.connection import get_db


def nvr_key(ip, mac=""):
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    return clean if len(clean) == 12 else f"ip:{ip}"


class NvrCredentialRepository:
    def __init__(self, db_path, key_path=None):
        self.db_path = db_path
        self.key_path = key_path or os.path.join(
            os.path.dirname(os.path.abspath(db_path)), "nvr_secret.key")
        self._fernet = None

    # -- encryption ---------------------------------------------------------
    def _cipher(self):
        if self._fernet is None:
            if os.path.isfile(self.key_path):
                with open(self.key_path, "rb") as handle:
                    key = handle.read().strip()
            else:
                key = Fernet.generate_key()
                with open(self.key_path, "wb") as handle:
                    handle.write(key)
                try:
                    os.chmod(self.key_path, 0o600)
                except OSError:
                    pass
            self._fernet = Fernet(key)
        return self._fernet

    def _encrypt(self, text):
        return self._cipher().encrypt((text or "").encode("utf-8")).decode("ascii") if text else ""

    def _decrypt(self, token):
        if not token:
            return ""
        try:
            return self._cipher().decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return ""

    # -- rows ---------------------------------------------------------------
    def seen(self, ip, mac=""):
        """Register a detected NVR (status 'pending') and return its row."""
        key = nvr_key(ip, mac)
        with get_db(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO nvr_credentials (key, ip, mac) VALUES (?, ?, ?)",
                (key, ip, mac or ""))
            conn.execute("UPDATE nvr_credentials SET ip = ? WHERE key = ?", (ip, key))
            row = conn.execute("SELECT * FROM nvr_credentials WHERE key = ?", (key,)).fetchone()
        return self._row(row)

    def get(self, ip, mac=""):
        with get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM nvr_credentials WHERE key = ?",
                               (nvr_key(ip, mac),)).fetchone()
        return self._row(row) if row else None

    def list_all(self):
        with get_db(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM nvr_credentials").fetchall()
        return [self._row(row) for row in rows]

    def _row(self, row):
        data = dict(row)
        data["password"] = self._decrypt(data.pop("password_enc", ""))
        data["has_credentials"] = bool(data.get("username") and data["password"])
        return data

    def save_credentials(self, ip, mac, username, password, port=80):
        """Set credentials for one NVR; resets its status so it is retried."""
        key = nvr_key(ip, mac)
        self.seen(ip, mac)
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE nvr_credentials SET username=?, password_enc=?, port=?, "
                "status='pending', detail='' WHERE key=?",
                (username, self._encrypt(password), int(port or 80), key))
        return key

    def apply_to_unresolved(self, username, password, port=80):
        """Give the same account to every NVR that has none or was rejected."""
        encrypted = self._encrypt(password)
        with get_db(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE nvr_credentials SET username=?, password_enc=?, port=?, "
                "status='pending', detail='' "
                "WHERE status IN ('pending','auth_failed') AND (username='' OR status='auth_failed')",
                (username, encrypted, int(port or 80)))
            return cursor.rowcount

    def set_result(self, ip, mac, status, detail="", camera_count=0):
        key = nvr_key(ip, mac)
        self.seen(ip, mac)
        with get_db(self.db_path) as conn:
            conn.execute(
                "UPDATE nvr_credentials SET status=?, detail=?, camera_count=?, "
                "checked_at=CURRENT_TIMESTAMP WHERE key=?",
                (status, detail[:300], camera_count, key))
