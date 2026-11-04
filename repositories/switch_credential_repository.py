"""Encrypted SNMP profiles scoped to an installation and management IP."""
import ipaddress
import json

from database.connection import get_db
from repositories.nvr_credential_repository import NvrCredentialRepository


class SwitchCredentialRepository:
    def __init__(self, db_path):
        self.db_path = db_path
        # Share the existing local Fernet key and encryption implementation.
        self.secrets = NvrCredentialRepository(db_path)

    def list_by_site(self, site_id, include_credentials=False):
        with get_db(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM switch_credentials WHERE site_id=? ORDER BY ip",
                                (site_id,)).fetchall()
        result = []
        for row in rows:
            data = dict(row)
            token = data.pop("credentials_enc")
            data["tables"] = json.loads(data.pop("tables_json") or "{}")
            if include_credentials:
                plaintext = self.secrets._decrypt(token)
                data["credentials"] = json.loads(plaintext) if plaintext else None
            result.append(data)
        return result

    def save(self, site_id, ip, credentials):
        ip = str(ipaddress.IPv4Address(ip))
        encrypted = self.secrets._encrypt(json.dumps(credentials))
        with get_db(self.db_path) as conn:
            conn.execute("""
                INSERT INTO switch_credentials(site_id,ip,credentials_enc) VALUES (?,?,?)
                ON CONFLICT(site_id,ip) DO UPDATE SET credentials_enc=excluded.credentials_enc,
                    status='pending',tables_json='{}',checked_at=NULL
            """, (site_id,ip,encrypted))

    def set_result(self, site_id, ip, status, tables):
        with get_db(self.db_path) as conn:
            conn.execute("""UPDATE switch_credentials SET status=?,tables_json=?,
                         checked_at=CURRENT_TIMESTAMP WHERE site_id=? AND ip=?""",
                         (status,json.dumps(tables),site_id,ip))

    def remove(self, site_id, ip):
        with get_db(self.db_path) as conn:
            conn.execute("DELETE FROM switch_credentials WHERE site_id=? AND ip=?", (site_id,ip))
