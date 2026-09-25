from database.connection import get_db

class NetworkRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def get_by_site(self, site_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM networks WHERE site_id = ? ORDER BY id ASC", (site_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_or_create(self, site_id, cidr, name=None, gateway=None, vlan_id=None, description=""):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM networks WHERE site_id = ? AND cidr = ?",
                (site_id, cidr)
            )
            row = cursor.fetchone()
            if row:
                # The scan form may correct a gateway recorded in an earlier run.
                if gateway and gateway != row["gateway"]:
                    cursor.execute(
                        "UPDATE networks SET gateway = ? WHERE id = ?",
                        (gateway, row["id"])
                    )
                return row["id"]
            
            network_name = name or f"Red {cidr}"
            cursor.execute("""
                INSERT INTO networks (site_id, name, cidr, gateway, vlan_id, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (site_id, network_name, cidr, gateway, vlan_id, description))
            return cursor.lastrowid
