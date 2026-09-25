from database.connection import get_db

class ConnectionRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def get_by_site(self, site_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.*, 
                       sd.ip as source_ip, sd.hostname as source_hostname, sd.device_type as source_type,
                       td.ip as target_ip, td.hostname as target_hostname, td.device_type as target_type
                FROM connections c
                JOIN devices sd ON c.source_device_id = sd.id
                JOIN devices td ON c.target_device_id = td.id
                WHERE c.site_id = ?
                ORDER BY c.id ASC
            """, (site_id,))
            return [dict(row) for row in cursor.fetchall()]

    def create_or_update(self, site_id, source_id, target_id, 
                         source_interface_id=None, target_interface_id=None,
                         connection_type="ETHERNET", discovery_method="MANUAL", confidence="HIGH"):
        if source_id == target_id:
            return None  # No self-loops

        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM connections 
                WHERE (source_device_id = ? AND target_device_id = ?)
                   OR (source_device_id = ? AND target_device_id = ?)
            """, (source_id, target_id, target_id, source_id))
            existing = cursor.fetchone()

            if existing:
                # Do not downgrade a MANUAL connection to an automatic one
                if existing["discovery_method"] == "MANUAL" and discovery_method != "MANUAL":
                    return existing["id"]

                cursor.execute("""
                    UPDATE connections
                    SET connection_type = ?,
                        discovery_method = ?,
                        confidence = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (connection_type, discovery_method, confidence, existing["id"]))
                return existing["id"]
            else:
                cursor.execute("""
                    INSERT INTO connections (
                        site_id, source_device_id, source_interface_id,
                        target_device_id, target_interface_id,
                        connection_type, discovery_method, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    site_id, source_id, source_interface_id,
                    target_id, target_interface_id,
                    connection_type, discovery_method, confidence
                ))
                return cursor.lastrowid

    def delete(self, connection_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
            return cursor.rowcount > 0

    def clear_discovered_for_site(self, site_id):
        """Clears automatic connections before rebuilding topology, preserving MANUAL links."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM connections WHERE site_id = ? AND discovery_method != 'MANUAL'",
                (site_id,)
            )
            return cursor.rowcount
