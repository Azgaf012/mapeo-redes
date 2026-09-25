from database.connection import get_db

class SiteRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def get_all(self):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, 
                       (SELECT COUNT(*) FROM devices d WHERE d.site_id = s.id) as device_count,
                       (SELECT COUNT(*) FROM connections c WHERE c.site_id = s.id) as connection_count
                FROM sites s
                ORDER BY s.id ASC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_by_id(self, site_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sites WHERE id = ?", (site_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_name(self, name):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sites WHERE name = ?", (name,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def create(self, name, description="", address_reference=""):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO sites (name, description, address_reference) VALUES (?, ?, ?)",
                (name, description, address_reference)
            )
            return cursor.lastrowid

    def update(self, site_id, name, description="", address_reference=""):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sites 
                SET name = ?, description = ?, address_reference = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (name, description, address_reference, site_id))
            return cursor.rowcount > 0

    def delete(self, site_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sites WHERE id = ?", (site_id,))
            return cursor.rowcount > 0
