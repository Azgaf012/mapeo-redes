"""Snapshot of client-to-AP associations from an operator-supplied export."""

from database.connection import get_db


class ApAssociationRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def replace_snapshot(self, site_id, associations):
        with get_db(self.db_path) as conn:
            conn.execute("DELETE FROM ap_client_associations WHERE site_id=?", (site_id,))
            conn.executemany("""
                INSERT INTO ap_client_associations (site_id, client_mac, ap_device_id)
                VALUES (?, ?, ?)
            """, [(site_id, mac, ap_id) for mac, ap_id in associations])

    def get_by_site(self, site_id):
        with get_db(self.db_path) as conn:
            return [dict(row) for row in conn.execute("""
                SELECT site_id, client_mac, ap_device_id, observed_at
                FROM ap_client_associations WHERE site_id=?
            """, (site_id,)).fetchall()]

    def get_recent_ap_ids(self, site_id):
        with get_db(self.db_path) as conn:
            return {row["ap_device_id"] for row in conn.execute("""
                SELECT DISTINCT ap_device_id FROM ap_client_associations
                WHERE site_id=? AND observed_at >= datetime('now', '-1 day')
            """, (site_id,)).fetchall()}
