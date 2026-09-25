"""Observed interface, VLAN, forwarding and neighbor details."""

from database.connection import get_db
from scanner.topology import resolve_neighbor


class NetworkDetailRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def save_inventory(self, site_id, device_id, inventory):
        with get_db(self.db_path) as conn:
            for port in inventory.get("interfaces", []):
                if_index = port.get("if_index")
                if if_index is None:
                    continue
                conn.execute("""
                    INSERT INTO interfaces (device_id, if_index, name, mac, speed, status,
                        description, admin_status, oper_status, speed_bps, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(device_id, if_index) DO UPDATE SET
                        name=excluded.name, mac=excluded.mac, speed=excluded.speed,
                        status=excluded.status, description=excluded.description,
                        admin_status=excluded.admin_status, oper_status=excluded.oper_status,
                        speed_bps=excluded.speed_bps, observed_at=CURRENT_TIMESTAMP
                """, (device_id, if_index, port.get("name") or str(if_index),
                      port.get("mac"), port.get("speed"), port.get("oper_status") or "UNKNOWN",
                      port.get("description"), port.get("admin_status"),
                      port.get("oper_status"), port.get("speed_bps")))

            for vlan in inventory.get("vlans", []):
                number = vlan.get("number")
                if number is None:
                    continue
                conn.execute("""
                    INSERT INTO vlans (site_id, vlan_id, name) VALUES (?, ?, ?)
                    ON CONFLICT(site_id, vlan_id) DO UPDATE SET name=excluded.name
                """, (site_id, number, vlan.get("name") or f"VLAN {number}"))

            for membership in inventory.get("interface_vlans", []):
                interface = conn.execute(
                    "SELECT id FROM interfaces WHERE device_id=? AND if_index=?",
                    (device_id, membership["if_index"]),
                ).fetchone()
                vlan = conn.execute(
                    "SELECT id FROM vlans WHERE site_id=? AND vlan_id=?",
                    (site_id, membership["vlan"]),
                ).fetchone()
                if interface and vlan:
                    conn.execute("""
                        INSERT INTO interface_vlans (interface_id, vlan_id, mode)
                        VALUES (?, ?, ?) ON CONFLICT(interface_id, vlan_id)
                        DO UPDATE SET mode=excluded.mode, observed_at=CURRENT_TIMESTAMP
                    """, (interface["id"], vlan["id"], membership.get("mode", "UNKNOWN")))

            for learned in inventory.get("mac_learnings", []):
                interface = conn.execute(
                    "SELECT id FROM interfaces WHERE device_id=? AND if_index=?",
                    (device_id, learned.get("if_index")),
                ).fetchone()
                conn.execute("""
                    INSERT INTO mac_learnings (device_id, interface_id, vlan_number, mac)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id, mac, vlan_number) DO UPDATE SET
                        interface_id=excluded.interface_id, observed_at=CURRENT_TIMESTAMP
                """, (device_id, interface["id"] if interface else None,
                      learned.get("vlan"), learned["mac"]))

    def save_neighbors(self, site_id, source, neighbors, devices):
        with get_db(self.db_path) as conn:
            conn.execute("DELETE FROM physical_links WHERE site_id=? AND source_device_id=?",
                         (site_id, source["id"]))
            conn.execute("DELETE FROM neighbor_observations WHERE site_id=? AND source_device_id=?",
                         (site_id, source["id"]))
            for neighbor in neighbors:
                target = resolve_neighbor(neighbor, devices)
                source_port = neighbor.get("source_port")
                target_port = neighbor.get("remote_port")
                if not target or target["id"] == source["id"]:
                    conn.execute("""
                        INSERT INTO neighbor_observations
                        (site_id, source_device_id, source_port, neighbor_name, neighbor_port, protocol)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (site_id, source["id"], source_port, neighbor.get("neighbor_name"),
                          target_port, neighbor.get("protocol", "LLDP")))
                    continue
                source_if = conn.execute(
                    "SELECT id FROM interfaces WHERE device_id=? AND name=?",
                    (source["id"], source_port),
                ).fetchone()
                target_if = conn.execute(
                    "SELECT id FROM interfaces WHERE device_id=? AND name=?",
                    (target["id"], target_port),
                ).fetchone()
                source_if_id = source_if["id"] if source_if else None
                target_if_id = target_if["id"] if target_if else None
                existing = conn.execute("""
                    SELECT id FROM physical_links WHERE site_id=? AND source_device_id=?
                        AND target_device_id=? AND source_interface_id IS ?
                        AND target_interface_id IS ?
                """, (site_id, source["id"], target["id"], source_if_id, target_if_id)).fetchone()
                if not existing:
                    existing = conn.execute("""
                        SELECT id FROM physical_links WHERE site_id=? AND source_device_id=?
                            AND target_device_id=? AND source_interface_id IS ?
                            AND target_interface_id IS ?
                    """, (site_id, target["id"], source["id"], target_if_id, source_if_id)).fetchone()
                if existing:
                    conn.execute("UPDATE physical_links SET observed_at=CURRENT_TIMESTAMP WHERE id=?",
                                 (existing["id"],))
                else:
                    conn.execute("""
                        INSERT INTO physical_links (site_id, source_device_id, source_interface_id,
                            target_device_id, target_interface_id, protocol, evidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (site_id, source["id"], source_if_id, target["id"], target_if_id,
                          neighbor.get("protocol", "LLDP"),
                          f"{source_port or '?'} → {target_port or '?'}"))

    def get_interfaces(self, device_id):
        with get_db(self.db_path) as conn:
            rows = conn.execute("""
                SELECT i.*, GROUP_CONCAT(v.vlan_id) AS vlans FROM interfaces i
                LEFT JOIN interface_vlans iv ON iv.interface_id=i.id
                LEFT JOIN vlans v ON v.id=iv.vlan_id
                WHERE i.device_id=? GROUP BY i.id ORDER BY i.if_index
            """, (device_id,)).fetchall()
            return [dict(row) for row in rows]

    def get_vlans(self, site_id):
        with get_db(self.db_path) as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM vlans WHERE site_id=? ORDER BY vlan_id", (site_id,)).fetchall()]

    def get_links(self, site_id):
        with get_db(self.db_path) as conn:
            return [dict(row) for row in conn.execute("""
                SELECT l.*, si.name AS source_port, ti.name AS target_port
                FROM physical_links l
                LEFT JOIN interfaces si ON si.id=l.source_interface_id
                LEFT JOIN interfaces ti ON ti.id=l.target_interface_id
                WHERE l.site_id=? ORDER BY l.id
            """, (site_id,)).fetchall()]

    def get_unresolved(self, site_id):
        with get_db(self.db_path) as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM neighbor_observations WHERE site_id=? ORDER BY id", (site_id,)
            ).fetchall()]

    def get_device_vlans(self, site_id):
        with get_db(self.db_path) as conn:
            rows = conn.execute("""
                SELECT i.device_id, v.vlan_id FROM interfaces i
                JOIN interface_vlans iv ON iv.interface_id=i.id
                JOIN vlans v ON v.id=iv.vlan_id
                WHERE v.site_id=? GROUP BY i.device_id, v.vlan_id
            """, (site_id,)).fetchall()
            result = {}
            for row in rows:
                result.setdefault(row["device_id"], set()).add(row["vlan_id"])
            return result

    def get_mac_learnings(self, device_id):
        with get_db(self.db_path) as conn:
            return [dict(row) for row in conn.execute("""
                SELECT m.*, i.name AS port_name FROM mac_learnings m
                LEFT JOIN interfaces i ON i.id=m.interface_id
                WHERE m.device_id=? ORDER BY m.vlan_number, m.mac
            """, (device_id,)).fetchall()]

    def find_devices_by_port(self, site_id, term):
        with get_db(self.db_path) as conn:
            rows = conn.execute("""
                SELECT DISTINCT i.device_id FROM interfaces i
                JOIN devices d ON d.id=i.device_id
                WHERE d.site_id=? AND (i.name LIKE ? OR i.description LIKE ?)
            """, (site_id, f"%{term}%", f"%{term}%")).fetchall()
            return {row["device_id"] for row in rows}
