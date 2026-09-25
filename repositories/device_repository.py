from database.connection import get_db

class DeviceRepository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def get_all(self, site_id=None, device_type=None, search=None, status=None):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            query = """
                SELECT d.*, s.name as site_name, n.cidr as network_cidr
                FROM devices d
                LEFT JOIN sites s ON d.site_id = s.id
                LEFT JOIN networks n ON d.network_id = n.id
                WHERE 1=1
            """
            params = []
            if site_id:
                query += " AND d.site_id = ?"
                params.append(site_id)
            if device_type:
                query += " AND d.device_type = ?"
                params.append(device_type)
            if status:
                query += " AND d.status = ?"
                params.append(status)
            if search:
                query += """ AND (d.ip LIKE ? OR d.mac LIKE ? OR d.hostname LIKE ?
                    OR d.vendor LIKE ? OR d.model LIKE ? OR d.location LIKE ?
                    OR EXISTS (SELECT 1 FROM interfaces i WHERE i.device_id=d.id AND i.name LIKE ?))"""
                term = f"%{search}%"
                params.extend([term] * 7)
            
            # Sort by IP address
            query += " ORDER BY d.device_type, d.ip ASC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_by_id(self, device_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, s.name as site_name, n.cidr as network_cidr, n.gateway as network_gateway
                FROM devices d
                LEFT JOIN sites s ON d.site_id = s.id
                LEFT JOIN networks n ON d.network_id = n.id
                WHERE d.id = ?
            """, (device_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_ip(self, site_id, ip):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE site_id = ? AND ip = ?", (site_id, ip))
            row = cursor.fetchone()
            return dict(row) if row else None

    def upsert_discovered(self, site_id, data):
        """
        Inserts or updates a discovered device.
        Preserves manual annotations (location, rack, floor, is_manual, custom device_type).
        """
        ip = data.get("ip")
        if not ip:
            return None

        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE site_id = ? AND ip = ?", (site_id, ip))
            existing = cursor.fetchone()

            if existing:
                device_id = existing["id"]
                is_manual = existing["is_manual"]

                if is_manual:
                    # Preserve manual fields, only update network presence indicators and dynamic metrics
                    cursor.execute("""
                        UPDATE devices
                        SET mac = COALESCE(?, mac),
                            hostname = CASE WHEN hostname IS NULL OR hostname = '' THEN ? ELSE hostname END,
                            vendor = CASE WHEN vendor IS NULL OR vendor = '' THEN ? ELSE vendor END,
                            latency_ms = COALESCE(?, latency_ms),
                            os_info = CASE WHEN os_info IS NULL OR os_info = '' THEN ? ELSE os_info END,
                            open_ports_list = COALESCE(?, open_ports_list),
                            workgroup = CASE WHEN workgroup IS NULL OR workgroup = '' THEN ? ELSE workgroup END,
                            security_status = COALESCE(?, security_status),
                            status = 'ONLINE',
                            last_seen = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (
                        data.get("mac") or existing["mac"],
                        data.get("hostname") or existing["hostname"],
                        data.get("vendor") or existing["vendor"],
                        data.get("latency_ms"),
                        data.get("os_info"),
                        data.get("open_ports_list"),
                        data.get("workgroup"),
                        data.get("security_status"),
                        device_id
                    ))
                else:
                    # Automatic update of all discovered fields
                    cursor.execute("""
                        UPDATE devices
                        SET network_id = COALESCE(?, network_id),
                            mac = COALESCE(?, mac),
                            hostname = COALESCE(?, hostname),
                            vendor = COALESCE(?, vendor),
                            model = COALESCE(?, model),
                            serial_number = COALESCE(?, serial_number),
                            device_type = COALESCE(?, device_type),
                            latency_ms = COALESCE(?, latency_ms),
                            os_info = COALESCE(?, os_info),
                            open_ports_list = COALESCE(?, open_ports_list),
                            workgroup = COALESCE(?, workgroup),
                            security_status = COALESCE(?, security_status),
                            status = 'ONLINE',
                            last_seen = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (
                        data.get("network_id") or existing["network_id"],
                        data.get("mac") or existing["mac"],
                        data.get("hostname") or existing["hostname"],
                        data.get("vendor") or existing["vendor"],
                        data.get("model") or existing["model"],
                        data.get("serial_number") or existing["serial_number"],
                        data.get("device_type") or existing["device_type"],
                        data.get("latency_ms"),
                        data.get("os_info"),
                        data.get("open_ports_list"),
                        data.get("workgroup"),
                        data.get("security_status"),
                        device_id
                    ))
                cursor.execute(
                    "UPDATE devices SET uptime_seconds=COALESCE(?, uptime_seconds) WHERE id=?",
                    (data.get("uptime_seconds"), device_id),
                )
                return device_id
            else:
                cursor.execute("""
                    INSERT INTO devices (
                        site_id, network_id, ip, mac, hostname, vendor, model, 
                        serial_number, device_type, latency_ms, os_info, open_ports_list,
                        workgroup, security_status, location, rack, floor, status, 
                        description, is_manual, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, 0, CURRENT_TIMESTAMP)
                """, (
                    site_id,
                    data.get("network_id"),
                    ip,
                    data.get("mac", ""),
                    data.get("hostname", ""),
                    data.get("vendor", ""),
                    data.get("model", ""),
                    data.get("serial_number", ""),
                    data.get("device_type", "UNKNOWN"),
                    data.get("latency_ms", 0.0),
                    data.get("os_info", ""),
                    data.get("open_ports_list", ""),
                    data.get("workgroup", ""),
                    data.get("security_status", "SECURE"),
                    data.get("location", ""),
                    data.get("rack", ""),
                    data.get("floor", ""),
                    data.get("description", "")
                ))
                device_id = cursor.lastrowid
                cursor.execute("UPDATE devices SET uptime_seconds=? WHERE id=?",
                               (data.get("uptime_seconds"), device_id))
                return device_id

    def update_manual_fields(self, device_id, fields):
        """Allows administrator to manually set rack, floor, location, notes, and override device_type."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET hostname = COALESCE(?, hostname),
                    device_type = COALESCE(?, device_type),
                    vendor = COALESCE(?, vendor),
                    model = COALESCE(?, model),
                    serial_number = COALESCE(?, serial_number),
                    location = COALESCE(?, location),
                    rack = COALESCE(?, rack),
                    floor = COALESCE(?, floor),
                    description = COALESCE(?, description),
                    is_manual = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                fields.get("hostname"),
                fields.get("device_type"),
                fields.get("vendor"),
                fields.get("model"),
                fields.get("serial_number"),
                fields.get("location"),
                fields.get("rack"),
                fields.get("floor"),
                fields.get("description"),
                device_id
            ))
            return cursor.rowcount > 0

    def clear_all_for_site(self, site_id):
        """Completely resets devices and connections for a site."""
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE site_id = ?", (site_id,))
            cursor.execute("DELETE FROM connections WHERE site_id = ?", (site_id,))
            return True

    def delete(self, device_id):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            return cursor.rowcount > 0

    def mark_offline_or_cleanup(self, site_id, active_ips, cidr=None):
        """Keep prior inventory; mark only scanned, absent addresses offline."""
        import ipaddress

        network = ipaddress.IPv4Network(cidr, strict=False) if cidr else None
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT id, ip FROM devices WHERE site_id = ?", (site_id,)).fetchall()
            missing = []
            for row in rows:
                try:
                    in_scope = network is None or ipaddress.IPv4Address(row["ip"]) in network
                except ValueError:
                    in_scope = False
                if in_scope and row["ip"] not in active_ips:
                    missing.append((row["id"],))
            cursor.executemany(
                "UPDATE devices SET status = 'OFFLINE', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                missing,
            )

    def count_by_type(self, site_id=None):
        with get_db(self.db_path) as conn:
            cursor = conn.cursor()
            query = "SELECT device_type, COUNT(*) as count FROM devices"
            params = []
            if site_id:
                query += " WHERE site_id = ?"
                params.append(site_id)
            query += " GROUP BY device_type"
            cursor.execute(query, params)
            counts = {row["device_type"]: row["count"] for row in cursor.fetchall()}
            total = sum(counts.values())
            counts["TOTAL"] = total
            return counts
