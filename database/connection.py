import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from config import Config

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

def get_connection(db_path=None):
    path = db_path or Config.DATABASE_PATH
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

@contextmanager
def get_db(db_path=None):
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db(db_path=None):
    """Initializes the database tables and inserts default seed sites if empty."""
    with get_db(db_path) as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        
        # Ensure new enterprise columns exist in devices table
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(devices)")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        new_columns = [
            ("latency_ms", "REAL DEFAULT 0.0"),
            ("uptime_seconds", "INTEGER"),
            ("os_info", "TEXT DEFAULT ''"),
            ("open_ports_list", "TEXT DEFAULT ''"),
            ("scan_evidence", "TEXT DEFAULT ''"),
            ("workgroup", "TEXT DEFAULT ''"),
            ("security_status", "TEXT DEFAULT 'SECURE'")
        ]
        for col_name, col_type in new_columns:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

        cursor.execute("PRAGMA table_info(interfaces)")
        interface_cols = {row["name"] for row in cursor.fetchall()}
        for name, column_type in (
            ("if_index", "INTEGER"),
            ("admin_status", "TEXT"),
            ("oper_status", "TEXT"),
            ("speed_bps", "INTEGER"),
            ("observed_at", "TIMESTAMP"),
        ):
            if name not in interface_cols:
                cursor.execute(f"ALTER TABLE interfaces ADD COLUMN {name} {column_type}")
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_interfaces_device_ifindex "
            "ON interfaces(device_id, if_index)"
        )

        cursor.execute("PRAGMA table_info(scan_jobs)")
        job_cols = {row["name"] for row in cursor.fetchall()}
        if "warnings" not in job_cols:
            cursor.execute("ALTER TABLE scan_jobs ADD COLUMN warnings TEXT")

        # Check if sites are seeded
        cursor.execute("SELECT COUNT(*) as count FROM sites")
        if cursor.fetchone()["count"] == 0:
            seed_sites = [("Sede local", "Inventario de esta instalación", "")]
            cursor.executemany(
                "INSERT INTO sites (name, description, address_reference) VALUES (?, ?, ?)",
                seed_sites
            )
