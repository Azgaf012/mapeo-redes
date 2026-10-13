import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-network-mapper-secret-key-2026")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "network.db"))
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    DEFAULT_PORT = int(os.environ.get("PORT", 5000))
    
    # Scanner settings
    DEFAULT_PING_TIMEOUT_MS = 250
    DEFAULT_PING_WORKERS = 64
    DEFAULT_SNMP_COMMUNITY = "public"
    DEFAULT_SNMP_PORT = 161
    DEFAULT_SNMP_TIMEOUT = 1.0
    MAX_SCAN_HOSTS = int(os.environ.get("MAX_SCAN_HOSTS", "16384"))
    SCAN_HOST_WORKERS = int(os.environ.get("SCAN_HOST_WORKERS", "12"))

    # Device identification: drivers, plugins, overrides and the "unidentified" log.
    # IDENTITY_DATA_DIR defaults to the folder that holds the SQLite database.
    IDENTITY_ENABLED = os.environ.get("IDENTITY_ENABLED", "true").lower() in ("true", "1", "yes")
    IDENTITY_DATA_DIR = os.environ.get("IDENTITY_DATA_DIR", "")
    PLUGIN_DIR = os.environ.get("PLUGIN_DIR", str(BASE_DIR / "plugins"))
    IDENTITY_BROADCAST = os.environ.get("IDENTITY_BROADCAST", "true").lower() in ("true", "1", "yes")
    IDENTITY_MDNS = os.environ.get("IDENTITY_MDNS", "true").lower() in ("true", "1", "yes")
    IDENTITY_SWEEP_SECONDS = float(os.environ.get("IDENTITY_SWEEP_SECONDS", "3"))
