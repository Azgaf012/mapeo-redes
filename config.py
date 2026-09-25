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
