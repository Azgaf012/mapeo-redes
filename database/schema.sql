-- Esquema de base de datos para Mapeo de Red Escolar

CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    address_reference TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL,
    gateway TEXT,
    vlan_id INTEGER,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    network_id INTEGER,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    model TEXT,
    serial_number TEXT,
    device_type TEXT NOT NULL DEFAULT 'UNKNOWN',
    location TEXT,
    rack TEXT,
    floor TEXT,
    status TEXT DEFAULT 'ONLINE',
    latency_ms REAL DEFAULT 0.0,
    uptime_seconds INTEGER,
    os_info TEXT DEFAULT '',
    open_ports_list TEXT DEFAULT '',
    scan_evidence TEXT DEFAULT '',
    workgroup TEXT DEFAULT '',
    security_status TEXT DEFAULT 'SECURE', -- 'SECURE', 'WARNING', 'CRITICAL'
    description TEXT,
    is_manual INTEGER DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE SET NULL,
    UNIQUE(site_id, ip)
);

CREATE TABLE IF NOT EXISTS interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    mac TEXT,
    ip TEXT,
    speed TEXT,
    status TEXT DEFAULT 'UP',
    description TEXT,
    vlan_id INTEGER,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    source_device_id INTEGER NOT NULL,
    source_interface_id INTEGER,
    target_device_id INTEGER NOT NULL,
    target_interface_id INTEGER,
    connection_type TEXT DEFAULT 'ETHERNET',
    discovery_method TEXT NOT NULL, -- 'MANUAL', 'LLDP', 'CDP', 'MAC_TABLE', 'GATEWAY_HEURISTIC'
    confidence TEXT DEFAULT 'HIGH', -- 'HIGH', 'MEDIUM', 'LOW'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    FOREIGN KEY (source_device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (target_device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE(source_device_id, target_device_id)
);

CREATE TABLE IF NOT EXISTS vlans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    vlan_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    subnet TEXT,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    UNIQUE(site_id, vlan_id)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    target_cidr TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'RUNNING', 'COMPLETED', 'FAILED'
    progress INTEGER DEFAULT 0,
    current_step TEXT,
    discovered_count INTEGER DEFAULT 0,
    error_message TEXT,
    warnings TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS interface_vlans (
    interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    vlan_id INTEGER NOT NULL REFERENCES vlans(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'UNKNOWN',
    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (interface_id, vlan_id)
);

CREATE TABLE IF NOT EXISTS mac_learnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    vlan_number INTEGER,
    mac TEXT NOT NULL,
    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(device_id, mac, vlan_number)
);

CREATE TABLE IF NOT EXISTS physical_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    source_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source_interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    target_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    protocol TEXT NOT NULL,
    evidence TEXT,
    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(site_id, source_device_id, source_interface_id, target_device_id, target_interface_id)
);

CREATE TABLE IF NOT EXISTS neighbor_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    source_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source_port TEXT,
    neighbor_name TEXT,
    neighbor_port TEXT,
    protocol TEXT,
    observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indices para acelerar consultas frecuentes
CREATE INDEX IF NOT EXISTS idx_devices_site_id ON devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_connections_site_id ON connections(site_id);
CREATE INDEX IF NOT EXISTS idx_connections_source ON connections(source_device_id);
CREATE INDEX IF NOT EXISTS idx_connections_target ON connections(target_device_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_site_id ON scan_jobs(site_id);
