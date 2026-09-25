import re
import socket

# Comprehensive service catalog for enterprise mapping
SERVICE_CATALOG = {
    20: {"name": "FTP-Data", "service": "Transferencia de archivos FTP", "risk": "WARNING"},
    21: {"name": "FTP", "service": "Servidor FTP (sin cifrar)", "risk": "CRITICAL"},
    22: {"name": "SSH", "service": "Consola remota segura SSH", "risk": "SECURE"},
    23: {"name": "Telnet", "service": "Terminal Telnet inseguro", "risk": "CRITICAL"},
    25: {"name": "SMTP", "service": "Servidor de correo SMTP", "risk": "WARNING"},
    53: {"name": "DNS", "service": "Servidor de nombres DNS", "risk": "SECURE"},
    80: {"name": "HTTP", "service": "Servidor web (panel de administración)", "risk": "INFO"},
    110: {"name": "POP3", "service": "Recepción de correo POP3", "risk": "WARNING"},
    135: {"name": "MSRPC", "service": "Llamada a procedimiento Windows RPC", "risk": "INFO"},
    139: {"name": "NetBIOS", "service": "Servicio de red NetBIOS heredado", "risk": "WARNING"},
    143: {"name": "IMAP", "service": "Acceso a buzón IMAP", "risk": "INFO"},
    161: {"name": "SNMP", "service": "Agente de monitoreo de red SNMP", "risk": "SECURE"},
    443: {"name": "HTTPS", "service": "Servidor web seguro SSL/TLS", "risk": "SECURE"},
    445: {"name": "SMB", "service": "Carpetas compartidas de red SMB", "risk": "INFO"},
    554: {"name": "RTSP", "service": "Transmisión de video RTSP (Cámara IP)", "risk": "INFO"},
    631: {"name": "IPP", "service": "Protocolo de impresión IPP / CUPS", "risk": "INFO"},
    1433: {"name": "MSSQL", "service": "Base de datos Microsoft SQL", "risk": "INFO"},
    3000: {"name": "webOS Remote", "service": "Control remoto LG Smart TV", "risk": "INFO"},
    3306: {"name": "MySQL", "service": "Base de datos MySQL / MariaDB", "risk": "INFO"},
    3389: {"name": "RDP", "service": "Escritorio remoto de Windows (RDP)", "risk": "WARNING"},
    5000: {"name": "AirPlay Audio", "service": "Transmisión de audio Apple AirPlay", "risk": "INFO"},
    5353: {"name": "mDNS", "service": "Descubrimiento Bonjour / Zeroconf", "risk": "SECURE"},
    5432: {"name": "PostgreSQL", "service": "Base de datos PostgreSQL", "risk": "INFO"},
    7000: {"name": "AirPlay Video", "service": "Transmisión de pantalla Apple AirPlay", "risk": "INFO"},
    8001: {"name": "Samsung TV API", "service": "API de control Smart TV Samsung Tizen", "risk": "INFO"},
    8002: {"name": "Samsung WS", "service": "WebSocket de Smart TV Samsung", "risk": "INFO"},
    8008: {"name": "Google Cast", "service": "API de Google Cast / Android TV", "risk": "INFO"},
    8009: {"name": "Google Cast TLS", "service": "API segura de Google Cast", "risk": "INFO"},
    8060: {"name": "Roku ECP", "service": "Control externo de streaming Roku", "risk": "INFO"},
    8080: {"name": "HTTP-Proxy", "service": "Servidor web alternativo / Proxy", "risk": "INFO"},
    8443: {"name": "HTTPS-Alt", "service": "Administración web segura / UniFi", "risk": "SECURE"},
    9000: {"name": "Bravia API", "service": "API de control Sony Bravia / Philips", "risk": "INFO"},
    9100: {"name": "JetDirect RAW", "service": "Puerto de impresión directa HP / Epson", "risk": "INFO"},
}

def format_open_ports_summary(open_ports):
    """
    Returns a human-readable string and list of dictionaries of open ports.
    """
    import json
    items = []
    for p in sorted(open_ports or []):
        info = SERVICE_CATALOG.get(p, {"name": f"TCP {p}", "service": f"Servicio en puerto {p}", "risk": "INFO"})
        items.append({
            "port": p,
            "name": info["name"],
            "service": info["service"],
            "risk": info["risk"]
        })
    return json.dumps(items)

def evaluate_security_status(open_ports):
    """
    Evaluates enterprise security status based on open ports.
    Returns: 'CRITICAL', 'WARNING', or 'SECURE'
    """
    ports = set(open_ports or [])
    if any(p in ports for p in [23, 21]):
        return "CRITICAL"
    if any(p in ports for p in [3389, 139, 25]):
        return "WARNING"
    return "SECURE"

def detect_os_info(ttl=0, open_ports=None, vendor="", device_type="UNKNOWN", hostname=""):
    """
    Combines TTL signatures, open ports, device vendor, and hostnames to estimate the OS.
    """
    ports = set(open_ports or [])
    v_low = (vendor or "").lower()
    h_low = (hostname or "").lower()

    # 1. Smart TVs
    if device_type == "SMART_TV":
        if any(p in ports for p in [8001, 8002]) or "samsung" in v_low:
            return "Tizen OS (Samsung)"
        if 8060 in ports or "roku" in v_low:
            return "Roku OS"
        if 3000 in ports or "lg" in v_low:
            return "webOS (LG)"
        if any(p in ports for p in [8008, 8009]) or "google" in v_low or "chromecast" in v_low:
            return "Android TV / Google TV"
        if "gaoshengda" in v_low:
            return "Android TV / Smart TV OS"
        return "Smart TV OS"

    # 2. Smartphones
    if device_type == "PHONE":
        if "apple" in v_low or "iphone" in h_low or "ipad" in h_low:
            return "Apple iOS"
        return "Android OS"

    # 3. Windows PCs / Laptops / Servers
    if 445 in ports or 135 in ports or 3389 in ports or (100 <= ttl <= 135):
        if any(w in h_low for w in ["srv", "server", "dc0", "sql"]):
            return "Windows Server"
        return "Windows 11 / 10"

    # 4. Network Infrastructure (Routers / Switches)
    if device_type in ["ROUTER", "FIREWALL", "SWITCH", "ACCESS_POINT"]:
        if "fortinet" in v_low:
            return "FortiOS"
        if "mikrotik" in v_low:
            return "RouterOS"
        if "cisco" in v_low:
            return "Cisco IOS"
        if "ubiquiti" in v_low:
            return "UniFi OS"
        return "Embedded Linux (Firmware de Red)"

    # 5. Printers
    if device_type == "PRINTER":
        return f"Firmware de Impresora ({vendor or 'Genérico'})"

    # 6. Fallback based on TTL
    if ttl > 0:
        if 50 <= ttl <= 70:
            return "Linux / Android / Unix"
        elif 100 <= ttl <= 135:
            return "Windows"
        elif 240 <= ttl <= 255:
            return "Cisco IOS / Network OS"

    return "Sistema Operativo no determinado"

def query_netbios_details(ip, timeout_s=0.4):
    """
    Sends a NetBIOS Node Status request (UDP 137).
    Returns: (computer_name, workgroup)
    """
    query = (
        b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    computer_name = None
    workgroup = "WORKGROUP"
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) > 56:
            num_names = data[56]
            for i in range(min(num_names, 10)):
                offset = 57 + (i * 18)
                if offset + 17 <= len(data):
                    name = data[offset : offset + 15].decode("latin1", errors="ignore").strip()
                    flags = (data[offset + 16] << 8) | data[offset + 17]
                    is_group = bool(flags & 0x8000)
                    name_clean = re.sub(r"[^\w\-]", "", name)
                    if name_clean and not name_clean.startswith("IS~"):
                        if is_group and name_clean != "WORKGROUP":
                            workgroup = name_clean
                        elif not computer_name and not is_group:
                            computer_name = name_clean
    except Exception:
        pass
    finally:
        sock.close()
    return computer_name, workgroup
