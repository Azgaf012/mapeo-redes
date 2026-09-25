import socket
import subprocess
import platform
import ipaddress
import json
from functools import lru_cache
import psutil
from scanner.arp import normalize_mac

def get_routing_ip():
    """Finds the primary local IPv4 address used to route traffic outside."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@lru_cache(maxsize=16)
def _windows_adapter_medium(interface_name):
    """Read the physical medium of one local Windows adapter."""
    command = (
        "$ErrorActionPreference='Stop'; "
        "Get-NetAdapter | Select-Object Name, NdisPhysicalMedium "
        "| ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode:
            return None
        adapters = json.loads(result.stdout)
        if isinstance(adapters, dict):
            adapters = [adapters]
        adapter = next((item for item in adapters
                        if item.get("Name", "").casefold() == interface_name.casefold()), None)
        if adapter:
            medium = int(adapter.get("NdisPhysicalMedium", 0))
            if medium in (1, 9):
                return "WIFI"
            if medium == 14:
                return "WIRED"
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        pass
    return None


def get_local_connection_medium(local_ip):
    """Identify the medium of the adapter carrying this machine's IPv4 address."""
    try:
        interfaces = psutil.net_if_addrs()
    except OSError:
        return "UNKNOWN", "No se pudieron leer las interfaces locales"
    for interface_name, addresses in interfaces.items():
        if not any(addr.family == socket.AF_INET and addr.address == local_ip
                   for addr in addresses):
            continue
        if platform.system().lower() == "windows":
            medium = _windows_adapter_medium(interface_name)
            if medium:
                return medium, f"Adaptador local {interface_name}: medio físico informado por Windows"
        normalized = interface_name.casefold()
        if normalized.startswith(("wi-fi", "wlan")) or normalized == "wifi":
            return "WIFI", f"Adaptador local {interface_name}: identificado por nombre"
        return "UNKNOWN", f"Adaptador local {interface_name}: medio no identificado"
    return "UNKNOWN", "No se encontró la interfaz local para esta IP"

def get_windows_default_gateway():
    """Extracts the default gateway and interface alias on Windows."""
    try:
        cmd = 'powershell -NoProfile -Command "Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' | Select-Object -First 1 NextHop, InterfaceAlias | ConvertTo-Json"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout)
            gateway = data.get("NextHop")
            iface = data.get("InterfaceAlias")
            return gateway, iface
    except Exception:
        pass

    # Fallback to route print
    try:
        out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, timeout=4)
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2], None
    except Exception:
        pass

    return None, None

def detect_network_config():
    """
    Detects active network interface, local IP, local MAC, netmask, gateway, and calculates CIDR.
    """
    local_ip = get_routing_ip()
    local_mac = ""
    gateway = None
    interface_name = "Ethernet / Wi-Fi"
    netmask = "255.255.255.0"
    cidr = "192.168.1.0/24"

    is_windows = platform.system().lower() == "windows"
    if is_windows:
        win_gw, win_iface = get_windows_default_gateway()
        if win_gw:
            gateway = win_gw
        if win_iface:
            interface_name = win_iface

    # Match interface with local_ip using psutil to find exact netmask and local MAC
    try:
        interfaces = psutil.net_if_addrs()
        for if_name, addrs in interfaces.items():
            has_ip = False
            mac_found = ""
            for addr in addrs:
                if addr.family == psutil.AF_LINK and addr.address:
                    mac_found = normalize_mac(addr.address)
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    has_ip = True
                    if addr.netmask:
                        netmask = addr.netmask
            if has_ip:
                if not is_windows or not interface_name or interface_name in ("Ethernet / Wi-Fi", ""):
                    interface_name = if_name
                if mac_found:
                    local_mac = mac_found
                break
    except Exception:
        pass

    # Calculate CIDR
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        cidr = str(network)
    except Exception:
        octets = local_ip.split(".")
        if len(octets) == 4:
            cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        else:
            cidr = "192.168.1.0/24"

    # Default gateway heuristic if still None
    if not gateway:
        octets = local_ip.split(".")
        if len(octets) == 4:
            gateway = f"{octets[0]}.{octets[1]}.{octets[2]}.1"

    # Get hostname
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "localhost"

    return {
        "local_ip": local_ip,
        "local_mac": local_mac,
        "netmask": netmask,
        "gateway": gateway,
        "cidr": cidr,
        "interface": interface_name,
        "hostname": hostname,
        "os": f"{platform.system()} {platform.release()}"
    }
