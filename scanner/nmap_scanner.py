import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

COMMON_INFRA_PORTS = [22, 23, 53, 80, 135, 139, 161, 443, 445, 554, 3000, 3389, 8001, 8008, 8060, 8080, 8443, 9100]

def is_nmap_available():
    return shutil.which("nmap") is not None

def quick_socket_port_scan(ip, ports=None, timeout_s=0.3):
    """Fallback port scanner using native Python sockets when Nmap is not installed."""
    ports_to_check = ports or COMMON_INFRA_PORTS
    open_ports = []

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_s)
            res = s.connect_ex((ip, port))
            s.close()
            if res == 0:
                return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(len(ports_to_check), 16)) as executor:
        results = executor.map(check_port, ports_to_check)
        for r in results:
            if r is not None:
                open_ports.append(r)

    return sorted(open_ports)

def scan_host_services(ip, ports=None):
    """
    Scans a single host for open ports.
    Uses nmap if available, otherwise falls back to pure python socket scan.
    """
    if is_nmap_available():
        try:
            import nmap
            nm = nmap.PortScanner()
            port_str = ",".join(str(p) for p in (ports or COMMON_INFRA_PORTS))
            nm.scan(ip, port_str, arguments="-sT -T4 -Pn --host-timeout 10s")
            if ip in nm.all_hosts():
                open_ports = []
                for proto in nm[ip].all_protocols():
                    lport = nm[ip][proto].keys()
                    for p in lport:
                        if nm[ip][proto][p]["state"] == "open":
                            open_ports.append(p)
                return open_ports
        except Exception:
            pass

    # Native Python fallback
    return quick_socket_port_scan(ip, ports)
