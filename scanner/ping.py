import subprocess
import platform
import ipaddress
import re
from itertools import islice
from concurrent.futures import ThreadPoolExecutor
from scanner.arp import get_arp_table

class PingResult:
    """Rich ping outcome compatible with both boolean checks and attribute access."""
    def __init__(self, alive=False, latency_ms=0.0, ttl=0):
        self.alive = alive
        self.latency_ms = latency_ms
        self.ttl = ttl

    def __bool__(self):
        return bool(self.alive)

    def __iter__(self):
        return iter((self.alive, self.latency_ms, self.ttl))

class SweepResult(list):
    """List of active IP addresses with an attached details map (latency and TTL)."""
    def __init__(self, ips, details=None):
        super().__init__(ips)
        self.details = details or {}

def ping_host_icmp(ip_str, timeout_ms=150):
    """
    Sends an ICMP ping to a single IP.
    Verifies that the target host genuinely answered with a TTL response.
    Returns PingResult with .alive, .latency_ms, and .ttl.
    """
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        cmd = f"ping -n 1 -w {timeout_ms} {ip_str}"
    else:
        cmd = f"ping -c 1 -W 1 {ip_str}"

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = (res.stdout or "").lower()
        if "ttl=" in out and "inaccesible" not in out and "unreachable" not in out:
            # Extract latency
            lat = 1.0
            m_time = re.search(r"(?:tiempo|time)[=<]([\d\.]+)\s*ms", out)
            if m_time:
                try:
                    lat = float(m_time.group(1))
                except ValueError:
                    lat = 1.0
            elif "<1ms" in out or "< 1ms" in out:
                lat = 0.5

            # Extract TTL
            ttl = 64
            m_ttl = re.search(r"ttl=(\d+)", out)
            if m_ttl:
                try:
                    ttl = int(m_ttl.group(1))
                except ValueError:
                    ttl = 64

            return PingResult(alive=True, latency_ms=round(lat, 2), ttl=ttl)
    except Exception:
        pass
    return PingResult(alive=False, latency_ms=0.0, ttl=0)

def ping_sweep(cidr, max_workers=64, timeout_ms=150, progress_callback=None):
    """
    Sweeps the CIDR subnet:
    1. Sends ICMP echo requests to warm up the kernel ARP table and measure latency.
    2. Identifies hosts that returned a true ICMP TTL response.
    3. Reads the ARP table for hosts with valid MAC addresses.
    4. Returns a SweepResult containing confirmed IPs and their ping metrics.
    """
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        hosts = net.hosts()
    except Exception:
        return SweepResult([])

    icmp_alive = set()
    ping_details = {}
    total = max(net.num_addresses - (2 if net.prefixlen < 31 else 0), 0)
    completed = 0

    def check(ip):
        ip_str = str(ip)
        res = ping_host_icmp(ip_str, timeout_ms)
        if res.alive:
            return ip_str, res
        return ip_str, None

    # Step 1: Concurrent ping sweep
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while batch := list(islice(hosts, 256)):
            for ip_str, res in executor.map(check, batch):
                if res and res.alive:
                    icmp_alive.add(ip_str)
                    ping_details[ip_str] = {"latency_ms": res.latency_ms, "ttl": res.ttl}
                completed += 1
                if progress_callback and (completed % 25 == 0 or completed == total):
                    progress_callback(completed, total)

    # Step 2: Read ARP table (any device that responded to ARP has a real MAC)
    arp_table = get_arp_table()
    arp_alive = set()
    for ip, mac in arp_table.items():
        try:
            if ipaddress.IPv4Address(ip) in net:
                if mac and mac != "FF:FF:FF:FF:FF:FF" and not mac.startswith("01:00:5E"):
                    arp_alive.add(ip)
                    # If it wasn't in ICMP alive, give it a quick measurement or default
                    if ip not in ping_details:
                        ping_details[ip] = {"latency_ms": 1.5, "ttl": 64}
        except Exception:
            pass

    # Verified hosts are those with valid ARP MAC or verified ICMP reply
    confirmed = sorted(
        list(icmp_alive.union(arp_alive)),
        key=lambda x: [int(o) for o in x.split(".") if o.isdigit()]
    )
    return SweepResult(confirmed, details=ping_details)
