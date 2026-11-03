"""Optional read-only sources for network diagnostics."""

import ipaddress
import json
import os
import shutil
import subprocess


def read_dhcp_leases(scope):
    server = os.environ.get("SCAN_DHCP_SERVER", "").strip()
    powershell = shutil.which("powershell")
    if not server or not powershell:
        return {}
    scope = str(ipaddress.IPv4Address(scope))
    command = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
        "Get-DhcpServerv4Lease -ComputerName $env:SCAN_DHCP_SERVER "
        "-ScopeId $env:NETMAP_DHCP_SCOPE -ErrorAction Stop | "
        "Select-Object @{n='IP';e={$_.IPAddress.ToString()}},HostName,ClientId | "
        "ConvertTo-Json -Compress"
    )
    output = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "NETMAP_DHCP_SCOPE": scope}, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=20, check=True,
    ).stdout
    rows = json.loads(output or "[]")
    if isinstance(rows, dict):
        rows = [rows]
    return {row["IP"]: {"hostname": row.get("HostName"), "client_id": row.get("ClientId")}
            for row in rows}


def trace_route(ip):
    address = str(ipaddress.IPv4Address(ip))
    executable = shutil.which("tracert")
    if not executable:
        raise RuntimeError("tracert solo está disponible en Windows.")
    result = subprocess.run(
        [executable, "-d", "-h", "8", "-w", "500", address],
        capture_output=True, text=True, encoding="oem", errors="replace", timeout=18,
    )
    return result.stdout.strip() or result.stderr.strip()
