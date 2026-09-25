import re


AP_MODEL = re.compile(r"\b(?:uap|eap|iap|air-cap|air-ap|ap)(?:[-_][a-z0-9]+|[0-9]+)", re.I)


def is_access_point_identity(hostname="", snmp_info=None):
    """Identify an AP from its own name or model, not a shared vendor or port."""
    info = snmp_info if isinstance(snmp_info, dict) else {}
    description = " ".join(str(info.get(key) or "") for key in ("sys_descr", "model"))
    names = (hostname or "", info.get("sys_name") or "")
    description_lower = description.lower()
    if "switch" in description_lower or "controller" in description_lower:
        return False
    if "access point" in description_lower or "access-point" in description_lower:
        return True
    if AP_MODEL.search(description):
        return True
    return any(re.match(r"^(?:ap|wap|uap|eap|iap)[-_0-9]", name, re.I)
               for name in names)


def classify_device(ip, mac="", hostname="", vendor="", open_ports=None, is_gateway=False, snmp_info=None):
    """
    Applies heuristic scoring rules to classify an endpoint into one of:
    ROUTER, FIREWALL, SWITCH, ACCESS_POINT, SERVER, PC, LAPTOP,
    PRINTER, CAMERA, NVR, UPS, PHONE, CONTROLLER, UNKNOWN.
    """
    ports = set(open_ports or [])
    h_lower = (hostname or "").lower()
    v_lower = (vendor or "").lower()
    snmp_descr = ""
    if snmp_info and isinstance(snmp_info, dict):
        snmp_descr = (snmp_info.get("sys_descr") or "").lower()

    # Rule 1: Gateway detection
    if is_gateway:
        if any(f in v_lower for f in ["fortinet", "palo alto", "sonicwall", "sophos", "checkpoint"]) or "firewall" in h_lower:
            return "FIREWALL"
        return "ROUTER"

    if is_access_point_identity(hostname, snmp_info):
        return "ACCESS_POINT"

    # Rule 2: SNMP System Description inspection
    if snmp_descr:
        if any(w in snmp_descr for w in ["fortigate", "firewall", "utm"]):
            return "FIREWALL"
        if any(w in snmp_descr for w in ["catalyst", "cbs", "procurve", "switch", "edgeswitch", "sw-"]):
            return "SWITCH"
        if any(w in snmp_descr for w in ["unifi", "access point", "wap", "airmax", "ap-"]):
            return "ACCESS_POINT"
        if any(w in snmp_descr for w in ["laserjet", "pagecenter", "printer", "epson", "brother"]):
            return "PRINTER"
        if "routeros" in snmp_descr or "router" in snmp_descr:
            return "ROUTER"

    # Rule 3: Hostname patterns
    if any(h_lower.startswith(prefix) for prefix in ["sw-", "sw_", "switch"]):
        return "SWITCH"
    if any(h_lower.startswith(prefix) for prefix in ["ap-", "ap_", "unifi", "wifi"]):
        return "ACCESS_POINT"
    if any(h_lower.startswith(prefix) for prefix in ["rt-", "rt_", "router", "gw-"]):
        return "ROUTER"
    if any(h_lower.startswith(prefix) for prefix in ["fw-", "fw_", "firewall", "fortigate"]):
        return "FIREWALL"
    if any(h_lower.startswith(prefix) for prefix in ["cam-", "cam_", "cctv"]):
        return "CAMERA"
    if any(h_lower.startswith(prefix) for prefix in ["prn-", "print-", "impresora"]):
        return "PRINTER"
    if any(h_lower.startswith(prefix) for prefix in ["srv-", "server", "dc0", "sql", "pve", "proxmox"]):
        return "SERVER"

    # Rule 4: Port-based heuristics
    if any(p in ports for p in [8001, 8002, 8060, 3000, 8008, 7000]):
        return "SMART_TV"

    if 554 in ports:  # RTSP video stream
        if 80 in ports and any(cam in v_lower for cam in ["hikvision", "dahua"]):
            return "NVR" if "nvr" in h_lower else "CAMERA"
        return "CAMERA"

    if any(p in ports for p in [9100, 515, 631]):  # JetDirect, LPD, CUPS/IPP
        return "PRINTER"

    if (8080 in ports or 8443 in ports) and ("ubiquiti" in v_lower or "unifi" in h_lower):
        return "CONTROLLER"

    if 161 in ports:  # SNMP Agent open
        if any(net in v_lower for net in ["cisco", "aruba", "huawei", "hpe"]):
            return "SWITCH"
        if "mikrotik" in v_lower:
            return "ROUTER"

    # Rule 5: Vendor-based heuristics
    if any(tv in v_lower for tv in ["roku", "gaoshengda", "hisense", "tcl", "skyworth", "vizio", "smart tv"]):
        return "SMART_TV"
    if "móvil" in v_lower or "movil" in v_lower or "privad" in v_lower:
        return "PHONE"
    if any(mfg in v_lower for mfg in ["xiaomi", "oppo", "vivo", "realme", "motorola"]):
        return "PHONE"
    if "fortinet" in v_lower:
        return "FIREWALL"
    if any(cam in v_lower for cam in ["hikvision", "dahua"]):
        return "CAMERA"
    if any(prn in v_lower for prn in ["epson", "brother", "kyocera", "canon", "xerox"]):
        return "PRINTER"
    if "ubiquiti" in v_lower:
        return "ACCESS_POINT"

    # Rule 6: Workstation / Server heuristics
    if 3389 in ports:  # RDP
        if any(srv in h_lower for srv in ["srv", "server", "dc", "sql", "ad"]):
            return "SERVER"
        return "PC"

    if 445 in ports or 139 in ports:  # SMB
        return "PC"

    if any(pc_vend in v_lower for pc_vend in ["dell", "hp", "lenovo", "intel", "apple", "realtek"]):
        return "PC"

    return "UNKNOWN"
