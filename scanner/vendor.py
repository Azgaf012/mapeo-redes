import re

# Curated OUI dictionary for network infrastructure, servers, cameras, and printers
CURATED_OUI = {
    # Ubiquiti
    "00:15:6D": "Ubiquiti Networks", "00:27:22": "Ubiquiti Networks", "04:18:D6": "Ubiquiti Networks",
    "18:E8:29": "Ubiquiti Networks", "24:A4:3C": "Ubiquiti Networks", "44:D9:E7": "Ubiquiti Networks",
    "60:E3:27": "Ubiquiti Networks", "68:72:51": "Ubiquiti Networks", "70:8B:CD": "Ubiquiti Networks",
    "74:83:C2": "Ubiquiti Networks", "78:8A:20": "Ubiquiti Networks", "80:2A:A8": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks", "DC:9F:DB": "Ubiquiti Networks", "E0:63:DA": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks", "FC:EC:DA": "Ubiquiti Networks",

    # Fortinet
    "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet", "70:4C:A5": "Fortinet",
    "90:6C:AC": "Fortinet", "00:65:42": "Fortinet", "04:D5:90": "Fortinet", "84:B8:02": "Fortinet",

    # MikroTik
    "00:0C:42": "MikroTik", "48:8F:5A": "MikroTik", "64:D1:54": "MikroTik",
    "6C:3B:6B": "MikroTik", "74:4D:28": "MikroTik", "CC:2D:E0": "MikroTik",
    "D4:CA:6D": "MikroTik", "E4:8D:8C": "MikroTik",

    # TP-Link
    "00:1D:0F": "TP-Link", "00:23:CD": "TP-Link", "00:25:86": "TP-Link", "00:27:19": "TP-Link",
    "14:CF:92": "TP-Link", "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "60:E3:2B": "TP-Link",
    "70:4F:57": "TP-Link", "74:05:A5": "TP-Link", "84:16:F9": "TP-Link", "98:48:27": "TP-Link",
    "A0:F3:C1": "TP-Link", "C0:06:C3": "TP-Link", "C4:6E:1F": "TP-Link", "D8:07:B6": "TP-Link",
    "EC:08:6B": "TP-Link", "EC:55:1C": "TP-Link",

    # Cisco Systems
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:96": "Cisco", "00:02:16": "Cisco",
    "00:04:4D": "Cisco", "00:07:0E": "Cisco", "00:0A:41": "Cisco", "00:0C:CE": "Cisco",
    "00:11:20": "Cisco", "00:14:1B": "Cisco", "00:17:0E": "Cisco", "00:1A:A1": "Cisco",
    "00:1C:57": "Cisco", "00:21:55": "Cisco", "00:24:14": "Cisco", "00:26:0B": "Cisco",
    "00:40:96": "Cisco", "00:50:0F": "Cisco", "00:60:2F": "Cisco", "00:D0:58": "Cisco",
    "04:4F:AA": "Cisco", "04:62:73": "Cisco", "08:D0:9F": "Cisco", "18:33:9D": "Cisco",
    "28:94:0F": "Cisco", "38:ED:18": "Cisco", "44:AD:D9": "Cisco", "50:06:04": "Cisco",
    "60:73:5C": "Cisco", "70:69:79": "Cisco", "80:E0:1D": "Cisco", "90:E7:C4": "Cisco",
    "A0:EC:F9": "Cisco", "B0:AA:77": "Cisco", "C0:62:6B": "Cisco", "D0:C7:89": "Cisco",
    "E0:5F:B9": "Cisco", "F0:29:29": "Cisco", "FC:5B:39": "Cisco",

    # Aruba / HPE
    "00:0B:86": "Aruba / HPE", "00:1A:1E": "Aruba / HPE", "00:24:6C": "Aruba / HPE",
    "18:64:72": "Aruba / HPE", "20:4C:03": "Aruba / HPE", "24:BE:05": "Aruba / HPE",
    "6C:F3:7F": "Aruba / HPE", "70:10:5C": "Aruba / HPE", "88:E0:F3": "Aruba / HPE",

    # Huawei
    "00:1E:10": "Huawei", "00:25:9E": "Huawei", "08:19:A6": "Huawei", "28:6E:D4": "Huawei",
    "48:46:FB": "Huawei", "70:7B:E8": "Huawei", "80:B6:86": "Huawei", "D4:6E:5C": "Huawei",

    # Cameras / CCTV
    "00:18:AE": "Hikvision", "10:BF:48": "Hikvision", "44:19:B6": "Hikvision",
    "4C:BD:8F": "Hikvision", "54:C4:15": "Hikvision", "C0:56:E3": "Hikvision",
    "00:12:12": "Dahua", "38:AF:29": "Dahua", "44:11:C2": "Dahua", "4C:11:BF": "Dahua",
    "90:02:A9": "Dahua", "BC:32:5F": "Dahua", "E0:50:8B": "Dahua",

    # Printers
    "00:00:48": "Epson", "00:21:64": "Epson", "00:26:AB": "Epson", "44:D2:44": "Epson",
    "00:80:77": "Brother", "00:1B:A9": "Brother", "30:05:5C": "Brother", "40:B0:34": "Brother",
    "00:00:AA": "Xerox", "00:17:C8": "Kyocera", "00:25:36": "Canon",

    # Computers / Servers / NICs
    "14:85:7F": "Intel", "00:1B:21": "Intel", "00:1E:67": "Intel", "3C:97:0E": "Intel", "80:86:F2": "Intel",
    "00:14:22": "Dell", "18:03:73": "Dell", "24:B6:FD": "Dell", "34:17:EB": "Dell",
    "00:17:F2": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple", "60:03:08": "Apple",
    "AC:BC:32": "Apple", "F0:18:98": "Apple", "70:CD:60": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "24:0A:C4": "Espressif IoT", "30:AE:A4": "Espressif IoT", "DC:4F:22": "Espressif IoT"
}

def is_locally_administered_mac(clean_mac):
    """Checks if bit 1 of the first octet is set (Locally Administered / Randomized MAC)."""
    if len(clean_mac) >= 2:
        try:
            first_byte = int(clean_mac[:2], 16)
            return (first_byte & 0x02) != 0
        except ValueError:
            pass
    return False

def lookup_vendor(mac_address):
    """
    Identifies the hardware vendor based on the MAC OUI prefix.
    Recognizes private/randomized MACs used by mobile devices and laptops.
    """
    if not mac_address:
        return "Desconocido"

    clean_mac = re.sub(r"[^0-9a-fA-F]", "", mac_address).upper()
    if len(clean_mac) < 6:
        return "Desconocido"

    # Check for randomized / private MAC (Android / iOS / Windows Wi-Fi Privacy)
    if is_locally_administered_mac(clean_mac):
        return "Dispositivo Móvil / Privado (Android/iOS/Win)"

    prefix = f"{clean_mac[0:2]}:{clean_mac[2:4]}:{clean_mac[4:6]}"
    
    # 1. Check curated list
    if prefix in CURATED_OUI:
        return CURATED_OUI[prefix]

    # 2. Try netaddr library fallback
    try:
        import netaddr
        eui = netaddr.EUI(mac_address)
        org = eui.oui.registration().org
        if org:
            org = org.replace(" Inc.", "").replace(" Corporation", "").replace(" Co., Ltd.", "").strip()
            return org
    except Exception:
        pass

    return "Desconocido"
