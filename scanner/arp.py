import re
import subprocess
import platform

# Regex to match IPv4 and MAC address formats (e.g. 192.168.1.1 and 00-11-22-33-44-55 or 00:11:22:33:44:55)
ARP_REGEX = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
)

def normalize_mac(mac_str):
    if not mac_str:
        return ""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac_str).upper()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac_str.upper().replace("-", ":")

def get_arp_table():
    """
    Executes 'arp -a' and returns a mapping of { ip: mac }.
    Filters out broadcast and multicast entries.
    """
    arp_map = {}
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, timeout=5)
        for line in output.splitlines():
            match = ARP_REGEX.search(line)
            if match:
                ip = match.group(1)
                mac = normalize_mac(match.group(2))
                
                # Filter broadcast and multicast MACs
                if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E"):
                    continue
                # Filter multicast IPs (224.0.0.0 to 239.255.255.255)
                first_octet = int(ip.split(".")[0])
                if 224 <= first_octet <= 239 or ip.endswith(".255"):
                    continue

                arp_map[ip] = mac
    except Exception:
        pass

    return arp_map
