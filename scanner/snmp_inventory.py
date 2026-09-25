"""Read standard SNMP tables for a single managed device."""

import asyncio
import ipaddress


OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_uptime": "1.3.6.1.2.1.1.3.0",
    "ent_serial": "1.3.6.1.2.1.47.1.1.1.1.11",
    "ent_model": "1.3.6.1.2.1.47.1.1.1.1.13",
    "ent_class": "1.3.6.1.2.1.47.1.1.1.1.5",
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_descr": "1.3.6.1.2.1.2.2.1.2",
    "if_mac": "1.3.6.1.2.1.2.2.1.6",
    "if_admin": "1.3.6.1.2.1.2.2.1.7",
    "if_oper": "1.3.6.1.2.1.2.2.1.8",
    "if_speed": "1.3.6.1.2.1.31.1.1.1.15",
    "bridge_if": "1.3.6.1.2.1.17.1.4.1.2",
    "vlan_name": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "vlan_egress": "1.3.6.1.2.1.17.7.1.4.3.1.2",
    "vlan_untagged": "1.3.6.1.2.1.17.7.1.4.3.1.4",
    "fdb_port": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "lldp_local_port": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldp_name": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldp_port": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldp_description": "1.0.8802.1.1.2.1.4.1.1.10",
    "lldp_chassis_subtype": "1.0.8802.1.1.2.1.4.1.1.4",
    "lldp_chassis_id": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldp_capabilities": "1.0.8802.1.1.2.1.4.1.1.12",
    "lldp_management_if": "1.0.8802.1.1.2.1.4.2.1.3",
    "cdp_name": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdp_port": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
}


def _text(value):
    return value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)


def _number(value):
    try:
        return int(_text(value))
    except (TypeError, ValueError):
        return None


def _mac(value):
    if not hasattr(value, "asOctets"):
        return _text(value)
    raw = value.asOctets()
    return ":".join(f"{part:02X}" for part in raw) if raw else ""


def _ports_from_bitmap(value):
    raw = value.asOctets() if hasattr(value, "asOctets") else b""
    return {
        index * 8 + bit + 1
        for index, byte in enumerate(raw)
        for bit in range(8)
        if byte & (0x80 >> bit)
    }


def _hardware_identity(tables):
    classes = tables.get("ent_class", {})
    models = tables.get("ent_model", {})
    serials = tables.get("ent_serial", {})
    indices = sorted(set(models) | set(serials), key=lambda value: int(value.split(".")[0]))
    for hardware_class in (3, 11, 9):
        chassis = [index for index in indices if _number(classes.get(index)) == hardware_class]
        if chassis:
            index = chassis[0]
            return _text(models.get(index) or ""), _text(serials.get(index) or "")
    model = next((_text(models[index]) for index in indices if models.get(index)
                  and _text(models[index]).strip()), "")
    serial = next((_text(serials[index]) for index in indices if serials.get(index)
                   and _text(serials[index]).strip()), "")
    return model, serial


def _lldp_management_ips(tables):
    addresses = {}
    for suffix in tables.get("lldp_management_if", {}):
        parts = suffix.split(".")
        if len(parts) < 9 or parts[3:5] != ["1", "4"]:
            continue
        try:
            address = str(ipaddress.IPv4Address(bytes(int(part) for part in parts[5:9])))
        except (ValueError, TypeError):
            continue
        addresses.setdefault(".".join(parts[:3]), set()).add(address)
    return addresses


def _lldp_capabilities(value):
    names = ("other", "repeater", "bridge", "wlan_access_point", "router",
             "telephone", "docsis_cable", "station")
    raw = value.asOctets() if hasattr(value, "asOctets") else b""
    return [name for index, name in enumerate(names)
            if len(raw) > index // 8 and raw[index // 8] & (0x80 >> (index % 8))]


def build_inventory(tables):
    """Turn standard MIB columns into device, port, VLAN and neighbor records."""
    indices = set().union(*(set(tables.get(key, {})) for key in
                            ("if_name", "if_descr", "if_admin", "if_oper")))
    interfaces = []
    for suffix in sorted(indices, key=lambda item: int(item.split(".")[0])):
        index = int(suffix.split(".")[0])
        name = _text(tables.get("if_name", {}).get(suffix) or
                     tables.get("if_descr", {}).get(suffix) or index)
        speed_mbps = _number(tables.get("if_speed", {}).get(suffix))
        admin = _number(tables.get("if_admin", {}).get(suffix))
        oper = _number(tables.get("if_oper", {}).get(suffix))
        interfaces.append({
            "if_index": index, "name": name,
            "description": _text(tables.get("if_descr", {}).get(suffix) or ""),
            "mac": _mac(tables.get("if_mac", {}).get(suffix) or ""),
            "speed_bps": speed_mbps * 1_000_000 if speed_mbps is not None else None,
            "speed": f"{speed_mbps} Mb/s" if speed_mbps is not None else None,
            "admin_status": "UP" if admin == 1 else "DOWN" if admin == 2 else "UNKNOWN",
            "oper_status": "UP" if oper == 1 else "DOWN" if oper == 2 else "UNKNOWN",
        })

    bridge_to_if = {int(port): _number(value)
                    for port, value in tables.get("bridge_if", {}).items()}
    vlans = [{"number": int(number), "name": _text(value)}
             for number, value in tables.get("vlan_name", {}).items()]
    membership = []
    for number, bitmap in tables.get("vlan_egress", {}).items():
        untagged = _ports_from_bitmap(tables.get("vlan_untagged", {}).get(number))
        for bridge_port in _ports_from_bitmap(bitmap):
            if_index = bridge_to_if.get(bridge_port)
            if if_index is not None:
                membership.append({"if_index": if_index, "vlan": int(number),
                                   "mode": "UNTAGGED" if bridge_port in untagged else "TAGGED"})

    mac_learnings = []
    for suffix, value in tables.get("fdb_port", {}).items():
        parts = suffix.split(".")
        if len(parts) != 7:
            continue
        bridge_port = _number(value)
        mac_learnings.append({
            "vlan": int(parts[0]),
            "mac": ":".join(f"{int(part):02X}" for part in parts[1:]),
            "if_index": bridge_to_if.get(bridge_port),
        })

    if_names = {str(port["if_index"]): port["name"] for port in interfaces}
    local_ports = {suffix: _text(value)
                   for suffix, value in tables.get("lldp_local_port", {}).items()}
    neighbors = []
    management_ips = _lldp_management_ips(tables)
    lldp_keys = ("lldp_name", "lldp_port", "lldp_description", "lldp_chassis_id",
                 "lldp_capabilities")
    for suffix in sorted(set().union(*(set(tables.get(key, {})) for key in lldp_keys))):
        parts = suffix.split(".")
        local_number = parts[-2] if len(parts) >= 3 else ""
        chassis = tables.get("lldp_chassis_id", {}).get(suffix)
        chassis_mac = _number(tables.get("lldp_chassis_subtype", {}).get(suffix)) == 4
        chassis_id = _mac(chassis) if chassis_mac and chassis is not None else _text(chassis or "")
        ips = management_ips.get(suffix, set())
        neighbors.append({
            "neighbor_name": _text(tables.get("lldp_name", {}).get(suffix) or ""),
            "source_port": local_ports.get(local_number) or if_names.get(local_number),
            "remote_port": _text(tables.get("lldp_port", {}).get(suffix) or ""),
            "protocol": "LLDP",
            "description": _text(tables.get("lldp_description", {}).get(suffix) or ""),
            "chassis_id": chassis_id,
            "capabilities": _lldp_capabilities(tables.get("lldp_capabilities", {}).get(suffix)),
            "target_ip": sorted(ips)[0] if len(ips) == 1 else "",
        })
    for suffix, name in tables.get("cdp_name", {}).items():
        local_index = suffix.split(".")[0]
        neighbors.append({
            "neighbor_name": _text(name), "source_port": if_names.get(local_index),
            "remote_port": _text(tables.get("cdp_port", {}).get(suffix) or ""),
            "protocol": "CDP",
        })
    model, serial = _hardware_identity(tables)
    return {"interfaces": interfaces, "vlans": vlans, "serial_number": serial,
            "model": model,
            "interface_vlans": membership, "mac_learnings": mac_learnings,
            "neighbors": neighbors}


async def _collect(ip, credentials):
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
        UdpTransportTarget, UsmUserData, USM_AUTH_HMAC192_SHA256,
        USM_AUTH_HMAC96_SHA, USM_PRIV_CFB128_AES, bulk_walk_cmd, get_cmd,
    )

    if credentials.get("version") == "3":
        protocol = (USM_AUTH_HMAC96_SHA if credentials.get("auth_protocol") == "SHA1"
                    else USM_AUTH_HMAC192_SHA256)
        auth = UsmUserData(credentials["username"],
                           authKey=credentials.get("auth_key") or None,
                           privKey=credentials.get("priv_key") or None,
                           authProtocol=protocol, privProtocol=USM_PRIV_CFB128_AES)
    else:
        auth = CommunityData(credentials.get("community") or "public", mpModel=1)
    target = await UdpTransportTarget.create((ip, 161), timeout=0.8, retries=0)
    context = ContextData()
    tables = {}
    with SnmpEngine() as engine:
        scalar_oids = (OIDS["sys_descr"], OIDS["sys_name"], OIDS["sys_uptime"],
                       OIDS["sys_object_id"])
        error, status, _, bindings = await get_cmd(
            engine, auth, target, context,
            *(ObjectType(ObjectIdentity(oid)) for oid in scalar_oids), lookupMib=False,
        )
        if error or status:
            return {"has_snmp": False}
        uptime_ticks = _number(bindings[2][1])
        result = {"has_snmp": True, "sys_descr": _text(bindings[0][1]),
                  "sys_name": _text(bindings[1][1]),
                  "sys_object_id": _text(bindings[3][1]),
                  "uptime_seconds": uptime_ticks // 100 if uptime_ticks is not None else None}
        for key, oid in OIDS.items():
            if key.startswith("sys_"):
                continue
            values = {}
            async for error, status, _, bindings in bulk_walk_cmd(
                    engine, auth, target, context, 0, 20,
                    ObjectType(ObjectIdentity(oid)), lookupMib=False,
                    lexicographicMode=False, maxRows=4096):
                if error or status:
                    break
                for binding in bindings:
                    name = _text(binding[0])
                    if name.startswith(oid + "."):
                        values[name[len(oid) + 1:]] = binding[1]
            tables[key] = values
        result.update(build_inventory(tables))
        return result


def collect_snmp_inventory(ip, credentials):
    return asyncio.run(_collect(ip, credentials))
