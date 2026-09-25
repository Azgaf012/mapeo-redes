"""Resolve observed neighbors without fabricating physical connections."""


def _normalized(value):
    return (value or "").strip().lower().split(".")[0]


def resolve_neighbor(neighbor, devices):
    identifiers = [neighbor.get("target_ip"), neighbor.get("neighbor_name")]
    matches = []
    for device in devices:
        names = {device.get("ip", "").lower(), _normalized(device.get("hostname"))}
        for identifier in identifiers:
            if identifier and (_normalized(identifier) in names or identifier.lower() in names):
                matches.append(device)
                break
    return matches[0] if len(matches) == 1 else None


def build_topology(site_id, devices, connection_repo, gateway_ip=None, lldp_links=None):
    """Persist only uniquely resolved LLDP/CDP links and preserve manual links."""
    by_ip = {d["ip"]: d for d in devices}
    connection_repo.clear_discovered_for_site(site_id)
    for neighbor in lldp_links or []:
        source = by_ip.get(neighbor.get("source_ip"))
        target = resolve_neighbor(neighbor, devices)
        if not source or not target or source["id"] == target["id"]:
            continue
        connection_repo.create_or_update(
            site_id, source["id"], target["id"],
            source_interface_id=neighbor.get("source_interface_id"),
            target_interface_id=neighbor.get("target_interface_id"),
            discovery_method=neighbor.get("protocol", "LLDP"), confidence="HIGH",
        )
    return connection_repo.get_by_site(site_id)
