"""Validate and import a controller client export as an observed snapshot."""

import csv
import io


def _column_name(value):
    return "".join(char for char in (value or "").casefold() if char.isalnum())


def _mac(value):
    normalized = "".join(char for char in (value or "").upper() if char in "0123456789ABCDEF")
    return normalized if len(normalized) == 12 else ""


class ApAssociationService:
    def __init__(self, device_repo, association_repo):
        self.device_repo = device_repo
        self.association_repo = association_repo

    def import_csv(self, site_id, content):
        if len(content) > 2_000_000:
            raise ValueError("El CSV supera el límite de 2 MB.")
        try:
            decoded = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("El CSV debe estar codificado en UTF-8.") from exc
        header = decoded.splitlines()[0] if decoded else ""
        delimiter = ";" if ";" in header and "," not in header else ","
        reader = csv.DictReader(io.StringIO(decoded, newline=""), delimiter=delimiter)
        columns = {_column_name(name): name for name in (reader.fieldnames or [])}
        mac_column = next((columns[name] for name in
                           ("clientmac", "macaddress", "macaddr") if name in columns), None)
        ap_column = next((columns[name] for name in
                          ("apip", "accesspoint", "associateddevice", "apname")
                          if name in columns), None)
        if not mac_column or not ap_column:
            raise ValueError("El CSV necesita las columnas client_mac y ap_ip (o MAC address y Access Point).")

        devices = self.device_repo.get_all(site_id=site_id)
        by_reference = {}
        for device in devices:
            if device["device_type"] not in ("ACCESS_POINT", "UNKNOWN"):
                continue
            if device["device_type"] == "UNKNOWN" and device["is_manual"]:
                continue
            for field in ("ip", "hostname", "serial_number"):
                reference = (device.get(field) or "").strip().casefold()
                if reference:
                    by_reference.setdefault(reference, set()).add(device["id"])

        matches = {}
        conflicting = set()
        invalid = 0
        unresolved = 0
        rows = 0
        for row in reader:
            rows += 1
            mac = _mac(row.get(mac_column))
            ap_reference = (row.get(ap_column) or "").strip().casefold()
            ap_ids = by_reference.get(ap_reference, set())
            if not mac or not ap_reference:
                invalid += 1
                continue
            if len(ap_ids) != 1:
                unresolved += 1
                continue
            ap_id = next(iter(ap_ids))
            if mac in matches and matches[mac] != ap_id:
                conflicting.add(mac)
            matches[mac] = ap_id
        for mac in conflicting:
            del matches[mac]
        if rows and not matches:
            return {"imported": 0, "invalid": invalid, "unresolved": unresolved,
                    "ambiguous": len(conflicting), "replaced": False}

        self.association_repo.replace_snapshot(site_id, matches.items())
        for ap_id in set(matches.values()):
            self.device_repo.confirm_access_point(ap_id, "ap_client_csv")
        return {"imported": len(matches), "invalid": invalid, "unresolved": unresolved,
                "ambiguous": len(conflicting), "replaced": True}

    def refresh_recent_aps(self, site_id):
        for ap_id in self.association_repo.get_recent_ap_ids(site_id):
            self.device_repo.confirm_access_point(ap_id, "ap_client_csv")
