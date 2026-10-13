from scanner.vendor import lookup_vendor

def test_curated_vendor_lookup():
    # Cisco
    assert "Cisco" in lookup_vendor("00:00:0C:11:22:33")
    # Ubiquiti
    assert "Ubiquiti" in lookup_vendor("FC:EC:DA:99:88:77")
    # TP-Link
    assert "TP-Link" in lookup_vendor("EC:55:1C:83:B7:66")
    # Fortinet
    assert "Fortinet" in lookup_vendor("08:5B:0E:12:34:56")
    # Hikvision
    assert "Hikvision" in lookup_vendor("44:19:B6:AB:CD:EF")
    # Epson
    assert "Epson" in lookup_vendor("00:26:AB:12:34:56")

def test_unknown_or_empty_mac():
    assert lookup_vendor("") == "Desconocido"
    assert lookup_vendor(None) == "Desconocido"
    assert lookup_vendor("AA:22:D7:A1:D8:5B") == "MAC privada/aleatoria"


def test_supplemental_oui_prefixes_resolve():
    from scanner.vendor import lookup_vendor
    assert lookup_vendor("20:58:43:09:63:7C") == "WNC Corporation"
    assert lookup_vendor("54:EA:E1:00:00:01") == "Honor Device"
