def normalize_bssid(bssid: str) -> str:
    return bssid.replace(":", "").replace("-", "").replace(".", "").upper()


def vendor_from_oui(bssid: str, oui_map: dict[str, str]) -> str:
    key = normalize_bssid(bssid)[:6]
    return oui_map.get(key, "unknown")
