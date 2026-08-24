from wifi_safety.anomaly import compare_observations
from wifi_safety.models import WifiObservation


def test_security_and_fingerprint_mismatch():
    base = WifiObservation("Office", "aa:bb:cc:00:00:01", channel=1, security="wpa2", vendor="Cisco", ies_fingerprint="abc", rssi=-60)
    current = WifiObservation("Office", "dd:ee:ff:00:00:02", channel=6, security="open", vendor="Unknown", ies_fingerprint="xyz", rssi=-25)
    kinds = {x.kind for x in compare_observations(current, base)}
    assert {"bssid-change", "security-mismatch", "channel-change", "vendor-change", "ie-fingerprint-change", "rssi-jump"} == kinds
