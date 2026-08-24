from wifi_safety.detector import AccessPoint, compare_fingerprints, rssi_anomaly


def test_security_mismatch_is_flagged():
    points = [
        AccessPoint("Office", "00:11:22:33:44:55", security="WPA2", vendor="Cisco", channel=1),
        AccessPoint("Office", "66:77:88:99:aa:bb", security="OPEN", vendor="Cisco", channel=1),
    ]
    findings = compare_fingerprints(points)
    assert findings
    assert "differing security" in findings[0]["reasons"][0]


def test_rssi_jump_is_anomaly():
    assert rssi_anomaly([-80, -78, -79, -30], threshold_db=35)


def test_small_rssi_change_is_not_anomaly():
    assert not rssi_anomaly([-70, -68, -71, -66], threshold_db=35)
