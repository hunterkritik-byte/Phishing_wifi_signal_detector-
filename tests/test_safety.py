from wifi_safety.models import WifiObservation
from wifi_safety.privacy import anonymize_identifier
from wifi_safety.report import to_report


def test_open_public_wifi_gets_review_signal():
    report = to_report(WifiObservation("Public WiFi", security="open"))
    assert report["score"] >= 15
    assert report["risk"] == "review"


def test_trusted_security_change_is_explained():
    report = to_report(WifiObservation("Cafe", security="open"), trusted_security="wpa2")
    assert "trusted profile" in " ".join(report["reasons"])


def test_identifier_is_not_returned_verbatim():
    original = "aa:bb:cc:dd:ee:ff"
    anonymized = anonymize_identifier(original, "local-salt")
    assert original not in anonymized
    assert len(anonymized) == 16
