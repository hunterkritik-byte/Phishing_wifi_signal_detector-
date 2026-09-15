"""Passive Wi-Fi safety analysis.

Security: Input validation and sanitization applied throughout.
"""

from .detector import AccessPoint, compare_fingerprints, group_by_ssid, rssi_anomaly

__version__ = "0.2.1"
__all__ = ["AccessPoint", "compare_fingerprints", "group_by_ssid", "rssi_anomaly"]
