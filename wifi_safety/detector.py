from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable
import re


def _validate_ssid(ssid: str) -> str:
    """Validate and sanitize SSID to prevent injection attacks."""
    if not isinstance(ssid, str):
        raise TypeError("SSID must be a string")
    if len(ssid) > 32:
        raise ValueError("SSID length cannot exceed 32 characters")
    # SSID can contain any bytes, but we'll ensure safe handling
    return ssid.strip()


def _validate_bssid(bssid: str) -> str:
    """Validate BSSID format (MAC address)."""
    if not isinstance(bssid, str):
        raise TypeError("BSSID must be a string")
    # MAC address validation: XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX
    mac_pattern = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$'
    if not re.match(mac_pattern, bssid.replace('-', ':')):
        raise ValueError(f"Invalid BSSID format: {bssid}")
    return bssid.lower()


def _validate_channel(channel: int | None) -> int | None:
    """Validate WiFi channel number."""
    if channel is None:
        return None
    if not isinstance(channel, int):
        raise TypeError("Channel must be an integer")
    if not (1 <= channel <= 165):
        raise ValueError(f"Invalid channel: {channel}. Must be between 1 and 165")
    return channel


def _validate_rssi(rssi: float | None) -> float | None:
    """Validate RSSI (signal strength) value."""
    if rssi is None:
        return None
    rssi_float = float(rssi)
    if not (-100 <= rssi_float <= 0):
        raise ValueError(f"Invalid RSSI: {rssi}. Must be between -100 and 0 dBm")
    return rssi_float


@dataclass(frozen=True)
class AccessPoint:
    ssid: str
    bssid: str
    channel: int | None = None
    security: str = "unknown"
    vendor: str = "unknown"
    beacon_interval_ms: float | None = None
    rssi: float | None = None
    ies_fingerprint: str = ""

    def __post_init__(self):
        """Validate all fields after initialization."""
        object.__setattr__(self, 'ssid', _validate_ssid(self.ssid))
        object.__setattr__(self, 'bssid', _validate_bssid(self.bssid))
        object.__setattr__(self, 'channel', _validate_channel(self.channel))
        object.__setattr__(self, 'rssi', _validate_rssi(self.rssi))
        
        if not isinstance(self.security, str):
            raise TypeError("security must be a string")
        if not isinstance(self.vendor, str):
            raise TypeError("vendor must be a string")
        if not isinstance(self.ies_fingerprint, str):
            raise TypeError("ies_fingerprint must be a string")


def group_by_ssid(points: Iterable[AccessPoint]) -> dict[str, list[AccessPoint]]:
    """Group access points by SSID."""
    if not isinstance(points, Iterable):
        raise TypeError("points must be iterable")
    
    groups: dict[str, list[AccessPoint]] = {}
    for point in points:
        if not isinstance(point, AccessPoint):
            raise TypeError(f"Expected AccessPoint, got {type(point).__name__}")
        groups.setdefault(point.ssid, []).append(point)
    return groups


def compare_fingerprints(points: Iterable[AccessPoint]) -> list[dict[str, object]]:
    """Return explainable passive spoofing indicators; never declares certainty.
    
    Security: Input validation prevents injection attacks.
    """
    if not isinstance(points, Iterable):
        raise TypeError("points must be iterable")
    
    findings: list[dict[str, object]] = []
    for ssid, group in group_by_ssid(points).items():
        if len({p.bssid.lower() for p in group}) < 2:
            continue
        security = {p.security.lower() for p in group}
        vendors = {p.vendor.lower() for p in group}
        channels = {p.channel for p in group if p.channel is not None}
        fingerprints = {p.ies_fingerprint for p in group if p.ies_fingerprint}
        reasons: list[str] = []
        if len(security) > 1:
            reasons.append("same SSID advertised with differing security")
        if len(vendors) > 1:
            reasons.append("same SSID advertised by differing vendors")
        if len(fingerprints) > 1:
            reasons.append("802.11 information-element fingerprints differ")
        if len(channels) > 1:
            reasons.append("same SSID appears on multiple channels")
        if reasons:
            findings.append({"ssid": ssid, "bssids": sorted({p.bssid for p in group}), "reasons": reasons})
    return findings


def rssi_anomaly(history: Iterable[float], threshold_db: float = 35.0) -> bool:
    """Detect RSSI anomalies with validation."""
    if not isinstance(history, Iterable):
        raise TypeError("history must be iterable")
    
    values = [float(v) for v in history]
    
    if not (0 < threshold_db < 100):
        raise ValueError(f"threshold_db must be between 0 and 100, got {threshold_db}")
    
    if len(values) < 3:
        return False
    
    # Validate RSSI values
    for val in values:
        if not (-100 <= val <= 0):
            raise ValueError(f"Invalid RSSI value: {val}. Must be between -100 and 0 dBm")
    
    baseline = median(values[:-1])
    return abs(values[-1] - baseline) >= threshold_db
