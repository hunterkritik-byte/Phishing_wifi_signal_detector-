from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable


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


def group_by_ssid(points: Iterable[AccessPoint]) -> dict[str, list[AccessPoint]]:
    groups: dict[str, list[AccessPoint]] = {}
    for point in points:
        groups.setdefault(point.ssid, []).append(point)
    return groups


def compare_fingerprints(points: Iterable[AccessPoint]) -> list[dict[str, object]]:
    """Return explainable passive spoofing indicators; never declares certainty."""
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
    values = [float(v) for v in history]
    if len(values) < 3:
        return False
    baseline = median(values[:-1])
    return abs(values[-1] - baseline) >= threshold_db
