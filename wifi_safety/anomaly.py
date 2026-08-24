from dataclasses import dataclass


@dataclass(frozen=True)
class Anomaly:
    kind: str
    score: int
    reason: str


def compare_observations(current, baseline):
    """Return explainable passive anomalies; never transmit or modify networks."""
    findings = []
    if current.ssid == baseline.ssid and current.bssid != baseline.bssid:
        findings.append(Anomaly("bssid-change", 20, "Known SSID is advertised by a different BSSID."))
    if current.ssid == baseline.ssid and current.security != baseline.security:
        findings.append(Anomaly("security-mismatch", 35, "Known SSID has a different advertised security mode."))
    if current.ssid == baseline.ssid and current.channel != baseline.channel:
        findings.append(Anomaly("channel-change", 10, "Known SSID moved to a different channel."))
    if current.ssid == baseline.ssid and current.vendor != baseline.vendor:
        findings.append(Anomaly("vendor-change", 20, "Known SSID has a different BSSID vendor."))
    if current.ssid == baseline.ssid and current.ies_fingerprint != baseline.ies_fingerprint:
        findings.append(Anomaly("ie-fingerprint-change", 30, "802.11 information-element fingerprint changed."))
    if current.rssi is not None and baseline.rssi is not None and abs(current.rssi - baseline.rssi) >= 35:
        findings.append(Anomaly("rssi-jump", 15, "Observed RSSI changed sharply relative to the local baseline."))
    return findings
