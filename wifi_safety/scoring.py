from .models import WifiObservation


def score(observation: WifiObservation, trusted_security: str | None = None) -> tuple[int, list[str]]:
    points = 0
    reasons: list[str] = []
    if observation.security.lower() in {"open", "none", "unknown"}:
        points += 15
        reasons.append("Network security is open or unknown")
    if trusted_security and observation.security.lower() != trusted_security.lower():
        points += 25
        reasons.append("Security mode differs from the trusted profile")
    if observation.ssid.strip().lower() in {"free wifi", "public wifi", "airport wifi", "hotel wifi"}:
        points += 10
        reasons.append("Generic public-service SSID deserves verification")
    score = min(points, 100)
    return score, reasons


def level(score: int) -> str:
    if score >= 70:
        return "high-concern"
    if score >= 40:
        return "suspicious"
    if score >= 15:
        return "review"
    return "low"


def concern_score(*, security_mismatch: bool = False, vendor_mismatch: bool = False,
                  fingerprint_mismatch: bool = False, channel_mismatch: bool = False,
                  rssi_anomaly: bool = False) -> dict[str, object]:
    """Score passive indicators with explainable weights; never declares certainty."""
    weights = {
        "security_mismatch": 30,
        "vendor_mismatch": 15,
        "fingerprint_mismatch": 25,
        "channel_mismatch": 10,
        "rssi_anomaly": 20,
    }
    flags = {
        "security_mismatch": security_mismatch,
        "vendor_mismatch": vendor_mismatch,
        "fingerprint_mismatch": fingerprint_mismatch,
        "channel_mismatch": channel_mismatch,
        "rssi_anomaly": rssi_anomaly,
    }
    total = min(sum(weights[name] for name, enabled in flags.items() if enabled), 100)
    return {
        "score": total,
        "level": level(total),
        "indicators": [name for name, enabled in flags.items() if enabled],
        "disclaimer": "Heuristic review aid only; score is not proof of spoofing or maliciousness.",
    }
