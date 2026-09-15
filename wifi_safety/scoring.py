from .models import WifiObservation


def _validate_score_input(value: int | float) -> int:
    """Validate and sanitize score input."""
    try:
        score = int(value)
        if not (0 <= score <= 100):
            raise ValueError(f"Score must be between 0 and 100, got {value}")
        return score
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid score value: {value}") from e


def score(observation: WifiObservation, trusted_security: str | None = None) -> tuple[int, list[str]]:
    """Calculate risk score with input validation.
    
    Security: All inputs are validated before processing.
    """
    if not hasattr(observation, 'security'):
        raise ValueError("observation must have a 'security' attribute")
    
    points = 0
    reasons: list[str] = []
    
    security = str(observation.security).lower().strip()
    if security in {"open", "none", "unknown", ""}:
        points += 15
        reasons.append("Network security is open or unknown")
    
    if trusted_security:
        trusted_security = str(trusted_security).lower().strip()
        if security != trusted_security:
            points += 25
            reasons.append("Security mode differs from the trusted profile")
    
    if hasattr(observation, 'ssid'):
        ssid = str(observation.ssid).strip().lower()
        generic_ssids = {"free wifi", "public wifi", "airport wifi", "hotel wifi", "guest wifi", "open"}
        if ssid in generic_ssids:
            points += 10
            reasons.append("Generic public-service SSID deserves verification")
    
    score_value = min(points, 100)
    return score_value, reasons


def level(score: int) -> str:
    """Determine risk level from score with validation.
    
    Security: Input is validated to prevent unexpected behavior.
    """
    score = _validate_score_input(score)
    
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
    """Score passive indicators with explainable weights; never declares certainty.
    
    Security: All inputs are validated as boolean types.
    """
    # Validate boolean inputs
    for name, value in {
        "security_mismatch": security_mismatch,
        "vendor_mismatch": vendor_mismatch,
        "fingerprint_mismatch": fingerprint_mismatch,
        "channel_mismatch": channel_mismatch,
        "rssi_anomaly": rssi_anomaly,
    }.items():
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a boolean, got {type(value).__name__}")
    
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
