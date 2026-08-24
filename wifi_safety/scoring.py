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
