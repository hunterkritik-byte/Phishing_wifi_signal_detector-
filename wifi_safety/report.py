import json
from .models import WifiObservation
from .scoring import level, score


def to_report(observation: WifiObservation, trusted_security: str | None = None) -> dict:
    risk_score, reasons = score(observation, trusted_security)
    return {
        "ssid": observation.ssid,
        "security": observation.security,
        "signal_dbm": observation.signal_dbm,
        "channel": observation.channel,
        "risk": level(risk_score),
        "score": risk_score,
        "reasons": reasons,
        "recommendation": "Verify the network with the venue before connecting when risk indicators are present.",
    }


def dumps(observation: WifiObservation, trusted_security: str | None = None) -> str:
    return json.dumps(to_report(observation, trusted_security), indent=2)
