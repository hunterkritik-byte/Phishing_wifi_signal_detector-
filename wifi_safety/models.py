from dataclasses import dataclass, field


@dataclass(frozen=True)
class WifiObservation:
    ssid: str
    bssid: str | None = None
    security: str = "unknown"
    signal_dbm: int | None = None
    channel: int | None = None
    reasons: tuple[str, ...] = field(default_factory=tuple)
