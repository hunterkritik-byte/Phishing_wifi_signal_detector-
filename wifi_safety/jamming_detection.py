"""Passive, explainable Wi-Fi interference indicators.

This module never transmits frames, deauthenticates clients, jams channels,
or attempts to disable an access point. It analyzes observations supplied by
an authorized local collector.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median


@dataclass(frozen=True)
class InterferenceFinding:
    level: str
    score: int
    reasons: tuple[str, ...]
    recommendation: str


def assess_interference(
    observations: list[dict[str, object]],
    *,
    window_size: int = 12,
) -> InterferenceFinding:
    """Assess local observations for possible RF interference.

    Expected optional fields per observation: ``channel``, ``noise_dbm``,
    ``signal_dbm``, and ``beacon_count``. Missing values are ignored.
    A result is only an indicator of possible interference, never proof of
    intentional jamming.
    """
    recent = observations[-max(1, window_size):]
    noise = [float(x["noise_dbm"]) for x in recent if "noise_dbm" in x]
    beacons = [float(x["beacon_count"]) for x in recent if "beacon_count" in x]
    score = 0
    reasons: list[str] = []

    if len(noise) >= 4:
        baseline = median(noise[: max(2, len(noise) // 2)])
        latest = median(noise[-max(2, len(noise) // 3):])
        if latest - baseline >= 12:
            score += 45
            reasons.append("Noise floor increased sharply in the observation window")
        elif latest - baseline >= 7:
            score += 25
            reasons.append("Noise floor increased noticeably")

    if len(beacons) >= 4:
        baseline = median(beacons[: max(2, len(beacons) // 2)])
        latest = median(beacons[-max(2, len(beacons) // 3):])
        if latest < baseline * 0.35:
            score += 30
            reasons.append("Observed beacon count dropped substantially")

    score = min(score, 100)
    if score >= 60:
        level = "high-concern"
        recommendation = "Stop relying on the affected Wi-Fi and verify the environment through the venue/network administrator."
    elif score >= 25:
        level = "review"
        recommendation = "Move to a known-good connection if practical and collect another observation window."
    else:
        level = "low"
        recommendation = "No strong interference indicator was observed; continue normal safety checks."

    return InterferenceFinding(level, score, tuple(reasons), recommendation)
