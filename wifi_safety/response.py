"""Safe response helpers for suspicious Wi-Fi observations."""

from __future__ import annotations


def recommended_actions(*, risk: str, possible_interference: bool) -> list[str]:
    actions = [
        "Do not enter passwords or sensitive information while the network is unverified.",
        "Verify the SSID and venue-provided network details through a trusted channel.",
    ]
    if risk in {"suspicious", "high-concern"}:
        actions.insert(0, "Disconnect this device from the suspicious network if you can do so safely.")
    if possible_interference:
        actions.append("Switch to cellular data or another known-good connection and report suspected interference to the venue/network operator.")
    actions.append("Do not attempt to deauthenticate, jam, impersonate, or disable another access point.")
    return actions
