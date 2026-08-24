from __future__ import annotations

from pathlib import Path
from typing import Iterator


def iter_beacons(path: str | Path) -> Iterator[dict[str, object]]:
    """Yield normalized beacon metadata from an offline PCAP.

    Scapy is imported lazily so the core package remains installable without
    wireless capture dependencies. This parser is intentionally offline-only.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, rdpcap

    for packet in rdpcap(str(path)):
        if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11):
            continue
        dot11 = packet[Dot11]
        beacon = packet[Dot11Beacon]
        ssid = ""
        element = packet.getlayer(Dot11Elt)
        while element is not None:
            if getattr(element, "ID", None) == 0:
                raw = bytes(getattr(element, "info", b""))
                ssid = raw.decode("utf-8", errors="replace")
                break
            element = getattr(element, "payload", None)
        yield {
            "ssid": ssid,
            "bssid": str(getattr(dot11, "addr2", "")),
            "channel": getattr(beacon, "channel", None),
            "capability": str(getattr(beacon, "cap", "")),
        }
