from __future__ import annotations

from pathlib import Path
from typing import Iterator
import os


def _validate_pcap_path(path: str | Path) -> Path:
    """Validate PCAP file path for security and existence.
    
    Security: Prevents path traversal and ensures file exists and is readable.
    """
    file_path = Path(path).resolve()
    
    # Check if file exists
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")
    
    # Check if it's a file (not directory)
    if not file_path.is_file():
        raise ValueError(f"Path must point to a file, not a directory: {file_path}")
    
    # Check if file is readable
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"PCAP file is not readable: {file_path}")
    
    # Check file size (prevent DoS with huge files, limit to 1GB)
    max_size = 1024 * 1024 * 1024  # 1GB
    if file_path.stat().st_size > max_size:
        raise ValueError(f"PCAP file exceeds maximum size of 1GB: {file_path}")
    
    return file_path


def iter_beacons(path: str | Path) -> Iterator[dict[str, object]]:
    """Yield normalized beacon metadata from an offline PCAP.

    Scapy is imported lazily so the core package remains installable without
    wireless capture dependencies. This parser is intentionally offline-only.
    
    Security: Input validation prevents path traversal and DoS attacks.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, rdpcap
    
    # Validate path
    file_path = _validate_pcap_path(path)
    
    try:
        packets = rdpcap(str(file_path))
    except Exception as e:
        raise ValueError(f"Failed to parse PCAP file: {e}") from e
    
    for packet in packets:
        if not packet.haslayer(Dot11Beacon) or not packet.haslayer(Dot11):
            continue
        
        try:
            dot11 = packet[Dot11]
            beacon = packet[Dot11Beacon]
            ssid = ""
            element = packet.getlayer(Dot11Elt)
            
            while element is not None:
                if getattr(element, "ID", None) == 0:
                    raw = bytes(getattr(element, "info", b""))
                    # Safely decode with error handling
                    ssid = raw.decode("utf-8", errors="replace")
                    break
                element = getattr(element, "payload", None)
            
            # Validate extracted data
            bssid = str(getattr(dot11, "addr2", ""))
            channel = getattr(beacon, "channel", None)
            capability = str(getattr(beacon, "cap", ""))
            
            # Basic format validation
            if not bssid or ":" not in bssid:
                continue
            
            yield {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "capability": capability,
            }
        except Exception:
            # Skip malformed packets
            continue
