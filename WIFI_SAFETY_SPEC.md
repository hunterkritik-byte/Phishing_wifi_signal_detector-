# Passive Wi-Fi Safety Detector — MVP/Research Specification

## Scope

The detector is a defensive, passive awareness tool. It may analyze locally captured 802.11 management frames and offline PCAP files, but it must not deauthenticate clients, inject frames, impersonate access points, crack credentials, or disrupt networks.

## MVP

- Scapy/pcap ingestion for beacon and probe-response observations
- SSID/BSSID correlation and duplicate-SSID detection
- Encryption/channel/vendor/beacon-interval comparison
- RSSI history and anomaly scoring
- Local OUI/vendor database support
- SQLite observation history
- JSON/CSV export
- Console and desktop/webhook notifications
- CLI commands: `scan`, `show-suspects`, `export`, `start-monitor`

## Advanced passive analysis

- 802.11 deauthentication/disassociation surge detection
- Information-element fingerprint comparison
- Supported-rate/capability fingerprint comparison
- Channel/BSSID consistency checks
- Interference/noise anomaly detection
- Rogue DHCP/DNS indicators from authorized local captures
- Captive-portal review using explicitly authorized connectivity checks
- Optional offline anomaly scoring with scikit-learn

## Privacy

- Hash MAC addresses by default in persisted reports
- Do not persist client probe payloads unless explicitly enabled
- Provide retention controls
- Keep exact location disabled by default
- Clearly document that wireless captures can contain device identifiers

## Safe response

High-risk findings may trigger local notifications and optionally prevent the user's own device from automatically reconnecting to a suspicious network. The tool must never attempt to disable, deauthenticate, jam, or otherwise interfere with an access point or third-party device.
