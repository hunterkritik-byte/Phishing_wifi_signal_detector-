# 📡 Phishing Wi-Fi Signal Detector

A **public-safety, passive Wi-Fi awareness tool** for identifying suspicious wireless-network characteristics. It can analyze offline 802.11 captures and normalized observations without attacking, deauthenticating, cracking, or interfering with networks.

> ⚠️ Defensive by design: no credential capture, password cracking, frame injection, deauthentication, access-point impersonation, or automatic connection.

## MVP

### Passive Wi-Fi scanning

On Linux, a compatible adapter and monitor mode are required for live 802.11 capture. A safe workflow is to capture authorized traffic with standard system tooling and feed the resulting PCAP to the offline analyzer. `scapy` is an optional dependency for PCAP parsing.

```bash
pip install -r requirements-optional.txt
python -c "from wifi_safety.pcap import iter_beacons; print(list(iter_beacons('capture.pcap'))[:5])"
```

Live monitor-mode setup is platform/adapter specific. The project does **not** automatically enable monitor mode or inject traffic. Follow your OS and adapter documentation and only capture networks you are authorized to observe.

## 🕵️ Evil-Twin / spoofing indicators

The detector compares observations sharing an SSID and looks for explainable differences such as:

- Multiple BSSIDs for one SSID
- Different encryption/security modes
- Different vendors/OUI information
- Different channels
- Different 802.11 information-element fingerprints
- Beacon interval differences when available
- Sudden RSSI changes relative to a local history

A mismatch is an **indicator for review**, not proof of an evil twin.

## 📶 RSSI consistency

```python
from wifi_safety import rssi_anomaly

rssi_anomaly([-80, -78, -79, -30], threshold_db=35)
# True
```

RSSI varies naturally with movement and radio conditions, so thresholds should be tuned to the environment and never used as a sole detection signal.

## 📡 Deauthentication / interference awareness

Future passive capture modules can count Deauthentication and Disassociation management frames and report unusual bursts. Similarly, repeated channel observations and noise measurements can be used as **possible interference indicators**.

The tool must never respond by transmitting deauthentication frames, jamming, or otherwise disrupting an access point.

## 🧬 Fingerprinting

The roadmap includes normalized fingerprints from beacon information elements, supported rates, capabilities, channel behavior, beacon intervals, and local OUI/vendor data. Fingerprints should be stored locally and compared against a trusted profile rather than treated as a global identity proof.

## 🗃️ History and alerts

Planned/compatible storage includes:

- SQLite observation history
- first/last seen timestamps
- typical channels and RSSI ranges
- JSON/CSV exports
- console notifications
- optional desktop/webhook notifications

## 🛡️ Local defense

When a finding reaches a configured high-concern threshold, a future response adapter may notify the user and optionally prevent **the user's own device** from automatically reconnecting to the suspicious BSSID. It will not disable or interfere with the AP.

## 🔐 Privacy by design

- No password collection
- No credential harvesting
- No authentication attempts
- No deauthentication/disruption
- Offline PCAP analysis by default
- Optional BSSID/MAC hashing for stored reports
- Client probe data should be dropped unless explicitly enabled
- Retention controls should be used for captured identifiers
- Precise location storage is disabled by default

Wireless captures can contain device identifiers and other metadata. Check local law and organizational policy before capturing or retaining them.

## 🚦 Risk levels

| Level | Meaning |
|---|---|
| 🟢 Low | No significant suspicious indicators observed |
| 🟡 Review | An unusual characteristic deserves verification |
| 🟠 Suspicious | Multiple indicators suggest caution |
| 🔴 High concern | Strong combination of locally observed anomalies |

## 🧰 Architecture

```text
wifi_safety/
├── models.py       # normalized observations
├── detector.py     # spoof/fingerprint/RSSI indicators
├── pcap.py         # offline 802.11 beacon parsing
├── scoring.py      # explainable risk scoring
├── profiles.py     # trusted-network profiles
├── privacy.py      # hashing/redaction helpers
├── report.py       # JSON/HTML reports
└── cli.py          # command-line interface
```

## Roadmap

- [x] Offline beacon parsing
- [x] SSID/BSSID correlation
- [x] Security/channel/vendor/fingerprint comparison
- [x] RSSI anomaly helper
- [x] Regression tests
- [ ] Local OUI database
- [ ] SQLite observation history
- [ ] `scan`, `show-suspects`, `export`, `start-monitor` CLI
- [ ] Passive deauth/disassociation surge detector
- [ ] Captive-portal review workflow
- [ ] DHCP/DNS anomaly analysis from authorized captures
- [ ] Optional ML anomaly scoring
- [ ] FastAPI/Streamlit dashboard

## Responsible use

Use this project only on Wi-Fi observations your device is legitimately allowed to inspect. The goal is to help people recognize suspicious wireless environments, not facilitate interception or unauthorized access.

## License

MIT
