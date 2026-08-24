# 📡 Phishing Wi-Fi Signal Detector

A **public-safety, passive Wi-Fi awareness tool** for identifying suspicious wireless-network characteristics without attacking, deauthenticating, cracking, or interfering with networks.

> ⚠️ Defensive by design: no credential capture, password cracking, frame injection, deauthentication, access-point impersonation, or automatic connection.

## 🎯 Detection indicators

- Duplicate or near-duplicate SSIDs
- Suspicious SSID/BSSID changes
- Open networks using names associated with public services
- Unexpected encryption changes for a known SSID
- Rapid changes in advertised network metadata
- Weak or inconsistent security configuration
- User-defined trusted-network profiles

A score is **not proof of a rogue access point**. Every result should explain which indicators contributed to the score.

## 🛡️ Public-safety workflow

```text
┌──────────────┐
│ Local Wi-Fi  │
│ observation  │
└──────┬───────┘
       ▼
┌──────────────┐
│ Normalize    │
│ metadata     │
└──────┬───────┘
       ▼
┌──────────────┐
│ Compare with │
│ local policy │
└──────┬───────┘
       ▼
┌──────────────┐
│ Explain risk │
└──────┬───────┘
       ▼
┌──────────────┐
│ User decides │
│ what to do   │
└──────────────┘
```

## 🔐 Privacy by design

- No password collection
- No packet interception
- No credential harvesting
- No authentication attempts
- No deauthentication/disruption
- No active probing required
- Local analysis by default
- Optional hashing/redaction of BSSID/MAC values in reports
- Avoid precise location storage unless explicitly enabled

## 🚦 Risk levels

| Level | Meaning |
|---|---|
| 🟢 Low | No significant suspicious indicators observed |
| 🟡 Review | An unusual characteristic deserves verification |
| 🟠 Suspicious | Multiple indicators suggest caution |
| 🔴 High concern | Strong combination of locally observed anomalies |

The detector uses **explainable indicators instead of certainty claims**.

## 🧰 Architecture

```text
wifi_safety/
├── models.py       # normalized observation models
├── scoring.py      # explainable passive risk scoring
├── profiles.py     # trusted-network profiles
├── privacy.py      # hashing/redaction helpers
├── report.py       # JSON/HTML safety reports
└── cli.py          # local command-line interface
```

## Example report

```json
{
  "ssid": "Public WiFi",
  "security": "open",
  "risk": "review",
  "score": 42,
  "reasons": [
    "Open network",
    "SSID resembles a public-service network"
  ],
  "recommendation": "Verify the network name with the venue before connecting."
}
```

## 🧑‍💻 Responsible use

Use this project only on Wi-Fi observations your device is legitimately allowed to inspect. The goal is to help people recognize suspicious wireless environments, not facilitate interception or unauthorized access.

## License

MIT
