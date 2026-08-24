import hashlib
import sqlite3


def pseudonymize(value: str, salt: str) -> str:
    return hashlib.sha256((salt + value).encode()).hexdigest()[:16]


def open_db(path: str = "wifi_safety.sqlite3") -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS observations (ssid TEXT, bssid TEXT, channel INTEGER, security TEXT, rssi REAL, vendor TEXT, observed_at TEXT)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_observations_bssid ON observations(bssid)")
    return db


def save_observation(db, observation, hash_mac: bool = True, salt: str = "local"):
    bssid = pseudonymize(observation.bssid, salt) if hash_mac else observation.bssid
    db.execute("INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)", (observation.ssid, bssid, observation.channel, observation.security, observation.rssi, observation.vendor, observation.timestamp.isoformat()))
    db.commit()
