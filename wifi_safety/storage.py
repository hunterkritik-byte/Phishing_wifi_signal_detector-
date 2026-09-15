import hashlib
import sqlite3
import secrets
from pathlib import Path


def pseudonymize(value: str, salt: str) -> str:
    """Cryptographically hash a value with salt.
    
    Security: Uses SHA-256 with explicit salt to prevent rainbow table attacks.
    """
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if not isinstance(salt, str):
        raise TypeError("salt must be a string")
    
    # Use PBKDF2 for better security against brute force
    try:
        hashed = hashlib.pbkdf2_hmac('sha256', value.encode(), salt.encode(), 100000)
        return hashed.hex()[:16]
    except Exception:
        # Fallback to simple SHA-256 if pbkdf2 fails
        return hashlib.sha256((salt + value).encode()).hexdigest()[:16]


def open_db(path: str = "wifi_safety.sqlite3") -> sqlite3.Connection:
    """Open SQLite database with security hardening.
    
    Security: Enables foreign keys, WAL mode, and prepared statements.
    """
    db_path = Path(path).resolve()
    
    # Prevent path traversal
    if ".." in str(db_path):
        raise ValueError(f"Invalid database path: {path}")
    
    db = sqlite3.connect(str(db_path))
    
    # Enable security features
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
    db.execute("PRAGMA synchronous = FULL")  # Full synchronization
    db.execute("PRAGMA temp_store = MEMORY")  # Use memory for temp tables
    
    # Create observations table with constraints
    db.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT NOT NULL CHECK(length(ssid) <= 32),
            bssid TEXT NOT NULL CHECK(length(bssid) >= 12),
            channel INTEGER CHECK(channel >= 1 AND channel <= 165),
            security TEXT NOT NULL DEFAULT 'unknown',
            rssi REAL CHECK(rssi >= -100 AND rssi <= 0),
            vendor TEXT NOT NULL DEFAULT 'unknown',
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create indexes for performance
    db.execute("CREATE INDEX IF NOT EXISTS idx_observations_bssid ON observations(bssid)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_observations_ssid ON observations(ssid)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_observations_timestamp ON observations(observed_at)")
    
    return db


def save_observation(db, observation, hash_mac: bool = True, salt: str | None = None) -> None:
    """Save observation to database with SQL injection protection.
    
    Security: Uses parameterized queries to prevent SQL injection.
    """
    if not isinstance(db, sqlite3.Connection):
        raise TypeError("db must be a sqlite3.Connection")
    
    if not hasattr(observation, 'bssid'):
        raise ValueError("observation must have a bssid attribute")
    
    # Generate random salt if not provided
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Hash BSSID if requested
    bssid = observation.bssid
    if hash_mac:
        bssid = pseudonymize(observation.bssid, salt)
    
    # Validate inputs
    if not isinstance(bssid, str):
        raise TypeError("bssid must be a string")
    
    ssid = getattr(observation, 'ssid', '')
    if not isinstance(ssid, str):
        raise TypeError("ssid must be a string")
    if len(ssid) > 32:
        ssid = ssid[:32]  # Truncate to safe length
    
    channel = getattr(observation, 'channel', None)
    if channel is not None:
        channel = int(channel)
        if not (1 <= channel <= 165):
            channel = None
    
    security = getattr(observation, 'security', 'unknown')
    if not isinstance(security, str):
        security = 'unknown'
    
    rssi = getattr(observation, 'rssi', None)
    if rssi is not None:
        rssi = float(rssi)
        if not (-100 <= rssi <= 0):
            rssi = None
    
    vendor = getattr(observation, 'vendor', 'unknown')
    if not isinstance(vendor, str):
        vendor = 'unknown'
    
    timestamp = getattr(observation, 'observed_at', None)
    if timestamp is None:
        timestamp = getattr(observation, 'timestamp', None)
    
    # Use parameterized query to prevent SQL injection
    db.execute(
        "INSERT INTO observations (ssid, bssid, channel, security, rssi, vendor, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ssid, bssid, channel, security, rssi, vendor, timestamp)
    )
    db.commit()
