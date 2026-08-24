import hashlib


def anonymize_identifier(value: str, salt: str = "") -> str:
    """Return a stable local identifier without exposing the original value."""
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()[:16]
