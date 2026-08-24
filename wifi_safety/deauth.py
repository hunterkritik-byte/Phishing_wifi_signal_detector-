from collections import defaultdict, deque
from time import monotonic


class ManagementFloodDetector:
    """Passive detector for local deauth/disassociation bursts."""
    def __init__(self, window_seconds: float = 5.0, threshold: int = 25):
        self.window = window_seconds
        self.threshold = threshold
        self.events = defaultdict(deque)

    def observe(self, bssid: str, frame_type: str, timestamp: float | None = None) -> bool:
        if frame_type not in {"deauth", "disassoc"}:
            return False
        now = monotonic() if timestamp is None else timestamp
        q = self.events[bssid]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q) >= self.threshold
