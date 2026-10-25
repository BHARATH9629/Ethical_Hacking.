import time
import threading
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class RequestEvent:
    access_key: Optional[str]
    service: str
    action: str
    resource: str = ""
    bytes: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)


@dataclass
class Alert:
    severity: str  # INFO, MEDIUM, HIGH, CRITICAL
    type: str
    message: str
    resource: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d["kind"] = "alert"
        return d


WINDOW_SECONDS = 15


class SharedState:
    def __init__(self):
        self._lock = threading.Lock()
        self.canary_keys: set[str] = set()
        self.event_window: deque[RequestEvent] = deque()
        self.alert_history: list[Alert] = []
        self.public_buckets: set[str] = set()
        self._recent_alert_keys: dict[str, float] = {}

    def register_canary(self, access_key: str):
        with self._lock:
            self.canary_keys.add(access_key)

    def add_event(self, event: RequestEvent):
        with self._lock:
            self.event_window.append(event)
            cutoff = time.time() - WINDOW_SECONDS
            while self.event_window and self.event_window[0].timestamp < cutoff:
                self.event_window.popleft()
            return list(self.event_window)

    def set_public_buckets(self, buckets: set[str]):
        with self._lock:
            self.public_buckets = buckets

    def add_alert(self, alert: Alert):
        with self._lock:
            self.alert_history.append(alert)
            if len(self.alert_history) > 200:
                self.alert_history = self.alert_history[-200:]

    def get_history(self):
        with self._lock:
            return list(self.alert_history)

    def should_emit(self, dedupe_key: str, cooldown_seconds: float = 5.0) -> bool:
        """Prevent the same alert type from spamming the feed every poll/event."""
        with self._lock:
            now = time.time()
            last = self._recent_alert_keys.get(dedupe_key)
            if last is not None and now - last < cooldown_seconds:
                return False
            self._recent_alert_keys[dedupe_key] = now
            return True

    def reset(self):
        with self._lock:
            self.event_window.clear()
            self.alert_history.clear()
            self.public_buckets.clear()
            self._recent_alert_keys.clear()
            # canary_keys intentionally kept until re-registered by next seed run


state = SharedState()
