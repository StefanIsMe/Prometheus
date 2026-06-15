"""Rate limiter for outgoing HTTP requests in prometheus."""

from __future__ import annotations

import re
import threading
import time
from collections import deque


# Default: 3 requests per second through Tor (exit nodes get rate-limited)
# Original: 5 req/s for direct connections
# Stefan wants exhaustive research - increase to 50 req/s
DEFAULT_RATE = 50  # requests per second (Stefan wants no limits)
DEFAULT_BURST = 50  # max concurrent (Stefan wants no limits)


class RateLimiter:
    """Token bucket rate limiter for HTTP requests."""

    def __init__(self, rate: float = DEFAULT_RATE, burst: int = DEFAULT_BURST):
        self.rate = rate
        self.burst = burst
        self._lock = threading.Lock()
        self._timestamps: deque[float] = deque()
        self._window = 1.0  # 1 second window

    def acquire(self) -> float:
        """Wait until a request slot is available. Returns wait time in seconds."""
        waited = 0.0
        with self._lock:
            now = time.monotonic()
            # Purge old timestamps outside the window
            while self._timestamps and self._timestamps[0] <= now - self._window:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.rate:
                # Need to wait until the oldest request expires
                sleep_until = self._timestamps[0] + self._window
                wait_time = sleep_until - now
                if wait_time > 0:
                    waited = wait_time
                    # Release lock during sleep
                    self._lock.release()
                    time.sleep(wait_time)
                    self._lock.acquire()
                    # Purge again after sleep
                    now = time.monotonic()
                    while self._timestamps and self._timestamps[0] <= now - self._window:
                        self._timestamps.popleft()

            self._timestamps.append(time.monotonic())
            return waited


# Global rate limiter instance
_limiter = RateLimiter(rate=DEFAULT_RATE, burst=DEFAULT_BURST)

# Patterns that indicate HTTP requests to targets
_HTTP_CMD_PATTERNS = [
    re.compile(r"\bcurl\b"),
    re.compile(r"\bwget\b"),
    re.compile(r"\bhttpx\b"),
    re.compile(r"\bnuclei\b"),
    re.compile(r"\bpython3?\b.*\brequests\b"),
    re.compile(r"\bpython3?\b.*\bhttpx\b"),
    re.compile(r"\bpython3?\b.*\burllib\b"),
    re.compile(r"\bpython3?\b.*\baiohttp\b"),
    re.compile(r"\bffuf\b"),
    re.compile(r"\bgobuster\b"),
    re.compile(r"\bdirb\b"),
    re.compile(r"\bnikto\b"),
    re.compile(r"\bsqlmap\b"),
    re.compile(r"\bhydra\b"),
    re.compile(r"\bmedusa\b"),
    re.compile(r"\bnc\b.*-[vez]"),  # netcat with HTTP-like flags
    re.compile(r"\bncat\b"),
]


def is_http_command(cmd: str) -> bool:
    """Check if a shell command is likely an HTTP request to a target."""
    # Skip commands that are clearly not HTTP requests (tool installs, file ops, etc.)
    skip_patterns = [
        r"\bapt\b",
        r"\bapt-get\b",
        r"\bpip\b",
        r"\bpip3\b",
        r"\bdnf\b",
        r"\byum\b",
        r"\bsnap\b",
        r"\bcat\b",
        r"\becho\b",
        r"\bgrep\b",
        r"\bsed\b",
        r"\bawk\b",
        r"\bls\b",
        r"\bmkdir\b",
        r"\bcp\b",
        r"\bmv\b",
        r"\brm\b",
        r"\bchmod\b",
        r"\bchown\b",
        r"\btar\b",
        r"\bunzip\b",
        r"\bgunzip\b",
        r"\bgit\b",
        r"\bmake\b",
        r"\bgo\b",
        r"\bcargo\b",
        r"\bnmap\b.*-[sS]\b",  # nmap SYN scan is network but not HTTP
        r"\bwhois\b",
        r"\bdig\b",
        r"\bhost\b",
        r"\bnslookup\b",
        r"\bping\b",
        r"\btraceroute\b",
        r"\bmtr\b",
        r"\bhead\b",
        r"\btail\b",
        r"\bwc\b",
        r"\bfile\b",
        r"\bwhich\b",
        r"\bwhereis\b",
        r"\bfind\b",
        r"\blocate\b",
        r"\bps\b",
        r"\bkill\b",
        r"\btop\b",
        r"\bhtop\b",
        r"\benv\b",
        r"\bexport\b",
        r"\bset\b",
        r"\bunset\b",
        r"\btype\b",
        r"\bcommand\b",
        r"\btee\b",
        r"\bxargs\b",
    ]
    for pat in skip_patterns:
        if re.search(pat, cmd):
            return False

    return any(pat.search(cmd) for pat in _HTTP_CMD_PATTERNS)


def maybe_rate_limit(cmd: str) -> float:
    """Rate-limit if the command is an HTTP request. Returns wait time (0 if not limited)."""
    if _limiter.rate <= 0:
        return 0.0
    if is_http_command(cmd):
        return _limiter.acquire()
    return 0.0


def set_rate(rate: float) -> None:
    """Update the rate limit (requests per second)."""
    global _limiter
    _limiter = RateLimiter(rate=rate, burst=int(rate))


def get_rate() -> float:
    """Get current rate limit."""
    return _limiter.rate
