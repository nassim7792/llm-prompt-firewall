"""Per-client rate limiting for the proxy, by request count AND by analysis cost.

Counting requests alone is not enough: one 50 000-character request with stacked encodings
costs far more to normalise than a short question. Each client therefore has two token
buckets, refilled continuously:
  * requests per minute
  * characters per minute (proxy for the CPU cost of the normalisation closure)

The client key is the verified principal id when there is one, otherwise the source address.
State is in memory (one process) and bounded: the least recently seen clients are evicted.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, requests_per_minute: int | None = None, chars_per_minute: int | None = None,
                 max_clients: int = 10_000, clock: Callable[[], float] = time.monotonic):
        self.rpm, self.cpm = requests_per_minute, chars_per_minute
        self.max_clients = max_clients
        self.clock = clock
        self._buckets: OrderedDict[tuple[str, str], _Bucket] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.rpm or self.cpm)

    def _take(self, key: tuple[str, str], capacity: int, amount: float, now: float) -> float:
        """Returns 0 if the tokens were taken, otherwise the seconds to wait."""
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket(float(capacity), now)
            self._buckets[key] = b
        rate = capacity / 60.0
        b.tokens = min(float(capacity), b.tokens + (now - b.updated) * rate)
        b.updated = now
        self._buckets.move_to_end(key)
        while len(self._buckets) > self.max_clients:
            self._buckets.popitem(last=False)
        if amount > capacity:                    # can never fit: refuse, retry is pointless
            return float("inf")
        if b.tokens >= amount:
            b.tokens -= amount
            return 0.0
        return (amount - b.tokens) / rate

    def check(self, client: str, cost_chars: int) -> tuple[bool, str | None, float]:
        """(allowed, reason, retry_after_seconds). Nothing is consumed when refused."""
        if not self.enabled:
            return True, None, 0.0
        with self._lock:
            now = self.clock()
            snapshot = {k: _Bucket(b.tokens, b.updated) for k, b in self._buckets.items() if k[0] == client}
            if self.rpm:
                wait = self._take((client, "req"), self.rpm, 1, now)
                if wait:
                    self._restore(client, snapshot)
                    return False, "requests", wait
            if self.cpm:
                wait = self._take((client, "chars"), self.cpm, cost_chars, now)
                if wait:
                    self._restore(client, snapshot)
                    return False, "analysis_cost", wait
            return True, None, 0.0

    def _restore(self, client: str, snapshot: dict[tuple[str, str], _Bucket]) -> None:
        for kind in ("req", "chars"):
            key = (client, kind)
            if key in snapshot:
                self._buckets[key] = snapshot[key]
            else:
                self._buckets.pop(key, None)
