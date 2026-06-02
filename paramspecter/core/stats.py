"""
core/stats.py
Runtime state: CrawlStats, CrawlQueue, TokenBucket, ProxyManager.
"""

import queue, time, random, threading
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional


@dataclass
class CrawlStats:
    pages_crawled:    int = 0
    pages_failed:     int = 0
    links_found:      int = 0
    emails_found:     int = 0
    secrets_found:    int = 0
    forms_found:      int = 0
    params_found:     int = 0
    fuzz_hits:        int = 0
    param_hits:       int = 0
    subdomains_found: int = 0
    dir_hits:         int = 0
    requests_sent:    int = 0
    status_codes:     Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    start_time:       datetime = field(default_factory=datetime.now)
    phase_times:      Dict[str, float] = field(default_factory=dict)

    def elapsed(self) -> str:
        secs = int((datetime.now() - self.start_time).total_seconds())
        return f"{secs // 60}m{secs % 60}s"

    def avg_rps(self) -> str:
        secs = max(1, int((datetime.now() - self.start_time).total_seconds()))
        return f"{self.requests_sent / secs:.1f}"

    def record_phase(self, name: str, elapsed_s: float) -> None:
        self.phase_times[name] = round(elapsed_s, 1)


class CrawlQueue:
    def __init__(self, strategy="bfs"):
        self.strategy = strategy
        if strategy == "bfs":
            self._q = queue.Queue()
        elif strategy == "dfs":
            self._q = queue.LifoQueue()
        else:
            self._q = queue.PriorityQueue()

    def put(self, item, priority=0):
        if self.strategy == "priority":
            self._q.put((priority, item))
        else:
            self._q.put(item)

    def get(self, timeout=3):
        raw = self._q.get(timeout=timeout)
        if self.strategy == "priority":
            return raw[1]
        return raw

    def task_done(self):
        self._q.task_done()

    def join(self):
        self._q.join()

    def qsize(self):
        return self._q.qsize()


class TokenBucket:
    def __init__(self, rate: float, capacity: float = None):
        self.rate     = rate
        self.capacity = capacity or rate
        self._tokens  = self.capacity
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            wait = min(1.0 / max(self.rate, 0.001), deadline - time.monotonic())
            if wait <= 0:
                return False
            time.sleep(wait)


_HOST_BUCKET_LIMIT = 512


class ProxyManager:
    def __init__(self, proxy_list: List[str]):
        self.proxies = proxy_list
        self._idx = 0
        self._lock = threading.Lock()

    def next(self) -> Optional[Dict]:
        if not self.proxies:
            return None
        with self._lock:
            p = self.proxies[self._idx % len(self.proxies)]
            self._idx += 1
        return {"http": p, "https": p}
