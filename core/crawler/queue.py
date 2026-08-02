"""
Breadth-first crawl queue with depth tracking (SOP v4.0 Phase 2 — Advanced
Smart Crawling).

Unlike the legacy recursive crawler, the new engine uses an explicit queue so
depth limits, graceful budget cutoffs and a bounded, non-recursive expansion are
trivial. A ``set`` of enqueued URLs prevents the same candidate being pushed
twice.
"""

from __future__ import annotations

from collections import deque
from typing import Optional, Tuple, Tuple


class CrawlQueue:
    def __init__(self, max_depth: Optional[int] = None):
        self.max_depth = max_depth
        self._queue = deque()
        self._enqueued = set()

    def reset(self) -> None:
        self._queue.clear()
        self._enqueued.clear()

    def add(self, url: str, depth: int) -> bool:
        """Queue ``url`` at ``depth`` (depth limit applied). Returns False if
        rejected (duplicate or beyond depth limit)."""
        if self.max_depth is not None and depth > self.max_depth:
            return False
        if url in self._enqueued:
            return False
        self._enqueued.add(url)
        self._queue.append((url, depth))
        return True

    def pop(self) -> Optional[Tuple[str, int]]:
        if not self._queue:
            return None
        return self._queue.popleft()

    @property
    def empty(self) -> bool:
        return not self._queue

    def __len__(self) -> int:
        return len(self._queue)