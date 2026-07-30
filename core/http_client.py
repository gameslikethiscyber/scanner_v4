"""
HTTP Client with request tracking and response caching.
"""

import time
import threading
from collections import OrderedDict
from typing import Optional, Dict, Any, Tuple
import requests


class TrackedSession(requests.Session):
    def __init__(self, config: Optional['ScanConfig'] = None):
        super().__init__()
        self.request_count = 0
        self._lock = threading.Lock()
        if config:
            self._apply_config(config)

    def _apply_config(self, config: 'ScanConfig'):
        if config.headers:
            self.headers.update(config.headers)
        for cookie in getattr(config, 'cookies', []):
            name = cookie.get('name', '')
            value = cookie.get('value', '')
            domain = cookie.get('domain', '')
            if name and value:
                self.cookies.set(name, value, domain=domain)

    def request(self, method, url, **kwargs):
        with self._lock:
            self.request_count += 1
        return super().request(method, url, **kwargs)


class ResponseCache:
    def __init__(self, max_size: int = 200, ttl: int = 60):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, Tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def _make_key(self, method: str, url: str, params: Optional[Dict] = None,
                  data: Optional[Dict] = None) -> str:
        return f"{method}:{url}:{params}:{data}"

    def get(self, method: str, url: str, params: Optional[Dict] = None,
            data: Optional[Dict] = None) -> Optional[Any]:
        key = self._make_key(method, url, params, data)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            timestamp, response = entry
            if time.time() - timestamp > self.ttl:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return response

    def set(self, method: str, url: str, response: Any,
            params: Optional[Dict] = None, data: Optional[Dict] = None):
        key = self._make_key(method, url, params, data)
        with self._lock:
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            self._cache[key] = (time.time(), response)

    def invalidate(self, url: Optional[str] = None):
        with self._lock:
            if url is None:
                self._cache.clear()
            else:
                keys_to_delete = [k for k in self._cache if url in k]
                for k in keys_to_delete:
                    del self._cache[k]
