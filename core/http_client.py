"""
HTTP Client with request tracking, rate limiting, SSL verification, and response caching.
"""

import time
import threading
import certifi
from collections import OrderedDict
from datetime import datetime
from functools import wraps
from typing import Optional, Dict, Any, Tuple, List

import requests

# Rate limiter pools into the existing module namespace so it can also be imported
# standalone by other components that don't own a TrackedSession (e.g. standalone
# requests-based helpers).


class RateLimiter:
    def __init__(self, max_requests: int = 10, period: float = 1.0):
        self.max_requests = max_requests
        self.period = period
        self.requests: List[float] = []
        self.lock = threading.Lock()

    def wait_if_needed(self):
        with self.lock:
            now = time.time()
            self.requests = [t for t in self.requests if now - t < self.period]

            if len(self.requests) >= self.max_requests:
                sleep_time = self.period - (now - self.requests[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)

            self.requests.append(time.time())


# Global rate limiter instance — shared across all TrackedSession instances
# so the cap applies process-wide.
_rate_limiter = RateLimiter(max_requests=10, period=1.0)


def rate_limited_request(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        _rate_limiter.wait_if_needed()
        return func(*args, **kwargs)
    return wrapper


# SSL-verified session
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context

    _SSL_CONTEXT = create_urllib3_context()
    _SSL_CONTEXT.set_ciphers('DEFAULT@SECLEVEL=2')
except Exception:
    _SSL_CONTEXT = None


class SecureSession(requests.Session):
    def __init__(self, verify_ssl: bool = True):
        super().__init__()
        self.verify = verify_ssl

        if verify_ssl:
            self.verify = certifi.where()
            if _SSL_CONTEXT is not None:
                try:
                    ctx = create_urllib3_context()
                    ctx.set_ciphers('DEFAULT@SECLEVEL=2')
                    adapter = HTTPAdapter(ssl_context=ctx)
                    self.mount('https://', adapter)
                except Exception:
                    pass


class TrackedSession(requests.Session):
    def __init__(self, config: Optional['ScanConfig'] = None):
        super().__init__()
        self.request_count = 0
        self._lock = threading.Lock()
        self.auth = None
        self.classify_responses = False
        self.response_classifications: List[Dict[str, Any]] = []
        self.ssl_errors: List[Dict[str, Any]] = []
        self._verify_ssl = True

        if config:
            self._apply_config(config)

    def _apply_config(self, config: 'ScanConfig'):
        rps = getattr(config, 'max_requests_per_second', None)
        if rps is not None:
            global _rate_limiter
            _rate_limiter = RateLimiter(max_requests=rps, period=1.0)

        self._verify_ssl = getattr(config, 'verify_ssl', True)

        if config.headers:
            self.headers.update(config.headers)
        for cookie in getattr(config, 'cookies', []):
            name = cookie.get('name', '')
            value = cookie.get('value', '')
            domain = cookie.get('domain', '')
            if name and value:
                if domain:
                    self.cookies.set(name, value, domain=domain)
                else:
                    self.cookies.set(name, value)
        auth = getattr(config, 'auth', None)
        if auth is not None:
            self.auth = auth
            try:
                self.auth.apply_to(self)
            except Exception:
                pass

    @rate_limited_request
    def get(self, url, **kwargs):
        with self._lock:
            self.request_count += 1
        if 'verify' not in kwargs and self._verify_ssl is False:
            kwargs['verify'] = False
        try:
            return super().get(url, **kwargs)
        except requests.exceptions.SSLError as e:
            self._record_ssl_error(url, e)
            raise

    @rate_limited_request
    def post(self, url, **kwargs):
        with self._lock:
            self.request_count += 1
        if 'verify' not in kwargs and self._verify_ssl is False:
            kwargs['verify'] = False
        try:
            return super().post(url, **kwargs)
        except requests.exceptions.SSLError as e:
            self._record_ssl_error(url, e)
            raise

    def request(self, method, url, **kwargs):
        _rate_limiter.wait_if_needed()
        with self._lock:
            self.request_count += 1
        if 'verify' not in kwargs and self._verify_ssl is False:
            kwargs['verify'] = False
        if self.auth is not None:
            try:
                self.auth.apply_to(self)
            except Exception:
                pass
        try:
            response = super().request(method, url, **kwargs)
        except requests.exceptions.SSLError as e:
            self._record_ssl_error(url, e)
            raise
        if self.auth is not None:
            try:
                self.auth.update_from_response(response)
            except Exception:
                pass
        if self.classify_responses:
            try:
                from core.auth_manager import classify_auth_response
                self.response_classifications.append(classify_auth_response(url, response))
            except Exception:
                pass
        return response

    def _record_ssl_error(self, url: str, error: Exception):
        self.ssl_errors.append({
            'url': url,
            'error': str(error),
            'timestamp': datetime.now().isoformat()
        })


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