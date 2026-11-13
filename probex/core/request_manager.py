"""Centralized HTTP request manager with global budget, delay, and safety."""

import time
import threading
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Config


class RequestManager:
    """Thread-safe request manager enforcing global request budget and rate limits."""

    def __init__(self, config: Config):
        self.config = config
        self._lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._next_request_at = 0.0
        self.session = self._build_session()
        self.total_requests = 0
        self.last_status_codes: list = []
        self.stopped_by_429 = False
        self.stopped_by_overload = False

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        })
        # Limited retries, no aggressive retry on 429
        # Keep retries disabled so every network attempt is accounted for by
        # the global request budget. The scanner stops cleanly on rate limits.
        retry = Retry(total=0, connect=0, read=0, redirect=0, status=0)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=2, pool_maxsize=2)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def is_same_origin(self, url: str) -> bool:
        """Return True only for the exact target origin (scheme/host/port)."""
        try:
            target = urlparse(self.config.base_url)
            candidate = urlparse(url)
            if not target.scheme or not target.hostname or not candidate.scheme or not candidate.hostname:
                return False
            target_port = target.port or (443 if target.scheme.lower() == "https" else 80)
            candidate_port = candidate.port or (443 if candidate.scheme.lower() == "https" else 80)
            return (
                target.scheme.lower() == candidate.scheme.lower()
                and target.hostname.rstrip(".").lower() == candidate.hostname.rstrip(".").lower()
                and target_port == candidate_port
                and candidate.username is None
                and candidate.password is None
            )
        except (TypeError, ValueError):
            return False

    def _reserve_request(self) -> bool:
        with self._lock:
            if self.stopped_by_429 or self.stopped_by_overload:
                return False
            if not self.config.consume_request():
                return False
            self.total_requests += 1
            return True

    def _pace(self) -> None:
        """Apply a process-wide minimum gap, even when a module uses threads."""
        with self._rate_lock:
            now = time.monotonic()
            wait_for = max(0.0, self._next_request_at - now)
            if wait_for:
                time.sleep(wait_for)
            self._next_request_at = time.monotonic() + self.config.delay

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
        stream: bool = False,
    ) -> Optional[requests.Response]:
        """Perform a single HTTP request under global budget and safety rules."""
        if not self._reserve_request():
            return None

        timeout = timeout or self.config.timeout
        self._pace()

        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                allow_redirects=False,  # We control redirects
                timeout=timeout,
                stream=stream,
            )

            # Handle limited redirects manually to stay in scope
            redirect_count = 0
            while (
                allow_redirects
                and resp.is_redirect
                and redirect_count < self.config.max_redirects
            ):
                location = resp.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(resp.url, location)
                if not self.is_same_origin(next_url):
                    # Out of scope – stop following
                    break
                if not self._reserve_request():
                    break
                self._pace()
                resp = self.session.request(
                    method="GET" if resp.status_code in (301, 302, 303) else method.upper(),
                    url=next_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=timeout,
                    stream=stream,
                )
                redirect_count += 1

            # Detect overload
            if resp.status_code == 429:
                with self._lock:
                    self.stopped_by_429 = True
                    self.last_status_codes.append(429)
                return resp
            if resp.status_code == 503:
                with self._lock:
                    self.stopped_by_overload = True
                    self.last_status_codes.append(503)
                return resp

            with self._lock:
                self.last_status_codes.append(resp.status_code)
                if len(self.last_status_codes) > 20:
                    self.last_status_codes.pop(0)

            # Limit body size
            if not stream and resp.content and len(resp.content) > self.config.max_response_size:
                # Truncate content in memory for safety
                resp._content = resp.content[: self.config.max_response_size]

            return resp

        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "remaining_budget": self.config.remaining_requests(),
                "stopped_by_429": self.stopped_by_429,
                "stopped_by_overload": self.stopped_by_overload,
            }
