"""Input validation and target parsing helpers."""

import re
import ipaddress
from typing import Optional, Tuple
from urllib.parse import urlparse


def validate_ip(ip: str) -> bool:
    """Accept IPv4, IPv6, or hostname (basic)."""
    if not ip or len(ip) > 253:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        pass
    if re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
        ip,
    ):
        return True
    return False


def validate_port(port: int) -> bool:
    return 1 <= port <= 65535


def parse_modules(module_str: str) -> list:
    if not module_str:
        return []
    return [m.strip().lower() for m in module_str.split(",") if m.strip()]


def looks_like_url(value: str) -> bool:
    """Heuristic: does this look like a URL rather than a bare IP/hostname?"""
    if not value:
        return False
    lower = value.lower()
    if lower.startswith(("http://", "https://")):
        return True
    # host:port or host/path
    if "/" in value or (":" in value and not _is_pure_ipv6(value)):
        return True
    return False


def _is_pure_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def parse_target(
    target: str,
    port: Optional[int] = None,
    force_https: bool = False,
) -> Tuple[str, int, bool, str]:
    """
    Parse target into (host, port, use_https, base_url).

    Accepts:
      - Full URL:  http://example.com:8080/path
      - Host:port: example.com:8080
      - Host only: example.com  (port defaults to 80/443)
      - IP + separate port argument

    Returns:
      (hostname, port, use_https, base_url_without_trailing_slash)
    """
    raw = target.strip()
    use_https = force_https
    path = ""

    # Ensure scheme for urlparse when missing
    if not raw.lower().startswith(("http://", "https://")):
        # host:port or host/path
        if ":" in raw and not _is_pure_ipv6(raw):
            # Could be host:port or already has path
            pass
        scheme = "https" if force_https else "http"
        raw_for_parse = f"{scheme}://{raw}"
    else:
        raw_for_parse = raw
        if raw.lower().startswith("https://"):
            use_https = True

    parsed = urlparse(raw_for_parse)

    host = parsed.hostname
    if not host:
        raise ValueError(f"Cannot extract hostname from target: {target}")

    # Port resolution
    if parsed.port:
        resolved_port = parsed.port
    elif port is not None:
        resolved_port = port
    else:
        resolved_port = 443 if use_https else 80

    if not validate_port(resolved_port):
        raise ValueError(f"Invalid port: {resolved_port}")

    # Path (keep non-root path if present)
    path = parsed.path or ""
    if path == "/":
        path = ""

    # Build base URL (no trailing slash unless path is present)
    scheme = "https" if use_https else "http"
    if (use_https and resolved_port == 443) or (not use_https and resolved_port == 80):
        netloc = host
    else:
        netloc = f"{host}:{resolved_port}"

    base_url = f"{scheme}://{netloc}{path}".rstrip("/")
    if not path:
        # keep clean root
        base_url = f"{scheme}://{netloc}"

    return host, resolved_port, use_https, base_url
