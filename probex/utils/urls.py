"""URL / endpoint helper — diekstrak dari boilerplate yang sama di tiap modul."""

from __future__ import annotations

from typing import Iterable, List, Optional


def discover_endpoints(reporter, base_url: str, extra: Optional[Iterable[str]] = None) -> List[str]:
    """Kumpulkan endpoint dari reporter.endpoints + base_url (+ opsional extra),
    deduplikasi sambil mempertahankan urutan pertama kali muncul.

    Tidak memfilter http/https di sini — biarkan setiap modul sendiri
    menentukan filter-nya (beberapa butuh path file, yang lain butuh URL lengkap).
    """
    collected: List[str] = []
    if hasattr(reporter, "endpoints"):
        collected.extend(reporter.endpoints)
    collected.append(base_url)
    if extra:
        for item in extra:
            if item:
                collected.append(item)

    seen = set()
    out: List[str] = []
    for ep in collected:
        if ep in seen:
            continue
        seen.add(ep)
        out.append(ep)
    return out


def http_only(urls: List[str]) -> List[str]:
    """Hanya URL yang dimulai http:// atau https://."""
    return [u for u in urls if u.startswith(("http://", "https://"))]


def same_origin(urls: List[str], base_url: str) -> List[str]:
    """Hanya URL yang skema + host + port-nya sama dengan base_url."""
    from urllib.parse import urlparse

    base = urlparse(base_url)
    base_key = (
        base.scheme,
        base.hostname,
        base.port or (443 if base.scheme == "https" else 80),
    )
    out: List[str] = []
    for u in urls:
        if not u.startswith(("http://", "https://")):
            continue
        p = urlparse(u)
        if (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)) == base_key:
            out.append(u)
    return out
