"""Lightweight Directory / Path Discovery (safe, limited wordlist)."""
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .base import BaseModule

# Very small, high-value wordlist – never aggressive
COMMON_PATHS = [
    "admin", "login", "api", "api/v1", "api/v2", "swagger", "swagger-ui",
    "docs", "documentation", "graphql", "console", "debug", "status",
    "health", "metrics", "actuator", "robots.txt", "sitemap.xml",
    ".env", ".git/HEAD", "backup", "config", "phpinfo.php", "test",
    "flag", "flags", "secret", "private", "uploads", "static", "assets",
    "wp-admin", "wp-login.php", "administrator", "dashboard",
    "server-status", "server-info", ".well-known/security.txt",
]


class DirectoryDiscovery(BaseModule):
    name = "Directory Discovery"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/") + "/"
        found = []
        lock = threading.Lock()

        def check(path: str):
            if not self.config.can_request() or self.rm.stopped_by_429:
                return None
            url = urljoin(base, path)
            # Do NOT follow redirects – detect protected 3xx endpoints
            resp = self.rm.get(url, allow_redirects=False)
            if resp is None:
                return None
            code = resp.status_code
            if code in (200, 201, 301, 302, 303, 307, 308, 401, 403):
                loc = resp.headers.get("Location", "")
                body = (resp.text or "")[:100_000]
                low = body.lower()
                if code == 200 and any(marker in low for marker in (
                    "<title>index of ", "<h1>index of ", "parent directory", "directory listing for"
                )):
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(body, "html.parser")
                        entries = []
                        for anchor in soup.find_all("a", href=True)[:60]:
                            href = str(anchor.get("href") or "").strip()
                            label = anchor.get_text(" ", strip=True) or href
                            if href and not href.startswith(("?", "#", "javascript:")):
                                entries.append({"name": label[:160], "href": href[:300]})
                    except Exception:
                        entries = []
                    self.reporter.extra.setdefault("public_directory_listings", {})[url] = entries
                    snippet = ", ".join(e["name"] for e in entries[:10])
                    self.reporter.add_finding(
                        "Public directory listing exposed",
                        severity="medium",
                        detail=f"{url} exposes {len(entries)} directory entry link(s) through normal HTTP browsing.",
                        evidence=snippet,
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=snippet,
                    )
                    self.log(f"Public directory listing exposed: {url}", style="yellow")
                    for entry in entries[:15]:
                        self.log(f"    {entry['name']} → {entry['href']}")
                return (url, code, len(resp.content or b""), loc)
            return None

        # Sequential by default (threads=1). Cap workers at config.threads
        workers = min(self.config.threads, 3)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check, p): p for p in COMMON_PATHS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    url, code, size, loc = result
                    with lock:
                        found.append(result)
                        self.reporter.add_endpoint(url)
                        loc_info = f" → {loc}" if loc else ""
                        self.log(f"[{code}] {url} ({size}b){loc_info}")
                        interesting_kw = ("flag", "secret", "admin", "api", ".env", "backup", "private", "internal")
                        if any(k in url.lower() for k in interesting_kw):
                            sev = "medium"
                            detail = f"HTTP {code}, size={size}"
                            if code in (301, 302, 303, 307, 308) and loc:
                                detail += f", redirect to {loc}"
                                sev = "info"
                                self.reporter.add_finding(
                                    f"Protected Endpoint: {url}",
                                    severity=sev,
                                    detail=detail,
                                    url=url,
                                    method="GET",
                                    parameter="",
                                    evidence_snippet=detail,
                                )
                            elif code in (200, 201):
                                self.reporter.add_finding(
                                    f"Interesting Endpoint: {url}",
                                    severity=sev,
                                    detail=detail,
                                    url=url,
                                    method="GET",
                                    parameter="",
                                    evidence_snippet=detail,
                                )
                            elif code in (401, 403):
                                self.reporter.add_finding(
                                    f"Auth-required Endpoint: {url}",
                                    severity="info",
                                    detail=detail,
                                    url=url,
                                    method="GET",
                                    parameter="",
                                    evidence_snippet=detail,
                                )

        self.log(f"Discovered {len(found)} interesting path(s)")
