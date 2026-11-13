"""API endpoint discovery (lightweight)."""
from urllib.parse import urljoin
from .base import BaseModule

API_PATHS = [
    "api",
    "api/",
    "api/v1",
    "api/v2",
    "api/v1/",
    "api/v2/",
    "graphql",
    "graphiql",
    "swagger",
    "swagger.json",
    "swagger-ui",
    "openapi.json",
    "api-docs",
    "v1",
    "v2",
    "rest",
    "json",
]


class APIDiscovery(BaseModule):
    name = "API Discovery"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/") + "/"
        found = 0
        for path in API_PATHS:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            url = urljoin(base, path)
            resp = self.rm.get(url)
            if not resp:
                continue
            if resp.status_code in (200, 201, 401, 403):
                found += 1
                self.reporter.add_endpoint(url)
                ctype = resp.headers.get("Content-Type", "")
                self.log(f"[{resp.status_code}] {url} ({ctype[:40]})")
                if "json" in ctype or "swagger" in path or "openapi" in path:
                    self.reporter.add_finding(
                        f"API Endpoint: {url}",
                        severity="info",
                        detail=f"HTTP {resp.status_code}, Content-Type: {ctype}",
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=f"HTTP {resp.status_code}, Content-Type: {ctype}",
                    )
        self.log(f"API-related endpoints found: {found}")
