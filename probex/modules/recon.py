"""HTTP Reconnaissance module."""

from urllib.parse import urljoin
from .base import BaseModule


class HTTPRecon(BaseModule):
    name = "HTTP Reconnaissance"

    def run(self) -> None:
        base = self.config.base_url
        resp = self.rm.get(base)
        if not resp:
            self.log("No response from root")
            return

        self.reporter.add_endpoint(base)
        self.log(f"Status: {resp.status_code}")
        self.log(f"Server: {resp.headers.get('Server', 'N/A')}")
        self.log(f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}")
        self.log(f"Content-Length: {resp.headers.get('Content-Length', len(resp.content))}")

        # Basic page title extraction
        try:
            text = resp.text[:5000]
            if "<title>" in text.lower():
                start = text.lower().find("<title>") + 7
                end = text.lower().find("</title>", start)
                if end > start:
                    title = text[start:end].strip()[:80]
                    self.log(f"Title: {title}")
        except Exception:
            pass

        # Check common methods
        for method in ("OPTIONS", "HEAD"):
            if not self.config.can_request():
                break
            r = self.rm.request(method, base)
            if r and r.status_code < 400:
                allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods")
                if allow:
                    self.log(f"{method} allowed: {allow}")
                    self.reporter.add_finding(
                        f"HTTP Method {method} supported",
                        severity="info",
                        detail=allow,
                        url=base,
                        method=method,
                        parameter="",
                        evidence_snippet=allow,
                    )
