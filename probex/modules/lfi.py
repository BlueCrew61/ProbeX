"""Safe LFI / path traversal detection (read-only, common files only)."""

from urllib.parse import quote
from .base import BaseModule

# Only well-known non-sensitive files for detection
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "file:///etc/passwd",
]

PASSWD_SIGS = ["root:x:0:0", "root:x:0:0:root"]


class LFIDetection(BaseModule):
    name = "LFI Detection"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        params = ["file", "page", "path", "include", "doc", "template"]

        for param in params:
            if not self.config.can_request():
                break
            for payload in TRAVERSAL_PAYLOADS:
                if not self.config.can_request():
                    break
                url = f"{base}/?{param}={quote(payload)}"
                resp = self.rm.get(url)
                if not resp:
                    continue
                body = resp.text or ""
                for sig in PASSWD_SIGS:
                    if sig in body:
                        self.log("Possible LFI: /etc/passwd content detected")
                        self.reporter.add_finding(
                            "Possible LFI / Path Traversal (unconfirmed)",
                            severity="high",
                            detail=f"Parameter '{param}' appears vulnerable",
                            evidence=payload,
                            url=url,
                            method="GET",
                            parameter=param,
                            evidence_snippet=payload,
                        )
                        return
        self.log("No LFI indicators detected")
