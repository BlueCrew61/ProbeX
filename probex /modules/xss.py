"""Safe reflected XSS detection (non-destructive)."""

from urllib.parse import quote
from .base import BaseModule

# Unique marker that is harmless
MARKER = "ProbeX_xss_1337"
PAYLOADS = [
    f"<script>/*{MARKER}*/</script>",
    f"\"><img src=x onerror=/*{MARKER}*/>",
    f"{MARKER}",
]


class XSSDetection(BaseModule):
    name = "XSS Detection"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        tested = 0

        for payload in PAYLOADS:
            if not self.config.can_request() or tested >= 6:
                break
            # Reflect in a query parameter
            url = f"{base}/?q={quote(payload)}&search={quote(payload)}"
            resp = self.rm.get(url)
            tested += 1
            if not resp:
                continue

            body = resp.text or ""
            if MARKER in body and payload in body:
                # Simple reflection check
                self.log("Possible reflected XSS (payload reflected)")
                self.reporter.add_finding(
                    "Possible Reflected XSS (unconfirmed)",
                    severity="medium",
                    detail="Payload reflected in response body",
                    evidence=payload[:80],
                    url=url,
                    method="GET",
                    parameter="q",
                    evidence_snippet=payload,
                )
                return

        self.log("No obvious reflected XSS indicators")
