"""Low-impact reflected HTML injection check using inert custom elements.

Only GET query parameters and GET forms are tested. No script tags, event
handlers, state-changing POST submissions, or browser execution are used.
"""

from __future__ import annotations

import secrets
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup

from .base import BaseModule


MAX_CANDIDATES = 4
MAX_BODY = 120_000


class HTMLInjectionDetection(BaseModule):
    name = "HTML Injection Detection"

    def run(self) -> None:
        candidates: List[Tuple[str, str, Dict[str, str]]] = []
        seen = set()

        # Existing same-origin query endpoints discovered by recon/flow.
        for endpoint in list(self.reporter.endpoints):
            if not self.rm.is_same_origin(endpoint):
                continue
            parsed = urlparse(endpoint)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for key, value in pairs:
                if key.lower() in {"csrf", "_token", "token", "auth", "password", "session"}:
                    continue
                signature = (endpoint, key)
                if signature not in seen:
                    seen.add(signature)
                    candidates.append((endpoint, key, dict(pairs)))

        # GET forms are useful even when the action has no query string.
        for form in self.reporter.runtime_context.get("forms", []):
            if form.get("method") != "GET" or not self.rm.is_same_origin(form.get("action", "")):
                continue
            for field in form.get("fields", []):
                name = str(field.get("name") or "")
                kind = str(field.get("type") or "text").lower()
                if not name or kind in {"hidden", "password", "file", "submit", "button"}:
                    continue
                signature = (form["action"], name)
                if signature in seen:
                    continue
                seen.add(signature)
                candidates.append((form["action"], name, {}))

        if not candidates:
            self.log("No safe GET parameter/form candidates found")
            return

        tested = 0
        for endpoint, parameter, base_params in candidates[:MAX_CANDIDATES]:
            if not self.config.can_request() or self.rm.stopped_by_429 or self.rm.stopped_by_overload:
                break
            marker = "ProbeX_HTML_" + secrets.token_hex(4)
            inert_markup = f"<ProbeX-probe>{marker}</ProbeX-probe>"
            params = dict(base_params)
            params[parameter] = inert_markup
            parsed = urlparse(endpoint)
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            if not self.rm.is_same_origin(test_url):
                continue
            response = self.rm.get(test_url, allow_redirects=True)
            tested += 1
            if response is None:
                continue
            body = (response.text or "")[:MAX_BODY]
            if marker not in body:
                continue

            soup = BeautifulSoup(body, "html.parser")
            inserted = soup.find("ProbeX-probe")
            if inserted and inserted.get_text(strip=True) == marker:
                self.log(f"Reflected inert HTML element detected in parameter '{parameter}'")
                evidence = f"{response.url or test_url} parameter={parameter} marker={marker}"
                self.reporter.add_finding(
                    "Reflected HTML Injection (non-script marker)",
                    severity="low",
                    detail=(f"Input parameter '{parameter}' was reflected as an HTML element. "
                            "This test did not execute JavaScript and is not proof of XSS."),
                    evidence=evidence,
                    url=test_url,
                    method="GET",
                    parameter=parameter,
                    evidence_snippet=evidence,
                )
            else:
                self.log(f"Marker reflected in '{parameter}', but HTML element context was not confirmed")

        self.log(f"Checked {tested} bounded GET input(s)")
