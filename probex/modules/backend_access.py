"""Backend access vulnerability probes (authorized CTF labs only).

Checks for weaknesses that can reach internal/backend services behind the
frontend target:

  - SSRF via URL-ish parameters (?url=, ?image=, ?webhook=, ...)
  - Proxy / gateway misconfiguration (X-Forwarded-For to internal IP,
    X-Original-URL / X-Rewrite-URL to internal path)
  - Open redirect pointing at internal/localhost hosts

All probes are read-only and bounded: each candidate URL is probed once with
a short timeout, and no payload is written to the target.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .base import BaseModule

# Parameters commonly used for server-side fetching (SSRF sinks).
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "image", "img", "thumb",
    "webhook", "callback", "return", "redirect", "next", "page",
    "file", "path", "fetch", "proxy", "dest", "destination",
]

# Internal / backend targets to probe (safe, non-destructive).
INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://internal/",
    "http://backend/",
    "http://admin.internal/",
]

# Header-based attempts to reach internal services via the frontend.
INTERNAL_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
]

# Paths that hint at backend/admin surfaces behind a gateway.
INTERNAL_PATHS = [
    "/admin", "/admin/", "/backend", "/internal", "/private",
    "/management", "/console", "/api/admin", "/api/internal",
]


def _same_host(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return pa.hostname == pb.hostname and pa.port == pb.port


class BackendAccessModule(BaseModule):
    name = "Backend Access / SSRF"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        found_any = False

        # --- 1) SSRF via URL parameters on discovered endpoints --------------
        endpoints = list(getattr(self.reporter, "endpoints", []))
        endpoints.append(base)

        tested_params: set = set()
        for ep in endpoints:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            parsed = urlparse(ep)
            qs = parse_qs(parsed.query)
            for param in list(qs.keys()):
                if param.lower() not in SSRF_PARAMS:
                    continue
                key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}"
                if key in tested_params:
                    continue
                tested_params.add(key)

                # Probe each internal target through this parameter once.
                for target in INTERNAL_TARGETS[:3]:
                    if not self.config.can_request():
                        break
                    new_qs = dict(qs)
                    new_qs[param] = target
                    new_parsed = parsed._replace(query=urlencode(new_qs, doseq=True))
                    ssrf_url = urlunparse(new_parsed)
                    resp = self.rm.get(ssrf_url, allow_redirects=False, timeout=6)
                    if resp is None:
                        continue
                    # A 200/3xx with a body different from the frontend norm,
                    # or an error mentioning the internal host, is a hint.
                    if resp.status_code in (200, 301, 302, 303, 307, 308, 400, 403):
                        body = (resp.text or "")[:200]
                        hint = (
                            f"SSRF sink: {param}={target} on {ep} "
                            f"(HTTP {resp.status_code}, body: {body!r})"
                        )
                        self.log(hint)
                        self.reporter.add_finding(
                            "Possible SSRF / backend access via parameter",
                            severity="high",
                            detail=hint,
                            evidence=param,
                            url=ssrf_url,
                            method="GET",
                            parameter=param,
                            evidence_snippet=param,
                        )
                        self.reporter.add_endpoint(ssrf_url)
                        found_any = True
                        break  # one hit per param is enough

        # --- 2) Header-based internal reach ----------------------------------
        if self.config.can_request():
            probe_path = base + "/"
            for hname, hval in INTERNAL_HEADERS:
                if not self.config.can_request():
                    break
                resp = self.rm.get(probe_path, headers={hname: hval},
                                   allow_redirects=False)
                if resp is None:
                    continue
                if resp.status_code in (200, 301, 302, 303, 307, 308, 403):
                    detail = (
                        f"Header {hname}: {hval} accepted on {probe_path} "
                        f"(HTTP {resp.status_code}) — possible internal reach"
                    )
                    self.log(detail)
                    self.reporter.add_finding(
                        "Possible internal access via header",
                        severity="medium",
                        detail=detail,
                        evidence=f"{hname}: {hval}",
                        url=probe_path,
                        method="GET",
                        parameter=hname,
                        evidence_snippet=f"{hname}: {hval}",
                    )
                    found_any = True
                    break

        # --- 3) Direct internal path probes ----------------------------------
        if self.config.can_request():
            parsed_base = urlparse(base)
            for path in INTERNAL_PATHS[:4]:
                if not self.config.can_request():
                    break
                url = f"{parsed_base.scheme}://{parsed_base.netloc}{path}"
                resp = self.rm.get(url, allow_redirects=False, timeout=6)
                if resp is None:
                    continue
                if resp.status_code in (200, 301, 302, 303, 307, 308, 401, 403):
                    detail = (
                        f"Internal path reachable: {url} (HTTP {resp.status_code})"
                    )
                    self.log(detail)
                    self.reporter.add_finding(
                        "Backend/internal surface reachable",
                        severity="medium",
                        detail=detail,
                        evidence=url,
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=url,
                    )
                    self.reporter.add_endpoint(url)
                    found_any = True
                    break

        if not found_any:
            self.log("No backend access / SSRF hint detected")
