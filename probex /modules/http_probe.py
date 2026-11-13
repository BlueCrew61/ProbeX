"""HTTP probing of hosts (httpx-style).

Takes subdomains from reporter.extra['subdomains'] (or single target)
and probes http/https for live services, titles, status, tech hints.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from urllib.parse import urlparse
import re

from .base import BaseModule


class HTTPProbe(BaseModule):
    name = "HTTP Probe (httpx)"

    def run(self) -> None:
        hosts = self.reporter.extra.get("subdomains") or [self.config.target_ip]
        # Clean hosts
        clean = []
        for h in hosts:
            h = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if h and h not in clean:
                clean.append(h)

        host_cap = 8 if self.config.low_impact else 15
        clean = clean[:host_cap]
        self.log(f"Probing {len(clean)} host(s) (cap={host_cap}) ...")
        live: List[Dict[str, Any]] = []
        workers = min(self.config.threads, 2)

        def probe(host: str) -> List[Dict[str, Any]]:
            results = []
            for scheme in ("https", "http"):
                if not self.config.can_request() or self.rm.stopped_by_429:
                    break
                # Default ports only (80/443) – keep budget
                url = f"{scheme}://{host}"
                resp = self.rm.get(url, allow_redirects=True, timeout=8)
                if resp is None:
                    continue
                title = self._title(resp.text or "")
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                results.append({
                    "url": str(resp.url) if resp.url else url,
                    "input": url,
                    "status": resp.status_code,
                    "length": len(resp.content or b""),
                    "title": title[:80],
                    "server": server,
                    "powered": powered,
                    "host": host,
                })
                # Prefer https – if it works, skip http for same host
                if scheme == "https" and resp.status_code < 500:
                    break
            return results

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(probe, h): h for h in clean}
            for fut in as_completed(futs):
                for r in fut.result() or []:
                    # Default: hanya host status 200 yang dianggap "live".
                    # --all-status mengembalikan perilaku lama (semua status).
                    if not (self.config.all_status or r["status"] == 200):
                        continue
                    live.append(r)
                    self.reporter.add_endpoint(r["url"])
                    self.log(
                        f"[{r['status']}] {r['url']} "
                        f"len={r['length']} title=\"{r['title']}\" "
                        f"{r['server']}"
                    )
                    if r["status"] in (200, 201, 301, 302, 401, 403):
                        if any(k in (r["title"] + r["url"]).lower() for k in ("admin", "login", "dashboard", "api")):
                            self.reporter.add_finding(
                                f"Live interesting host: {r['url']}",
                                severity="info",
                                detail=f"HTTP {r['status']} – {r['title']}",
                                url=r["url"],
                                method="GET",
                                evidence_snippet=f"HTTP {r['status']} – {r['title']}",
                            )

        self.reporter.extra["live_hosts"] = live
        self.log(f"Live HTTP services: {len(live)}")

    def _title(self, html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()
        return ""