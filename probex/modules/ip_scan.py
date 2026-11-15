"""IP / Host Accessible Scanner (hanya deteksi port terbuka, tidak eksploitasi).

- Dukkungan CIDR (mis. 192.168.1.0/24) untuk enumerasi host.
- Rate limiting + parallel port scan (batas threads dari config, cap 1-3).
- Probing HTTP(S) ke tiap host/IP yang ditemukan, hormati global request
  budget & delay dari request_manager.
- HANYA mencatat host/IP yang mengembalikan HTTP 200 sebagai "accessible"
  (selaras dengan filter status-200 di http_probe, kecuali
  --all-status dipakai).
- Hasil disimpan ke reporter.extra["accessible_hosts"] dan ditampilkan
  sebagai section "[+] ACCESSIBLE HOSTS (200 OK)".
"""

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from probex.modules.base import BaseModule

# Port umum web yang dipindai (kecuali 80/443 juga di probing HTTP).
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888]
CONNECT_TIMEOUT = 1.5


class IpScanModule(BaseModule):
    name = "IP / Host Accessible Scanner"

    def run(self) -> None:
        target = str(self.config.base_url or "")
        hosts = self._collect_hosts(target)
        if not hosts:
            self.log("tidak ada host/IP untuk dipindai")
            return

        open_ports = self._scan_ports(hosts)
        accessible = self._probe_http(open_ports)

        self.reporter.extra["accessible_hosts"] = accessible

        if accessible:
            self.console.print()
            self.console.print("[bold #00FF41][+] ACCESSIBLE HOSTS (200 OK)[/bold #00FF41]")
            for h in accessible:
                self.console.print(
                    f"  • {h['url']}  (title: {h.get('title','-')}, server: {h.get('server','-')})"
                )
            self.log(f"{len(accessible)} host accessible (HTTP 200)")
        else:
            self.log("tidak ada host yang mengembalikan HTTP 200")

    # ---------- host collection -------------------------------------------
    def _collect_hosts(self, target: str) -> list[str]:
        hosts: list[str] = []

        # Target IP utama dari config (ekstrak host dari base_url).
        if target:
            host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            try:
                ipaddress.ip_network(host, strict=False)
                hosts.append(host)  # CIDR target
            except ValueError:
                hosts.append(host)  # single host/IP

        # Dari hasil subdomain / http_probe (reporter.extra).
        for key in ("subdomains", "live_hosts"):
            for item in self.reporter.extra.get(key, []) or []:
                if isinstance(item, str):
                    h = item.split("://", 1)[-1].split("/", 1)[0]
                elif isinstance(item, dict):
                    h = item.get("url") or item.get("host") or item.get("ip") or ""
                    h = h.split("://", 1)[-1].split("/", 1)[0]
                else:
                    continue
                if h and h not in hosts:
                    hosts.append(h)

        # Dedup & batas agar tidak meledakkan budget.
        seen: set[str] = set()
        uniq: list[str] = []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                uniq.append(h)
        return uniq[:200]

    # ---------- port scan --------------------------------------------------
    def _scan_ports(self, hosts: list[str]) -> list[tuple[str, int]]:
        """Parallel port scan dengan rate limiting. Kembalikan (host, port) terbuka."""
        open_ports: list[tuple[str, int]] = []
        lock = threading.Lock()
        last_connect = {"t": 0.0}
        delay = max(0.0, float(self.config.delay))

        def try_port(host: str, port: int) -> Optional[tuple[str, int]]:
            with lock:
                now = time.monotonic()
                wait = delay - (now - last_connect["t"])
                if wait > 0:
                    time.sleep(wait)
                last_connect["t"] = time.monotonic()
            try:
                with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
                    return (host, port)
            except (OSError, socket.timeout, ConnectionRefusedError):
                return None

        jobs = [(h, p) for h in hosts for p in COMMON_PORTS]
        max_workers = max(1, min(3, int(self.config.threads or 1)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(try_port, h, p): (h, p) for h, p in jobs}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    open_ports.append(res)
        return open_ports

    # ---------- HTTP probing ----------------------------------------------
    def _probe_http(self, open_ports: list[tuple[str, int]]) -> list[dict]:
        accessible: list[dict] = []
        seen_urls: set[str] = set()
        lock = threading.Lock()
        last_req = {"t": 0.0}
        delay = max(0.0, float(self.config.delay))

        def probe(host: str, port: int) -> Optional[dict]:
            nonlocal_last = None
            schemes = ["http", "https"] if port in (443, 8443) else ["http", "https"]
            for scheme in schemes:
                url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
                with lock:
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    now = time.monotonic()
                    wait = delay - (now - last_req["t"])
                    if wait > 0 and self.config.can_request():
                        time.sleep(wait)
                    last_req["t"] = time.monotonic()
                if not self.config.can_request() or self.rm.stopped_by_429:
                    break
                try:
                    r = self.rm.request("GET", url, headers={"User-Agent": self.config.user_agent})
                except Exception:
                    continue
                want_200 = self.config.all_status or True  # accessible = status 200 only
                if r is not None and r.status_code == 200:
                    title = self._extract_title(r.text or "")
                    server = (r.headers or {}).get("Server", "-")
                    return {"host": host, "url": url, "status": 200, "title": title, "server": server}
            return None

        max_workers = max(1, min(3, int(self.config.threads or 1)))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(probe, h, p): (h, p) for h, p in open_ports}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    accessible.append(res)
        accessible.sort(key=lambda x: x["url"])
        return accessible

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        return "-"
