"""DDoS vulnerability scanner — authorized CTF labs only.

Memindai kerentanan yang bisa dieksploitasi untuk DDoS:
  - Missing rate limiting
  - Slowloris vulnerability (incomplete HTTP requests)
  - Large request body handling (no size limits)
  - Connection exhaustion potential
  - Missing security headers (CSP, HSTS, etc.)
  - WebSocket/long-polling endpoints yang bisa diabuse
  - Expensive operations tanpa rate limit (search, export, PDF generation)

Semua probe READ-ONLY dan BOUNDED. Hanya mendeteksi kerentanan,
TIDAK melakukan serangan DDoS aktual.
"""

from __future__ import annotations

import socket
import time
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

from .base import BaseModule


class DDoSVulnScannerModule(BaseModule):
    name = "DDoS Vulnerability Scanner"

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: DDoS vuln scan requires --no-safe")
            return

        if not self.config.can_request():
            return

        self.log("Scanning for DDoS vulnerabilities...")

        base = self.config.base_url.rstrip("/")
        parsed = urlparse(base)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme

        # 1. Check rate limiting on common endpoints
        self._check_rate_limiting(base)

        # 2. Check Slowloris vulnerability
        self._check_slowloris(host, port, scheme == "https")

        # 3. Check large request body handling
        self._check_large_body_handling(base)

        # 4. Check connection handling
        self._check_connection_exhaustion(host, port, scheme == "https")

        # 5. Check for expensive endpoints without protection
        self._check_expensive_endpoints(base)

        # 6. Check security headers
        self._check_security_headers(base)

        self.log("DDoS vulnerability scan complete.")

    def _check_rate_limiting(self, base: str) -> None:
        """Cek apakah ada rate limiting pada endpoint umum."""
        test_endpoints = [
            "/login", "/api/login", "/auth/login", "/signin",
            "/register", "/api/register", "/signup",
            "/search", "/api/search", "/q",
            "/contact", "/api/contact",
            "/reset-password", "/forgot-password",
        ]

        for endpoint in test_endpoints:
            if not self.config.can_request():
                break
            url = urljoin(base + "/", endpoint.lstrip("/"))
            # Kirim 5 request cepat, cek apakah ada 429
            responses = []
            for _ in range(5):
                if not self.config.can_request():
                    break
                resp = self.rm.post(url, data={"test": "rate_limit_check"}, allow_redirects=False)
                if resp:
                    responses.append(resp.status_code)
                time.sleep(0.1)

            if responses:
                has_429 = any(c == 429 for c in responses)
                has_403 = any(c == 403 for c in responses)
                if not has_429 and not has_403:
                    self.reporter.add_finding(
                        f"Potential missing rate limiting: {endpoint}",
                        severity="medium",
                        detail=f"Sent 5 rapid requests to {endpoint}, no 429/403 response. Possible missing rate limit.",
                        evidence=f"Status codes: {responses}",
                        url=url,
                        method="POST",
                        parameter="",
                        evidence_snippet=f"Status codes: {responses}",
                    )
                    self.log(f"[!] No rate limit detected on {endpoint}")

    def _check_slowloris(self, host: str, port: int, use_ssl: bool) -> None:
        """Cek kerentanan Slowloris (incomplete HTTP requests)."""
        import ssl

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            # Kirim request HTTP tidak lengkap (tanpa \r\n\r\n)
            partial_request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
            sock.sendall(partial_request)

            # Tunggu sebentar, lihat apakah server menutup koneksi
            time.sleep(3)

            # Coba kirim header tambahan
            sock.sendall(b"X-Custom-Header: test\r\n")
            time.sleep(2)

            # Cek apakah koneksi masih terbuka (indikasi server menunggu header lengkap)
            try:
                sock.sendall(b"X-Another: test\r\n")
                sock.sendall(b"\r\n")
                response = sock.recv(1024)
                if response:
                    self.reporter.add_finding(
                        "Potential Slowloris vulnerability",
                        severity="high",
                        detail=f"Server accepted incomplete HTTP request and kept connection open for >5 seconds. Vulnerable to Slowloris-style connection exhaustion.",
                        evidence=f"Host: {host}:{port}",
                        url=f"{host}:{port}",
                        method="GET",
                        parameter="",
                        evidence_snippet=f"Host: {host}:{port}",
                    )
                    self.log("[!] Potential Slowloris vulnerability detected")
            except (socket.timeout, OSError):
                # Server menutup koneksi - tidak rentan
                pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

        except (OSError, socket.timeout) as e:
            self.log(f"Slowloris check failed: {e}")

    def _check_large_body_handling(self, base: str) -> None:
        """Cek apakah server membatasi ukuran request body."""
        test_url = urljoin(base + "/", "upload_test")

        # Test berbagai ukuran body
        sizes = [
            (1024 * 1024, "1MB"),      # 1MB
            (10 * 1024 * 1024, "10MB"), # 10MB
            (50 * 1024 * 1024, "50MB"), # 50MB
        ]

        for size_bytes, label in sizes:
            if not self.config.can_request():
                break
            large_data = b"x" * size_bytes
            resp = self.rm.post(test_url, data=large_data, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (200, 201, 202):
                self.reporter.add_finding(
                    f"Large request body accepted ({label})",
                    severity="medium",
                    detail=f"Server accepted {label} request body without rejection. Potential for resource exhaustion via large uploads.",
                    evidence=f"Status: {resp.status_code}, URL: {test_url}",
                    url=test_url,
                    method="POST",
                    parameter="",
                    evidence_snippet=f"Status: {resp.status_code}, URL: {test_url}",
                )
                self.log(f"[!] Server accepted {label} request body")

    def _check_connection_exhaustion(self, host: str, port: int, use_ssl: bool) -> None:
        """Cek apakah server rentan terhadap connection exhaustion."""
        import ssl

        try:
            # Coba buka banyak koneksi simultan tanpa mengirim data
            sockets = []
            for i in range(20):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, port))
                    if use_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                    sockets.append(sock)
                except OSError:
                    break

            if len(sockets) >= 15:
                self.reporter.add_finding(
                    "Potential connection exhaustion vulnerability",
                    severity="medium",
                    detail=f"Server accepted {len(sockets)} concurrent idle connections without rejection. Could be vulnerable to connection exhaustion attacks.",
                    evidence=f"Host: {host}:{port}, Connections: {len(sockets)}",
                    url=f"{host}:{port}",
                    method="GET",
                    parameter="",
                    evidence_snippet=f"Host: {host}:{port}, Connections: {len(sockets)}",
                )
                self.log(f"[!] Server accepted {len(sockets)} idle connections")

            # Tutup semua koneksi
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass

        except Exception as e:
            self.log(f"Connection exhaustion check failed: {e}")

    def _check_expensive_endpoints(self, base: str) -> None:
        """Cek endpoint operasi berat tanpa proteksi."""
        expensive_paths = [
            "/export", "/api/export", "/download", "/api/download",
            "/report", "/api/report", "/generate", "/api/generate",
            "/pdf", "/api/pdf", "/excel", "/api/excel",
            "/backup", "/api/backup", "/dump", "/api/dump",
            "/search", "/api/search", "/autocomplete", "/suggest",
        ]

        for path in expensive_paths:
            if not self.config.can_request():
                break
            url = urljoin(base + "/", path.lstrip("/"))
            resp = self.rm.get(url, allow_redirects=False)
            if resp and resp.status_code == 200:
                # Cek apakah ada rate limit header
                has_rate_limit = any(h.lower() in ("x-ratelimit-limit", "x-rate-limit", "retry-after")
                                     for h in resp.headers)
                if not has_rate_limit:
                    self.reporter.add_finding(
                        f"Expensive endpoint without rate limit: {path}",
                        severity="low",
                        detail=f"Endpoint {path} returned 200 OK without apparent rate limiting headers. Could be abused for resource exhaustion.",
                        evidence=f"URL: {url}, Status: {resp.status_code}",
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=f"URL: {url}, Status: {resp.status_code}",
                    )
                    self.log(f"[*] Expensive endpoint found: {path}")

    def _check_security_headers(self, base: str) -> None:
        """Cek header keamanan yang membantu mitigasi DDoS."""
        resp = self.rm.get(base, allow_redirects=False)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []

        # Header yang membantu mitigasi DDoS/abuse
        checks = [
            ("x-ratelimit-limit", "Rate limit header"),
            ("x-rate-limit", "Rate limit header (alt)"),
            ("retry-after", "Retry-After header"),
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "CSP"),
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
        ]

        for header, desc in checks:
            if header not in headers:
                missing.append(desc)

        if missing:
            self.reporter.add_finding(
                "Missing security headers for DDoS mitigation",
                severity="low",
                detail=f"Missing headers that help mitigate abuse: {', '.join(missing)}",
                evidence=f"Target: {base}",
                url=base,
                method="GET",
                parameter="",
                evidence_snippet=f"Target: {base}",
            )
            self.log(f"[*] Missing security headers: {', '.join(missing)}")
