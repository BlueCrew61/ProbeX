"""Docker / SSH active-service scanner — authorized CTF labs only.

Cek apakah host target menjalankan layanan yang bisa dieksploitasi:

  - Docker API tanpa autentikasi (port 2375 TCP, 2376 TLS)
  - SSH server (port 22 TCP)

Semua probe read-only dan terbatas: setiap port dicoba sekali dengan timeout
pendek, tidak melakukan login atau perintah pada layanan yang ditemukan.
"""

from __future__ import annotations

import socket
from typing import List, Tuple
from urllib.parse import urlparse

from .base import BaseModule

# (port, nama layanan, deskripsi)
TARGET_PORTS: List[Tuple[int, str, str]] = [
    (22, "SSH", "Secure Shell server"),
    (2375, "Docker API", "Docker REST API (plain TCP, no TLS)"),
    (2376, "Docker API (TLS)", "Docker REST API over TLS"),
]


def _probe_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Coba buka koneksi TCP ke host:port. True jika port terbuka."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout, ConnectionRefusedError):
        return False


class DockerSSHModule(BaseModule):
    name = "Docker / SSH Active Scan"

    def run(self) -> None:
        if not self.config.can_request():
            return

        host = urlparse(self.config.base_url).hostname
        if not host:
            self.log("Tidak dapat menentukan host dari base URL", style="yellow")
            return

        found_any = False

        for port, service, desc in TARGET_PORTS:
            if not self.config.can_request():
                break
            open_port = _probe_port(host, port)
            status = "TERBUKA" if open_port else "tertutup"
            self.log(f"    {host}:{port} — {service} ({desc}): {status}")

            if open_port:
                found_any = True
                severity = "high" if service == "Docker API" else "info"
                detail = f"{service} aktif di {host}:{port} — {desc}"
                self.reporter.add_finding(
                    f"Active {service} service",
                    severity=severity,
                    detail=detail,
                    evidence=f"{host}:{port}",
                    url=f"{host}:{port}",
                    method="GET",
                    parameter="",
                    evidence_snippet=f"{host}:{port}",
                )
                self.reporter.add_endpoint(f"{service.lower()}://{host}:{port}")

        if not found_any:
            self.log("Tidak ada layanan Docker/SSH aktif yang terdeteksi")
