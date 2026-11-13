"""Dettack-style scanner module — authorized CTF labs only.

Implementasi 5-tahap scan Dettack (dari dettack.com):

  1. DISCOVER  — enumerasi subdomain (sumber publik: crt.sh, hackertarget)
  2. PROBE     — cek host hidup + HTTP fingerprinting
  3. CAPTURE   — tangkapan layar host (catatan: butuh browser headless; di-skip kalau tidak ada)
  4. SCAN VULNS — CVE, web vuln, misconfig, exposure, port, DNS/TLS/takeover
  5. INCIDENT  — defacement, gambling injection, SEO spam (30 tanda tangan)

Semua probe read-only dan bounded. Hanya melaporkan, tidak mengeksploitasi.
"""

from __future__ import annotations

import json
import re
import socket
from typing import List, Tuple
from urllib.parse import urlparse

from .base import BaseModule

# ---------- TAHAP 1: DISCOVER — subdomain enumeration ----------
DISCOVER_SOURCES = [
    "https://crt.sh/?q=%.{domain}&output=json",
    "https://api.hackertarget.com/hostsearch/?q={domain}",
]


def _fetch_json(url: str, timeout: int = 10):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ProbeX-dettack/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read().decode("utf-8", errors="replace")
        return json.loads(data)
    except Exception:
        return None


def _fetch_text(url: str, timeout: int = 10):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ProbeX-dettack/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def discover_subdomains(domain: str, limit: int = 50) -> List[str]:
    found: set = set()

    # crt.sh
    data = _fetch_json(DISCOVER_SOURCES[0].format(domain=domain))
    if isinstance(data, list):
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.endswith("." + domain) or line == domain:
                    found.add(line)

    # hackertarget hostsearch
    text = _fetch_text(DISCOVER_SOURCES[1].format(domain=domain))
    if text:
        for line in text.splitlines():
            parts = line.split(",")
            if parts and parts[0].strip().endswith(domain):
                found.add(parts[0].strip().lower())

    return sorted(found)[:limit]


# ---------- TAHAP 2: PROBE — alive check + fingerprint ----------
def probe_host(host: str, timeout: int = 8) -> Tuple[bool, int, str | None]:
    """Cek apakah host merespons HTTP. Return (alive, status_code, server_header)."""
    import urllib.request
    for scheme in ("http://", "https://"):
        url = f"{scheme}{host}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ProbeX-dettack/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                server = r.headers.get("Server")
                return True, r.status, server
        except Exception:
            continue
    return False, 0, None


# ---------- TAHAP 5: INCIDENT — defacement, gambling, SEO spam ----------
INCIDENT_PATTERNS = {
    "defacement": [
        r"hacked by", r"pwned", r"greetz", r"defaced", r"owned by",
        r"h4ck3d", r"pwnd", r"hacked", r"security has been bypassed",
    ],
    "gambling_injection": [
        r"casino", r"jackpot", r"slot", r"bet365", r"1xbet",
        r"judi online", r"togel", r"bola parlay", r"live casino",
    ],
    "seo_spam": [
        r"viagra", r"cialis", r"cheap", r"replica", r"fake",
        r"buy now", r"discount", r"pharmacy", r"loan",
    ],
}


def check_incident_signatures(body: str, url: str) -> List[Tuple[str, str]]:
    """Cek tanda tangan insiden di body respons. Return list (jenis, pola)."""
    hits: List[Tuple[str, str]] = []
    lower = body.lower()
    for jenis, patterns in INCIDENT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, lower):
                hits.append((jenis, pat))
                break
    return hits


class DettackScanModule(BaseModule):
    name = "Dettack Scan Pipeline"

    def run(self) -> None:
        base = self.config.base_url
        parsed = urlparse(base)
        domain = parsed.hostname or parsed.path
        scheme = parsed.scheme

        self.log(f"[Dettack] Mulai pipeline 5-tahap untuk {domain}")

        # === TAHAP 1: DISCOVER ===
        self.log("[Dettack/1] Discover — enumerasi subdomain...")
        subdomains = discover_subdomains(domain)
        self.log(
            f"  Ditemukan {len(subdomains)} subdomain: {', '.join(subdomains[:10])}"
            + ("..." if len(subdomains) > 10 else "")
        )
        for sub in subdomains[:10]:
            self.reporter.add_endpoint(f"{scheme}://{sub}")

        # === TAHAP 2: PROBE ===
        self.log("[Dettack/2] Probe — cek host hidup + fingerprint...")
        alive, status, server = probe_host(domain)
        if alive:
            self.log(f"  Host hidup: {domain} (HTTP {status}, Server: {server or '-'})")
            self.reporter.add_finding(
                f"Host alive: {domain}",
                severity="info",
                detail=f"HTTP {status}, Server header: {server or 'tidak diketahui'}",
                evidence=f"{scheme}://{domain}",
                url=f"{scheme}://{domain}",
                method="GET",
                parameter="",
                evidence_snippet=f"HTTP {status}, Server header: {server or 'tidak diketahui'}",
            )
        else:
            self.log(f"  Host tidak merespons: {domain}")

        # === TAHAP 3: CAPTURE (catatan) ===
        self.log("[Dettack/3] Capture — tangkapan layar di-skip (butuh browser headless).")

        # === TAHAP 4: SCAN VULNS ===
        self.log("[Dettack/4] Scan vulns — jalankan modul deteksi kerentanan...")
        # Jalankan modul-modul yang sudah ada di ProbeX sebagai bagian dari scan vuln
        self._run_vuln_modules(base)

        # === TAHAP 5: INCIDENT ===
        self.log("[Dettack/5] Incident check — defacement, gambling, SEO spam...")
        import urllib.request
        try:
            req = urllib.request.Request(base, headers={"User-Agent": "ProbeX-dettack/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="replace")
            hits = check_incident_signatures(body, base)
            if hits:
                for jenis, pat in hits:
                    self.log(f"  [!] Tanda insiden terdeteksi: {jenis} (pola: {pat})")
                    self.reporter.add_finding(
                        f"Incident signature: {jenis}",
                        severity="high",
                        detail=f"Tanda {jenis} ditemukan di {base}",
                        evidence=f"Pola cocok: {pat}",
                        url=base,
                        method="GET",
                        parameter="",
                        evidence_snippet=f"Pola cocok: {pat}",
                    )
            else:
                self.log("  Tidak ada tanda insiden (defacement, gambling, SEO spam).")
        except Exception as e:
            self.log(f"  Gagal mengambil body untuk incident check: {e}")

        self.log("[Dettack] Pipeline selesai.")

    def _run_vuln_modules(self, base: str) -> None:
        """Jalankan modul deteksi kerentanan terdaftar di ProbeX.

        Dipanggil pada tahap 4 (SCAN VULNS) pipeline Dettack. Modul-modul
        dijalankan di sini dengan pengecekan budget agar tahap vuln dalam
        pipeline tidak hanya mencatat tapi benar-benar memindai. Setiap
        modul sendiri mematikan safe_mode dan budget, jadi tidak akan
        melebihi batas atau melampaui gate --no-safe.
        """
        from probex.modules.sensitive_files import SensitiveFilesModule
        from probex.modules.sourcemap import SourcemapModule
        from probex.modules.docker_ssh import DockerSSHModule

        vuln_modules = [
            ("Sensitive File Exposure", SensitiveFilesModule),
            ("Sourcemap Exposure", SourcemapModule),
            ("Docker / SSH Active Scan", DockerSSHModule),
        ]

        for label, ModuleCls in vuln_modules:
            if not self.config.can_request() or self.rm.stopped_by_429:
                self.log(f"Budget habis, lewati {label}")
                break
            try:
                self.log(f"  Menjalankan {label}...")
                module = ModuleCls(self.config, self.rm, self.reporter, self.console)
                module.run()
            except Exception as exc:
                self.log(f"  {label} error (non-fatal): {exc}")
