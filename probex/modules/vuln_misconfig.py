"""Security misconfiguration.

- Header keamanan yang hilang (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
- Directory listing ("Index of" / daftar direktori).
- Stack trace / halaman debug (Traceback, Exception, Fatal error).
- CORS terlalu longgar (Access-Control-Allow-Origin: *).
- Path sensitif (.env, .git/HEAD, phpinfo) dengan permintaan GET saja.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from probex.core.vuln import (
    CONF_LOW,
    CONF_MEDIUM,
    Location,
    Finding,
    SEVERITY_MEDIUM,
    TYPE_MISCONFIG,
)
from .base import BaseModule

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
]

DIRECTORY_LISTING_RE = re.compile(r"Index of|directory listing|directory index for", re.I)
STACK_TRACE_RE = re.compile(r"Traceback|Exception in|Fatal error|Warning:.*\bon line\d+", re.I)

SENSITIVE_PATHS = [".env", ".git/HEAD", "phpinfo.php", "server-status", ".htaccess"]


class MisconfigDetection(BaseModule):
    name = "Vuln Scan: Security Misconfiguration"

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("Misconfig: budget habis atau rate-limited")
            return
        base = str(getattr(self.config, "base_url", ""))
        found = 0

        r = self.rm.get(base)
        if r is None:
            self.log_skip("Misconfig: tidak dapat mengambil respons target")
            return
        headers = {str(k).lower(): str(v) for k, v in (r.headers or {}).items()}
        text = r.text or ""

        # --- Header keamanan ---
        missing = [h for h in REQUIRED_HEADERS if h.lower() not in headers]
        if missing:
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_MISCONFIG,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_MEDIUM,
                title="Header keamanan hilang",
                description=(
                    "Beberapa header keamanan penting tidak terkirim dalam respons, sehingga browser "
                    "tidak diberi kebijakan perlindungan (CSP, HSTS, nosniff, frame-options)."
                ),
                location=Location(
                    url=base,
                    method="GET",
                    parameter="",
                    parameter_in="header",
                    snippet=", ".join(missing),
                ),
                evidence="Header hilang: " + ", ".join(missing),
                recommendation=(
                    "Pasang header keamanan: Content-Security-Policy, Strict-Transport-Security, "
                    "X-Content-Type-Options: nosniff, dan X-Frame-Options: DENY (atau SAMEORIGIN)."
                ),
                references=[
                    "OWASP Top 10 2021 A05:2021 – Security Misconfiguration",
                    "CWE-16: Improper Neutralization of Output",
                ],
            ))
            self.log_hit(f"Header keamanan hilang: {', '.join(missing)}")
        else:
            self.log("Misconfig: header keamanan utama lengkap")

        # --- Directory listing ---
        if DIRECTORY_LISTING_RE.search(text):
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_MISCONFIG,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_MEDIUM,
                title="Directory listing diaktifkan",
                description="Respons mengandung indikasi daftar direktori; isi direktori dapat dilihat publik.",
                location=Location(url=base, method="GET", parameter="", parameter_in="", snippet="Index of / daftar direktori"),
                evidence="Body respons mengandung pola directory listing",
                recommendation="Nonaktifkan directory listing pada web server (misal Options -Indexes pada Apache).",
                references=[
                    "OWASP Top 10 2021 A05:2021 – Security Misconfiguration",
                    "CWE-548: Exposure of Information Through Directory Listing",
                ],
            ))
            self.log_hit("Directory listing terindikasi")

        # --- Stack trace / debug ---
        if STACK_TRACE_RE.search(text):
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_MISCONFIG,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_MEDIUM,
                title="Stack trace / halaman debug terpapar",
                description="Respons mengindikasikan stack trace atau halaman debug aktif; detail internal dapat membantu penyerang.",
                location=Location(url=base, method="GET", parameter="", parameter_in="", snippet="stack trace / debug page"),
                evidence="Body respons mengandung pola stack trace/debug",
                recommendation="Matikan mode debug dan tampilkan pesan error generik kepada pengguna di produksi.",
                references=[
                    "OWASP Top 10 2021 A05:2021 – Security Misconfiguration",
                    "CWE-215: Information Exposure Through Debug Information",
                ],
            ))
            self.log_hit("Stack trace/debug terindikasi")

        # --- CORS longgar ---
        if headers.get("access-control-allow-origin") == "*":
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_MISCONFIG,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_MEDIUM,
                title="CORS terlalu longgar (Allow-Origin: *)",
                description="Header Access-Control-Allow-Origin: * memungkinkan situs lain membaca respons target.",
                location=Location(url=base, method="GET", parameter="", parameter_in="header", snippet="Access-Control-Allow-Origin: *"),
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Batasi Access-Control-Allow-Origin pada origin terpercaya, jangan gunakan * untuk data sensitif.",
                references=[
                    "OWASP Top 10 2021 A05:2021 – Security Misconfiguration",
                    "CWE-942: Overly Permissive Cross-domain Whitelist",
                ],
            ))
            self.log_hit("CORS terlalu longgar")

        # --- Path sensitif (GET only) ---
        for path in SENSITIVE_PATHS:
            if not self.budget_ok():
                break
            target = base.rstrip("/") + "/" + path
            rr = self.rm.get(target)
            if rr is None:
                continue
            if rr.status_code == 200 and rr.text and len(rr.text) > 0:
                low = rr.text.lower()
                if path == ".env" or any(k in low for k in ("env", "api_key", "secret", "password")):
                    marker = "berisi variabel lingkungan/rahasia"
                elif path == ".git/HEAD":
                    marker = "berisi ref repositori Git"
                else:
                    marker = "tersedia publik"
                self.reporter.add_vuln_finding(Finding(
                    type=TYPE_MISCONFIG,
                    severity=SEVERITY_MEDIUM,
                    confidence=CONF_MEDIUM,
                    title=f"Path sensitif tersedia publik ({path})",
                    description=f"Path '{path}' dapat diakses dengan GET dan mengembalikan HTTP 200 ({marker}).",
                    location=Location(url=target, method="GET", parameter="", parameter_in="", snippet=marker),
                    evidence=f"GET {path} -> HTTP 200 ({marker})",
                    recommendation=(
                        "Hapus atau batasi akses ke file sensitif (.env, .git, phpinfo, .htaccess) dari "
                        "server publik; gunakan .htaccess / konfigurasi server untuk menolak akses."
                    ),
                    references=[
                        "OWASP Top 10 2021 A05:2021 – Security Misconfiguration",
                        "CWE-538: File and Directory Information Exposure",
                    ],
                ))
                self.log_hit(f"Path sensitif tersedia: {path}")
        if not found:
            self.log("Misconfig: tidak ada konfigurasi keamanan yang mencurigakan terdeteksi")
