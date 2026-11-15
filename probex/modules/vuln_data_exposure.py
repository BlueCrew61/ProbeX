"""Sensitive data exposure.

- Situs menggunakan HTTP tanpa HTTPS.
- Pola API key / token / secret di HTML dan JavaScript.
- Data sensitif di URL (parameter password, token, key, nik).
- Field berlebih di respons API (password, hash, token, NIK).
Nilai rahasia disamarkan sebelum dilaporkan.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from probex.core.vuln import (
    CONF_HIGH,
    CONF_MEDIUM,
    CONF_LOW,
    Location,
    Finding,
    mask_secret,
    PARAM_IN_QUERY,
    SEVERITY_MEDIUM,
    TYPE_DATA_EXPOSURE,
)
from .base import BaseModule

SECRET_KV_RE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|nik)[^&\n\"'<]{3,}", re.I
)
SENSITIVE_PARAM_RE = re.compile(r"^(password|passwd|token|key|api_key|nik|secret)$", re.I)
SENSITIVE_KEY_RE = re.compile(r"^(password|passwd|token|hash|nik|secret|api_key)$", re.I)

MAX_ENDPOINTS = 6


class DataExposureDetection(BaseModule):
    name = "Vuln Scan: Sensitive Data Exposure"

    def _scan_body(self, url: str, text: str) -> list[str]:
        hits = []
        for m in SECRET_KV_RE.finditer(text):
            hits.append(mask_secret(m.group(0)[:120]))
        return hits[:5]

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("Data exposure: budget habis atau rate-limited")
            return
        base = str(getattr(self.config, "base_url", ""))
        found = 0

        # --- HTTP tanpa HTTPS ---
        if base.startswith("http://"):
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_DATA_EXPOSURE,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_HIGH,
                title="Situs menggunakan HTTP tanpa HTTPS",
                description="Komunikasi target menggunakan HTTP, sehingga data (termasuk cookie dan token) bisa dicegat dalam perantaraan.",
                location=Location(url=base, method="GET", parameter="", parameter_in="", snippet="http://"),
                evidence="Scheme URL: http://",
                recommendation="Aktifkan HTTPS untuk seluruh situs dan alihkan semua lalu lintas HTTP ke HTTPS (HSTS).",
                references=[
                    "OWASP Top 10 2021 A02:2021 – Cryptographic Failures",
                    "CWE-319: Cleartext Transmission of Sensitive Information",
                ],
            ))
            self.log_hit("Target menggunakan HTTP (tanpa HTTPS)")
        else:
            self.log("Data exposure: target menggunakan HTTPS")

        # --- Endpoint: rahasia dalam body, parameter sensitif, field berlebih ---
        checked = 0
        for url in self.endpoints():
            if not url.startswith(("http://", "https://")):
                continue
            if not self.budget_ok():
                break
            checked += 1
            if checked > MAX_ENDPOINTS:
                break
            resp = self.rm.get(url)
            if resp is None:
                continue
            text = resp.text or ""

            # Rahasia dalam HTML/JS.
            hits = self._scan_body(url, text)
            if hits:
                found += 1
                self.reporter.add_vuln_finding(Finding(
                    type=TYPE_DATA_EXPOSURE,
                    severity=SEVERITY_MEDIUM,
                    confidence=CONF_MEDIUM,
                    title="Kunci/token rahasia terpapar dalam respons",
                    description="Pola API key / token / secret ditemukan dalam isi respons HTML atau JavaScript.",
                    location=Location(url=url, method="GET", parameter="", parameter_in="", snippet=hits[0]),
                    evidence="; ".join(hits),
                    recommendation=(
                        "Hindari menyisipkan kunci rahasia ke dalam HTML/JavaScript klien. Simpan rahasia "
                        "di server, gunakan variabel lingkungan, dan pantau/mutar kunci yang telah terpapar."
                    ),
                    references=[
                        "OWASP Top 10 2021 A02:2021 – Cryptographic Failures",
                        "CWE-312: Cleartext Storage of Sensitive Information",
                    ],
                ))
                self.log_hit(f"Rahasia terpapar di {url}")
                continue

            # Data sensitif dalam URL.
            p = urlparse(url)
            for name, _ in parse_qsl(p.query, keep_blank_values=True):
                if SENSITIVE_PARAM_RE.match(name):
                    found += 1
                    self.reporter.add_vuln_finding(Finding(
                        type=TYPE_DATA_EXPOSURE,
                        severity=SEVERITY_MEDIUM,
                        confidence=CONF_MEDIUM,
                        title="Data sensitif terpapar dalam URL",
                        description=f"Parameter '{name}' mengandung data sensitif yang dikirim dalam URL (terlog di server/proxy).",
                        location=Location(url=url, method="GET", parameter=name, parameter_in="query", snippet=f"{name}=<disamarkan>"),
                        evidence=f"Parameter sensitif '{name}' ada dalam URL",
                        recommendation=(
                            "Jangan kirim password, token, atau NIK dalam query string. Gunakan body POST dan HTTPS."
                        ),
                        references=[
                            "OWASP Top 10 2021 A02:2021 – Cryptographic Failures",
                            "CWE-598: Use of GET Request Method with Sensitive Query Parameters",
                        ],
                    ))
                    self.log_hit(f"Parameter sensitif di URL: {name}")
                    break

            # Field berlebih di respons JSON.
            ctype = ""
            for _k, _v in (resp.headers or {}).items():
                if _k.lower() == "content-type":
                    ctype = _v
                    break
            if "application/json" in ctype:
                try:
                    data = json.loads(text)
                except (ValueError, TypeError):
                    data = None
                if isinstance(data, dict):
                    leaked = [k for k in data.keys() if SENSITIVE_KEY_RE.match(k)]
                    if leaked:
                        found += 1
                        self.reporter.add_vuln_finding(Finding(
                            type=TYPE_DATA_EXPOSURE,
                            severity=SEVERITY_MEDIUM,
                            confidence=CONF_MEDIUM,
                            title="Respons API menyertakan field berlebih",
                            description="Respons JSON menyertakan field sensitif (password, hash, token, NIK) yang seharusnya disaring.",
                            location=Location(url=url, method="GET", parameter="", parameter_in="", snippet=", ".join(leaked)),
                            evidence="Field sensitif dalam JSON: " + ", ".join(leaked),
                            recommendation=(
                                "Saring field sensitif sebelum mengirim respons API; gunakan serializer yang hanya menyertakan "
                                "field yang dibutuhkan klien."
                            ),
                            references=[
                                "OWASP Top 10 2021 A01:2021 – Broken Access Control",
                                "CWE-200: Information Exposure",
                            ],
                        ))
                        self.log_hit(f"Field berlebih di API: {', '.join(leaked)}")
        if not found:
            self.log("Data exposure: tidak ada indikasi paparan data sensitif")
