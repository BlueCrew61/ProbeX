"""Business logic flaw — tidak bisa diotomasi sepenuhnya.

Deteksi form/endpoint yang berisi field harga, jumlah, kupon, diskon, atau
langkah bertahap (checkout), lalu tandai "perlu verifikasi manual" dengan
checklist pengujian. Confidence selalu rendah.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from probex.core.vuln import (
    CONF_LOW,
    Location,
    Finding,
    PARAM_IN_QUERY,
    SEVERITY_VARIES,
    TYPE_BUSINESS_LOGIC,
)
from .base import BaseModule

FIELD_RE = re.compile(
    r"harga|total|jumlah|qty|quantity|kupon|coupon|diskon|checkout|bayar|pembayaran|subtotal",
    re.I,
)

MAX_FORMS = 8


class BusinessLogicDetection(BaseModule):
    name = "Vuln Scan: Business Logic"

    def _interesting_forms(self) -> list[dict[str, Any]]:
        forms = getattr(self.reporter, "runtime_context", {}).get("forms", []) or []
        out = []
        for form in forms:
            fields = form.get("fields", []) or []
            names = " ".join(str(f.get("name", "")) for f in fields).lower()
            if FIELD_RE.search(names):
                out.append(form)
                if len(out) >= MAX_FORMS:
                    break
        return out

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("Business logic: budget habis atau rate-limited")
            return
        found = 0

        # --- Form dengan field bisnis (harga, kupon, checkout, dst.) ---
        for form in self._interesting_forms():
            action = form.get("action") or str(self.config.base_url)
            fields = form.get("fields", []) or []
            matched = [f.get("name") for f in fields if f.get("name") and FIELD_RE.search(str(f.get("name", "")))]
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_BUSINESS_LOGIC,
                severity=SEVERITY_VARIES,
                confidence=CONF_LOW,
                title="Endpoint logika bisnis — perlu verifikasi manual",
                description=(
                    f"Form/endpoint '{action}' memiliki field terkait logika bisnis ({', '.join(matched)[:120]}). "
                    "Tidak dapat diverifikasi sepenuhnya oleh otomatisasi; perlu pengujian manual."
                ),
                location=Location(
                    url=action,
                    method=(form.get("method") or "GET").upper(),
                    parameter=", ".join(matched[:3]),
                    parameter_in="body",
                    snippet="field: " + ", ".join(matched),
                ),
                evidence="Field logika bisnis terdeteksi: " + ", ".join(matched),
                recommendation=(
                    "Checklist verifikasi manual: "
                    "1) Harga dan kuantitas tidak boleh diubah dari klien (hitung ulang di server), "
                    "2) Kupon tidak boleh diterapkan berulang secara berlebihan, "
                    "3) Jumlah tidak boleh nol/negatif, "
                    "4) Langkah checkout tidak boleh dilewati (urutan harus diatur server), "
                    "5) Diskon harus diverifikasi pada total akhir."
                ),
                references=[
                    "OWASP Top 10 2021 A04:2021 – Insecure Design (logika bisnis)",
                    "CWE-840: Business Logic Errors",
                ],
            ))
            self.log_hit(f"Logika bisnis: {action} (verifikasi manual)")

        # --- Parameter bisnis di query string ---
        for url in self.endpoints():
            p = urlparse(url)
            for name, _ in parse_qsl(p.query, keep_blank_values=True):
                if FIELD_RE.search(name):
                    found += 1
                    self.reporter.add_vuln_finding(Finding(
                        type=TYPE_BUSINESS_LOGIC,
                        severity=SEVERITY_VARIES,
                        confidence=CONF_LOW,
                        title="Parameter logika bisnis di URL — perlu verifikasi manual",
                        description=(
                            f"Parameter '{name}' pada {url} terkait logika bisnis (harga/diskon/kupon/kuantitas). "
                            "Perlu verifikasi manual bahwa tidak dapat dimanipulasi dari klien."
                        ),
                        location=Location(
                            url=url,
                            method="GET",
                            parameter=name,
                            parameter_in="query",
                            snippet=f"{name}=<nilai>",
                        ),
                        evidence=f"Parameter bisnis '{name}' ditemukan di URL",
                        recommendation=(
                            "Validasi dan hitung ulang harga, diskon, dan kuantitas di server; jangan percaya "
                            "nilai parameter bisnis dari klien."
                        ),
                        references=[
                            "OWASP Top 10 2021 A04:2021 – Insecure Design (logika bisnis)",
                            "CWE-840: Business Logic Errors",
                        ],
                    ))
                    self.log_hit(f"Parameter bisnis: {name} di {url}")
                    break
        if not found:
            self.log("Business logic: tidak ada form/endpoint logika bisnis yang terdeteksi")
