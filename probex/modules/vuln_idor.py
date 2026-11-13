"""IDOR / Broken Access Control — deteksi read-only (tidak mengubah data).

Logika: temukan parameter bertipe ID (angka/UUID, atau nama seperti id, uid,
user, order) pada query string. Untuk setiap kandidat, kirim GET dengan nilai
asli dan GET dengan nilai yang diubah (id+1, atau "0"). Keduanya HTTP 200,
konten berbeda, dan nilai baru dipantulkan di respons kedua  menandakan
potensi IDOR. Hanya satu sesi, sehingga ditandai "potensial" (confidence rendah).
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
    SEVERITY_HIGH,
    TYPE_IDOR,
)
from .base import BaseModule

ID_NAME_RE = re.compile(
    r"^(id|uid|user|user_id|account|customer|item|order|invoice|no|nik|kode|kode_item)([0-9_]*)$",
    re.I,
)
NUMERIC_RE = re.compile(r"^\d{1,18}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

MAX_CANDIDATES = 12


class IDORDetection(BaseModule):
    name = "Vuln Scan: IDOR / Broken Access Control"

    def _candidates(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen = set()
        for url in self.endpoints():
            p = urlparse(url)
            for name, value in parse_qsl(p.query, keep_blank_values=True):
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)
                if ID_NAME_RE.match(name) or NUMERIC_RE.match(value) or UUID_RE.match(value):
                    out.append({"url": url, "parameter": name, "value": value})
                    if len(out) >= MAX_CANDIDATES:
                        return out
        return out

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("IDOR: budget habis atau rate-limited")
            return
        found = 0
        for c in self._candidates():
            if not self.budget_ok():
                break
            base = c["url"]
            p = urlparse(base)
            params = dict(parse_qsl(p.query, keep_blank_values=True))
            orig = params.get(c["parameter"], "")

            # Variasi read-only: id+1 untuk angka, "0" untuk yang lainnya.
            if NUMERIC_RE.match(orig):
                test = str(int(orig) + 1)
            else:
                test = "0"
            if test == orig:
                test = "999999"

            params[c["parameter"]] = test
            mutated = p._replace(query="&".join(f"{k}={v}" for k, v in params.items())).geturl()

            r1 = self.rm.get(base)
            if r1 is None:
                continue
            r2 = self.rm.get(mutated)
            if r2 is None:
                continue

            same_status = r1.status_code == r2.status_code
            body_differs = r1.text != r2.text
            reflected = test in r2.text and test not in r1.text

            if same_status and r1.status_code == 200 and body_differs and reflected:
                found += 1
                self.reporter.add_vuln_finding(Finding(
                    type=TYPE_IDOR,
                    severity=SEVERITY_HIGH,
                    confidence=CONF_LOW,
                    title="Potensi IDOR / Broken Access Control",
                    description=(
                        "Dua nilai ID berbeda (asli dan dimutasi) sama-sama HTTP 200, konten berubah, "
                        "dan nilai ID baru muncul di respons kedua. Diuji dengan satu sesi saja, jadi "
                        "belum dikonfirmasi — butuh verifikasi dengan dua akun."
                    ),
                    location=Location(
                        url=base,
                        method="GET",
                        parameter=c["parameter"],
                        parameter_in=PARAM_IN_QUERY,
                        snippet=f"{c['parameter']}={orig} -> {test}; kedua HTTP 200, konten berbeda",
                    ),
                    evidence=(
                        f"GET {c['parameter']}={orig} dan {c['parameter']}={test} keduanya HTTP 200, "
                        f"body berbeda, '{test}' dipantulkan di respons kedua."
                    ),
                    recommendation=(
                        "Terapkan kontrol akses per objek (object-level access control) di server untuk "
                        "setiap permintaan yang mengandung ID resource. Jangan percaya pada ID yang "
                        "dikirim dari klien."
                    ),
                    references=[
                        "OWASP Top 10 2021 A01:2021 – Broken Access Control",
                        "CWE-639: Authorization Bypass Through User-Controlled Key",
                    ],
                ))
                self.log_hit(f"Potensi IDOR pada parameter '{c['parameter']}' di {base}")
            else:
                self.log(f"IDOR tidak mencurigakan pada '{c['parameter']}' di {base}")
        if not found:
            self.log("IDOR: tidak ada indikasi konklusif (diuji satu sesi, berlabel potensial saja)")
