"""SSRF — hanya mengidentifikasi parameter berisiko dan menguji dengan callback
publik milik pengguna (jika dikonfigurasi). Tidak pernah mengakses alamat
internal atau metadata cloud pada target.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from probex.core.vuln import (
    CONF_LOW,
    CONF_MEDIUM,
    Location,
    Finding,
    PARAM_IN_QUERY,
    SEVERITY_HIGH,
    TYPE_SSRF,
)
from .base import BaseModule

SSRF_PARAM_RE = re.compile(
    r"^(url|uri|dest|destination|redirect|callback|webhook|fetch|import|source|target|file)$",
    re.I,
)

MAX_CANDIDATES = 6


def _is_public_url(url: str) -> bool:
    """True jika URL skema http/https dan host bukan alamat internal/reserved."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname
        if not host:
            return False
        ip = ipaddress.ip_address(host)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        # Nama host (bukan IP): cek apakah mengarah ke internal/metadata.
        host_l = host.lower()
        internal_suffixes = (
            "localhost", ".local", ".invalid", ".localhost",
            "metadata.google.internal", "169.254.169.254",
        )
        if any(host_l == s or host_l.endswith(s) for s in internal_suffixes):
            return False
        # Tidak dapat di-resolve → anggap aman (tidak mencoba koneksi internal)
        return True


class SSRFDetection(BaseModule):
    name = "Vuln Scan: SSRF"

    def _candidates(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen = set()
        for url in self.endpoints():
            p = urlparse(url)
            for name, value in parse_qsl(p.query, keep_blank_values=True):
                if not SSRF_PARAM_RE.match(name):
                    continue
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": url, "parameter": name, "value": value})
                if len(out) >= MAX_CANDIDATES:
                    return out
        return out

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("SSRF: budget habis atau rate-limited")
            return
        cands = self._candidates()
        if not cands:
            self.log("SSRF: tidak ada parameter berisiko (url/uri/callback/webhook/dll.) ditemukan")
            return

        callback = getattr(self.config, "ssrf_callback", None) or ""
        if callback:
            if not _is_public_url(callback):
                self.log_skip(
                    f"SSRF: callback diabaikan (alamat internal/reserved tidak diizinkan): {callback}"
                )
                return
            else:
                # Uji non-destruktif satu kali: arahkan parameter ke callback milik pengguna.
                c = cands[0]
                p = urlparse(c["url"])
                params = dict(parse_qsl(p.query, keep_blank_values=True))
                params[c["parameter"]] = callback
                test_url = p._replace(query="&".join(f"{k}={v}" for k, v in params.items())).geturl()
                r = self.rm.get(test_url)
                if r is None:
                    self.log_skip("SSRF: tidak dapat mengirim uji ke callback")
                    return
                self.reporter.add_vuln_finding(Finding(
                    type=TYPE_SSRF,
                    severity=SEVERITY_HIGH,
                    confidence=CONF_MEDIUM,
                    title="Parameter SSRF diuji terhadap callback publik",
                    description=(
                        f"Parameter '{c['parameter']}' mengacu pada URL eksternal dan diuji dengan "
                        "callback publik milik pengguna. Tidak ada akses ke alamat internal atau "
                        "metadata cloud. Periksa apakah server melakukan request ke callback."
                    ),
                    location=Location(
                        url=c["url"],
                        method="GET",
                        parameter=c["parameter"],
                        parameter_in=PARAM_IN_QUERY,
                        snippet=f"{c['parameter']}=<callback publik> (diuji sekali, non-destruktif)",
                    ),
                    evidence=f"Parameter SSRF '{c['parameter']}' teridentifikasi dan diuji dengan callback publik.",
                    recommendation=(
                        "Validasi dan whitelist URL tujuan (hanya domain publik yang diizinkan). "
                        "Blokir alamat privat, loopback, link-local, dan metadata cloud (169.254.0.0/16). "
                        "Jangan memberikan respons mentah dari fetch URL kepada pengguna."
                    ),
                    references=[
                        "OWASP Top 10 2021 A10:2021 – Server-Side Request Forgery (SSRF)",
                        "CWE-918: Server-Side Request Forgery",
                    ],
                ))
                self.log_hit(f"SSRF: uji callback terkirim pada '{c['parameter']}' di {c['url']}")
                return

        # Tidak ada callback dikonfigurasi: parameter hanya diidentifikasi, tidak diuji aktif.
        self.reporter.add_vuln_finding(Finding(
            type=TYPE_SSRF,
            severity=SEVERITY_HIGH,
            confidence=CONF_LOW,
            title="Parameter SSRF teridentifikasi (belum diuji aktif)",
            description=(
                f"Ditemukan {len(cands)} parameter berisiko SSRF (url/uri/callback/webhook/dll.). "
                "Tidak ada callback yang dikonfigurasi (--ssrf-callback), sehingga uji aktif tidak "
                "dilakukan untuk menghindari akses ke alamat internal."
            ),
            location=Location(
                url=cands[0]["url"],
                method="GET",
                parameter=cands[0]["parameter"],
                parameter_in=PARAM_IN_QUERY,
                snippet=f"parameter '{cands[0]['parameter']}' mengacu pada URL eksternal",
            ),
            evidence="Parameter berisiko SSRF teridentifikasi; uji aktif dilewati (tidak ada callback publik).",
            recommendation=(
                "Konfirmasi dengan --ssrf-callback (URL publik milik Anda) untuk menguji apakah server "
                "melakukan request ke URL yang disisipkan. Batasi tujuan hanya pada domain publik."
            ),
            references=[
                "OWASP Top 10 2021 A10:2021 – Server-Side Request Forgery (SSRF)",
                "CWE-918: Server-Side Request Forgery",
            ],
        ))
        self.log("SSRF: parameter berisiko teridentifikasi (belum diuji aktif, tidak ada callback)")
