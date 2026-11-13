"""XSS — deteksi refleksi dan sink DOM berbahaya.

- Kirim canary unik dan tidak berbahaya ke setiap parameter; jika dipantulkan
  tanpa encoding -> temuan, dengan konteks (HTML / atribut / JavaScript).
- Pemindaian berkas JS sama origine untuk sink berbahaya (innerHTML,
  document.write, eval, setTimeout, setInterval).
- Header CSP dicatat (keberadaan); kelengkapan CSP dipindai di modul misconfig.
"""

from __future__ import annotations

import re
import random
from typing import Any
from urllib.parse import parse_qsl, urlparse

from probex.core.vuln import (
    CONF_HIGH,
    CONF_LOW,
    CONF_MEDIUM,
    Location,
    Finding,
    PARAM_IN_QUERY,
    SEVERITY_MEDIUM,
    TYPE_XSS,
)
from .base import BaseModule

MAX_PARAMS = 6
MAX_JS = 3

CANARY_PREFIX = "ProbeXCanary"
DOM_SINK_RE = re.compile(
    r"(innerHTML\s*=|document\.write\s*\(|eval\s*\(|setTimeout\s*\(|setInterval\s*\(|location\.hash\s*=)",
    re.I,
)
ESCAPED_MARKERS = ("&quot;", "&#x27;", "&#34;", "&#39;", "&lt;", "&gt;")


def _context_of(text: str, canary: str) -> str:
    idx = text.find(canary)
    if idx < 0:
        return "tidak dipantulkan"
    start = max(0, idx - 60)
    window = text[start:idx + len(canary) + 60]
    low = window.lower()
    if "<script" in low or "on" in low and ("=" in low):
        return "JavaScript"
    if '="' in window or "'=" in window or "value=" in low or "name=" in low:
        return "atribut HTML"
    return "HTML"


class XSSDetection(BaseModule):
    name = "Vuln Scan: XSS"

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
                out.append({"url": url, "parameter": name})
                if len(out) >= MAX_PARAMS:
                    return out
        return out

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("XSS: budget habis atau rate-limited")
            return
        found = 0
        for c in self._candidates():
            if not self.budget_ok():
                break
            canary = f"{CANARY_PREFIX}{random.randint(100000, 999999)}"
            p = urlparse(c["url"])
            params = dict(parse_qsl(p.query, keep_blank_values=True))
            baseline = self.rm.get(c["url"])
            baseline_text = baseline.text or "" if baseline is not None else ""
            params[c["parameter"]] = canary
            test_url = p._replace(query="&".join(f"{k}={v}" for k, v in params.items())).geturl()
            r = self.rm.get(test_url)
            if r is None:
                continue
            text = r.text or ""
            if canary not in text or canary in baseline_text:
                continue
            escaped = any(m in text for m in ESCAPED_MARKERS) and (
                f"&quot;{canary}" in text or f"&#x27;{canary}" in text or f"&#34;{canary}" in text
            )
            if escaped:
                self.log(f"XSS canary ter-encode pada '{c['parameter']}' di {c['url']} (aman)")
                continue
            context = _context_of(text, canary)
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_XSS,
                severity=SEVERITY_MEDIUM,
                confidence=CONF_HIGH,
                title=f"Refleksi XSS tanpa encoding (konteks: {context})",
                description=(
                    f"Canary unik '{canary}' dikembalikan oleh server tanpa encoding dalam konteks "
                    f"{context}. Serangan XSS reflected dapat dieksekusi jika pengguna ditunjuk ke URL ini."
                ),
                location=Location(
                    url=c["url"],
                    method="GET",
                    parameter=c["parameter"],
                    parameter_in=PARAM_IN_QUERY,
                    snippet=f"{c['parameter']}={canary} dipantulkan dalam {context}",
                ),
                evidence=f"Canary '{canary}' dipantulkan tanpa encoding di konteks {context}.",
                recommendation=(
                    "Lakukan output encoding pada semua parameter yang dipantulkan (HTML entity encoding "
                    "untuk teks, atribut, dan JavaScript). Terapkan Content Security Policy (CSP)."
                ),
                references=[
                    "OWASP Top 10 2021 A03:2021 – Injection (termasuk XSS)",
                    "CWE-79: Improper Neutralization of Input During Web Page Generation",
                ],
            ))
            self.log_hit(f"XSS reflected pada '{c['parameter']}' di {c['url']} ({context})")

        # --- Sink DOM pada berkas JS yang ditemukan ---
        js_urls = [u for u in self.endpoints() if u.lower().endswith(".js")]
        seen_js = set()
        for js in js_urls:
            if not self.budget_ok():
                break
            if js in seen_js:
                continue
            seen_js.add(js)
            if len(seen_js) > MAX_JS:
                break
            r = self.rm.get(js)
            if r is None:
                continue
            for line_no, line in enumerate((r.text or "").splitlines(), start=1):
                m = DOM_SINK_RE.search(line)
                if m:
                    self.reporter.add_vuln_finding(Finding(
                        type=TYPE_XSS,
                        severity=SEVERITY_MEDIUM,
                        confidence=CONF_LOW,
                        title="Sink DOM berbahaya dalam JavaScript",
                        description=(
                            f"Berkas JavaScript '{js}' menggunakan sink berbahaya "
                            f"({m.group(0)}) yang bisa mengeksekusi data yang dikontrol pengguna."
                        ),
                        location=Location(
                            url=js,
                            method="GET",
                            parameter="",
                            parameter_in="",
                            file=js,
                            line=line_no,
                            snippet=line.strip()[:160],
                        ),
                        evidence=f"Sink DOM '{m.group(0)}' pada baris {line_no} di {js}",
                        recommendation=(
                            "Hindari innerHTML, document.write, dan eval dengan data pengguna. "
                            "Gunakan textContent atau API pembuatan elemen yang aman, dan lakukan "
                            "validasi input yang ketat."
                        ),
                        references=[
                            "OWASP Top 10 2021 A03:2021 – Injection (termasuk XSS DOM)",
                            "CWE-79: Improper Neutralization of Input During Web Page Generation",
                        ],
                    ))
                    self.log_hit(f"Sink DOM di {js}:{line_no}")
                    break
        if not found:
            self.log("XSS: tidak ada refleksi canary atau sink DOM yang terdeteksi")
