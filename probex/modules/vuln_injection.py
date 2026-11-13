"""Injection: SQL, template (dinamis), command (statis saja).

- SQL: kirim tanda kutip tunggal ke setiap parameter; cocokkan pola pesan error
  database. Tidak mengeksekusi perintah berbahaya apa pun.
- Template: kirim {{7*7}}; jika "49" muncul dan tidak ada di baseline -> potensi SSTI.
- Command injection: cukup deteksi statis pada source code; jangan eksekusi
  perintah apa pun di target (dicatat sebagai catatan, bukan temuan aktif).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from probex.core.vuln import (
    CONF_MEDIUM,
    Location,
    Finding,
    PARAM_IN_QUERY,
    SEVERITY_HIGH,
    TYPE_INJECTION,
)
from .base import BaseModule

SQL_ERROR_RE = [
    re.compile(p, re.I) for p in [
        r"SQL syntax.*MySQL",
        r"Warning.*\bmysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\bpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"SQL Server.*Driver",
        r"Warning.*\bmssql_.*",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Warning.*\boci_.*",
        r"SQLite.*error",
        r"Warning.*sqlite",
        r"Unclosed quotation mark",
        r"syntax error",
        r"quotation mark not terminated",
        r"you have an error in your sql syntax",
    ]
]

TEMPLATE_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
TEMPLATE_MARKER = "49"

MAX_PARAMS = 8


class InjectionDetection(BaseModule):
    name = "Vuln Scan: Injection (SQL / Command / Template)"

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
                out.append({"url": url, "parameter": name, "value": value})
                if len(out) >= MAX_PARAMS:
                    return out
        return out

    def _has_sql_error(self, text: str) -> bool:
        return any(rx.search(text) for rx in SQL_ERROR_RE)

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("Injection: budget habis atau rate-limited")
            return
        found = 0
        for c in self._candidates():
            if not self.budget_ok():
                break
            base = c["url"]
            p = urlparse(base)
            params = dict(parse_qsl(p.query, keep_blank_values=True))

            baseline = self.rm.get(base)
            if baseline is None:
                continue
            baseline_text = baseline.text or ""

            # --- SQL: karakter uji aman (tanda kutip) ---
            sql_done = False
            for probe in (params.get(c["parameter"], "") + "'", "'"):
                if sql_done or not self.budget_ok():
                    break
                params_probe = dict(parse_qsl(p.query, keep_blank_values=True))
                params_probe[c["parameter"]] = probe
                mutated_probe = p._replace(
                    query="&".join(f"{k}={v}" for k, v in params_probe.items())
                ).geturl()
                if mutated_probe == base:
                    continue
                r = self.rm.get(mutated_probe)
                if r is not None and self._has_sql_error(r.text or ""):
                    found += 1
                    sql_done = True
                    self.reporter.add_vuln_finding(Finding(
                    type=TYPE_INJECTION,
                    severity=SEVERITY_HIGH,
                    confidence=CONF_MEDIUM,
                    title="Potensi SQL Injection",
                    description=(
                        "Memberikan tanda kutip tunggal pada parameter mengakibatkan pesan "
                        "error database di respons. Indikasi input tidak divalidasi sebelum "
                        "dimasukkan ke query."
                    ),
                    location=Location(
                        url=base,
                        method="GET",
                        parameter=c["parameter"],
                        parameter_in=PARAM_IN_QUERY,
                        snippet=f"{c['parameter']}=' -> respons mengandung pola error database",
                    ),
                    evidence=f"Respons untuk {c['parameter']}=' mengandung pola error database.",
                    recommendation=(
                        "Gunakan prepared statement / parameterized query. Jangan gabungkan "
                        "input pengguna langsung ke query SQL. Validasi dan saring input."
                    ),
                    references=[
                        "OWASP Top 10 2021 A03:2021 – Injection",
                        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                    ],
                ))
                self.log_hit(f"Potensi SQL Injection pada '{c['parameter']}' di {base}")
                continue

            # --- Template injection: {{7*7}} harus menghasilkan 49 ---
            for payload in TEMPLATE_PAYLOADS:
                if not self.budget_ok():
                    break
                params2 = dict(parse_qsl(p.query, keep_blank_values=True))
                params2[c["parameter"]] = payload
                tpl_url = p._replace(query="&".join(f"{k}={v}" for k, v in params2.items())).geturl()
                rt = self.rm.get(tpl_url)
                if rt is None:
                    continue
                tpl_text = rt.text or ""
                if TEMPLATE_MARKER in tpl_text and TEMPLATE_MARKER not in baseline_text:
                    found += 1
                    self.reporter.add_vuln_finding(Finding(
                        type=TYPE_INJECTION,
                        severity=SEVERITY_HIGH,
                        confidence=CONF_MEDIUM,
                        title="Potensi Server-Side Template Injection",
                        description=(
                            f"Payload '{payload}' dikembalikan sebagai '{TEMPLATE_MARKER}' di respons, "
                            "sedang baseline tidak mengandungnya. Indikasi template dirender di server."
                        ),
                        location=Location(
                            url=base,
                            method="GET",
                            parameter=c["parameter"],
                            parameter_in=PARAM_IN_QUERY,
                            snippet=f"{c['parameter']}={payload} -> respons berisi {TEMPLATE_MARKER}",
                        ),
                        evidence=f"Payload '{payload}' menghasilkan '{TEMPLATE_MARKER}' di respons; baseline tidak.",
                        recommendation=(
                            "Hindari rendering template dengan input pengguna. Gunakan sandbox/template "
                            "engine yang aman, atau gunakan pemaparan teks mentah tanpa dievaluasi."
                        ),
                        references=[
                            "OWASP Top 10 2021 A03:2021 – Injection",
                            "CWE-94: Improper Control of Generation of Code",
                        ],
                    ))
                    self.log_hit(f"Potensi SSTI pada '{c['parameter']}' di {base}")
                    break
        if not found:
            self.log("Injection: tidak ada indikasi SQL/template injection dari uji non-destruktif")
        self.log(
            "Command injection: hanya deteksi statis pada source code (mode kode); "
            "tidak dieksekusi terhadap target"
        )
