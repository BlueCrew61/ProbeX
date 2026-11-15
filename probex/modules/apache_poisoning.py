"""Apache Cache Poisoning / Known-Vuln Detector (read-only, bounded).

Sub-pemeriksaan:
  a. Version/CVE fingerprint: deteksi versi Apache dari header Server / X-Powered-By,
     cocokkan terhadap CVE path-traversal mod_cgi yang dikenal publik
     (CVE-2021-41773, CVE-2021-42013). Hanya deteksi, TIDAK mengirim payload
     eksploitasi RCE/shell.
  b. Cache poisoning surface (read-only): header unkeyed (X-Forwarded-Host,
     X-Forwarded-Scheme, X-Forwarded-Proto, X-Original-URL) dengan marker inert
     unik; flag jika marker terefleksi di response DAN response kelihatan
     cacheable (Cache-Control / Age / X-Cache / Vary).
  c. Cache already poisoned: cek indikasi body saat ini sudah mengandung payload
     asing (tag <script> aneh, refleksi parameter tanpa diminta, X-Cache: HIT
     dengan body tidak sesuai origin).

Batas: maksimal ~8 request, hormati global request budget & delay,
tidak destructive, tidak mencoba RCE/webshell, tidak menulis file.
"""

import re
import random
import string

from probex.modules.base import BaseModule

# Path traversal signature yang sudah well-known dipublikasikan (deteksi saja,
# tanpa payload eksploitasi RCE/shell).
TRAVERSAL_PATHS = [
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/Windows/win.ini",
    "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
]

# Header unkeyed yang umum dipakai cache/proxy.
UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-URL",
]

MARKER_PREFIX = "probex-marker-"

# Versi Apache yang diketahui RENTAN terhadap CVE mod_cgi path traversal
# (patched sejak 2.4.51). Hanya referensi fingerprint, bukan deteksi eksploitasi.
APACHE_VULN_VERSIONS = {"2.4.49", "2.4.50"}
APACHE_CVE_REFS = {
    "2.4.49": "CVE-2021-41773 (mod_cgi path traversal)",
    "2.4.50": "CVE-2021-42013 (mod_cgi path traversal bypass)",
}


def _random_suffix(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _apache_version(headers: dict) -> str:
    """Ekstrak versi Apache dari header Server / X-Powered-By."""
    for key in ("Server", "X-Powered-By"):
        val = headers.get(key) or headers.get(key.lower()) or ""
        m = re.search(r"Apache/(\d+\.\d+\.\d+)", val, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _is_cacheable(headers: dict) -> bool:
    """Heuristik: response kelihatan cacheable."""
    h = {k.lower(): v for k, v in headers.items()}
    if h.get("age") is not None:
        return True
    if h.get("x-cache"):
        return True
    cc = h.get("cache-control", "")
    if cc and "no-store" not in cc.lower() and "private" not in cc.lower():
        return True
    if h.get("vary"):
        return True
    return False


def _looks_poisoned(body: str, headers: dict) -> bool:
    """Heuristik indikasi cache sudah pernah diracuni oleh pihak lain."""
    h = {k.lower(): v for k, v in headers.items()}
    if re.search(r"<script[^>]*>.*?</script>", body or "", re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"(?:eval|alert|document\.cookie)\s*\(", body or ""):
        return True
    if h.get("x-cache", "").upper() == "HIT" and ("<html" not in (body or "").lower()):
        return True
    return False


class ApachePoisoningModule(BaseModule):
    name = "Apache Cache Poisoning / Vuln Detector"

    def run(self) -> None:
        target = str(self.config.base_url)
        if not target:
            self.log("target kosong, lewati Apache poisoning check")
            return

        used = 0
        limit = 8

        def req(path: str, headers: dict | None = None):
            nonlocal used
            if used >= limit or not self.config.can_request() or self.rm.stopped_by_429:
                return None
            used += 1
            try:
                return self.rm.request("GET", target.rstrip("/") + path, headers=headers)
            except Exception:
                return None

        # --- a. Version/CVE fingerprint -------------------------------------
        resp = req("/")
        server_ver = ""
        if resp is not None:
            server_ver = _apache_version(resp.headers or {})
        if server_ver:
            self.log(f"Server header: Apache/{server_ver}")
            if server_ver in APACHE_VULN_VERSIONS:
                self.reporter.add_finding(
                    title=f"Apache {server_ver} possibly vulnerable to {APACHE_CVE_REFS[server_ver]}",
                    severity="high",
                    detail=(
                        "Versi Apache terdeteksi rentan terhadap path-traversal mod_cgi "
                        "berdasarkan fingerprint header Server (deteksi saja, tidak dieksploitasi)."
                    ),
                    evidence=f"Server: Apache/{server_ver}",
                    url=target,
                    method="GET",
                    evidence_snippet=f"Apache/{server_ver} -> {APACHE_CVE_REFS[server_ver]}",
                )
            else:
                self.log(f"Apache/{server_ver} tidak dalam daftar versi rentan (fingerprint)")

        # Coba path traversal signature pada root (deteksi indikasi patched vs mungkin rentan).
        for path in TRAVERSAL_PATHS:
            if used >= limit:
                break
            r = req(path)
            if r is None:
                continue
            body = r.text or ""
            if r.status_code == 200 and ("root:" in body or "[extensions]" in body.lower()):
                self.reporter.add_finding(
                    title="Possible mod_cgi path traversal (signature match)",
                    severity="medium",
                    detail=(
                        f"Request ke {path} mengembalikan HTTP 200 dengan body yang mengandung "
                        "indikasi file sistem (mungkin rentan, verifikasi manual disarankan)."
                    ),
                    evidence=body[:200],
                    url=target.rstrip("/") + path,
                    method="GET",
                    evidence_snippet=f"HTTP {r.status_code} on {path}: {body[:120]}",
                )
                break
            elif r.status_code in (403, 404, 400):
                self.log(f"{path} -> HTTP {r.status_code} (kemungkinan ter-patch/terblokir)")

        # --- b. Cache poisoning surface (read-only) -------------------------
        marker = f"{MARKER_PREFIX}{_random_suffix()}"
        for header_name in UNKEYED_HEADERS:
            if used >= limit:
                break
            r = req("/", headers={header_name: f"evil{_random_suffix()}.example.com", "X-ProbeX-Marker": marker})
            if r is None:
                continue
            body = r.text or ""
            reflected = marker in body or f"evil{marker.split('-')[-1]}" in body
            if reflected and _is_cacheable(r.headers or {}):
                self.reporter.add_finding(
                    title="Potential unkeyed-header cache poisoning surface",
                    severity="medium",
                    detail=(
                        f"Header {header_name} berisi marker inert terefleksi di response dan "
                        "response kelihatan cacheable (Cache-Control/Age/X-Cache/Vary). "
                        "BUKAN bukti eksploitasi berhasil — hanya permukaan risiko."
                    ),
                    evidence=f"Header {header_name} echoed; cacheable headers present",
                    url=target,
                    method="GET",
                    parameter=header_name,
                    evidence_snippet=f"marker reflected + cacheable response via {header_name}",
                )
                break

        # --- c. Cache already poisoned? -------------------------------------
        if resp is not None:
            body = resp.text or ""
            if _looks_poisoned(body, resp.headers or {}):
                self.reporter.add_finding(
                    title="Cache appears already poisoned",
                    severity="critical",
                    detail=(
                        "Response GET biasa mengindikasikan payload/marker asing yang "
                        "mungkin telah diinject ke cache oleh pihak lain (verifikasi manual)."
                    ),
                    evidence=body[:300],
                    url=target,
                    method="GET",
                    evidence_snippet="suspicious reflected payload / X-Cache: HIT mismatch",
                )
            else:
                self.reporter.add_finding(
                    title="No cache poisoning indicators detected",
                    severity="info",
                    detail="Tidak ada indikasi cache sudah terinjeksi payload aneh saat pemindaian.",
                    evidence="-",
                    url=target,
                    method="GET",
                    evidence_snippet="clean GET response",
                )

        self.log(f"selesai (requests used: {used}/{limit})")
