"""modules.poisoning — Tahap 4: Core Cache Poisoning Testing.

Versi 2. Perubahan penting dibanding v1:

1. CACHE-BUSTER PER TES. Tiap header diuji ke URL unik, jadi tiap tes punya
   cache entry sendiri. v1 menguji 7 header ke URL yang sama sehingga request
   kedua-dst menerima marker dari cache dan dilaporkan "reflected" -> 1 celah
   nyata jadi 7 temuan palsu.
2. FINGERPRINT DI URL TERPISAH. v1 memanggil fingerprint_cache() ke URL target
   sebelum fuzz; request itu mengisi cache dengan body bersih sehingga fuzz
   berikutnya selalu HIT body bersih -> false negative total.
3. CACHE KEY DIFFERENTIAL. Menentukan header mana yang masuk cache key dan mana
   yang tidak lewat perbandingan dua probe ber-cache-buster berbeda.
4. EVIDENCE MENTAH. Tiap temuan menyimpan potongan response di sekitar marker,
   supaya bisa direproduksi manual atau lewat curl.
"""

import re
import uuid
import logging
import requests
from typing import Dict, Any, List, Optional

log = logging.getLogger("CachePoisonX.poisoning")


# Header yang secara umum tidak masuk cache key di proxy/CDN populer.
UNKEYED_HEADER_CANDIDATES = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-HTTP-Host-Override",
    "X-Forwarded-Server",
    "Forwarded",
]

CACHE_HIT_TOKENS = ("HIT", "TCP_HIT", "CACHED")
CACHE_MISS_TOKENS = ("MISS", "BYPASS", "EXPIRED", "DYNAMIC", "TCP_MISS")

# Header response yang menandakan ada layer cache di depan origin.
CACHE_INDICATORS = (
    "X-Cache",
    "X-Cache-Status",
    "CF-Cache-Status",
    "X-Varnish",
    "X-Proxy-Cache",
    "X-Cache-Hits",
    "CDN-Cache-Control",
    "Surrogate-Control",
    "Age",
)


class CachePoisonTester:
    """Detektor cache poisoning berbasis refleksi + verifikasi cache HIT."""

    def __init__(self, limiter=None, timeout: int = 15):
        self.limiter = limiter
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "id-ID,id;q=0.9,en;q=0.8",
                "Connection": "close",  # hindari keep-alive nyangkut di cache
            }
        )

    # ------------------------------------------------------------------
    # Util
    # ------------------------------------------------------------------
    def _wait(self):
        if self.limiter:
            self.limiter.wait()

    @staticmethod
    def cache_buster() -> str:
        """Token acak untuk memaksa request menembus cache (URL unik)."""
        return "cb" + uuid.uuid4().hex[:12]

    @staticmethod
    def with_cache_buster(url: str, token: str) -> str:
        """Sisipkan cache-buster sebagai query param unik."""
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{token}=1"

    @staticmethod
    def classify_cache(status_value: str) -> str:
        """Terjemahkan nilai header cache jadi hit/miss/unknown."""
        v = (status_value or "").upper()
        if not v:
            return "unknown"
        for t in CACHE_HIT_TOKENS:
            if t in v:
                return "hit"
        for t in CACHE_MISS_TOKENS:
            if t in v:
                return "miss"
        return "unknown"

    @staticmethod
    def _cache_header_of(resp) -> Dict[str, str]:
        """Ambil semua header response yang relevan dengan cache."""
        out = {}
        for name in CACHE_INDICATORS:
            if name in resp.headers:
                out[name] = resp.headers[name]
        return out

    # ------------------------------------------------------------------
    # a) fingerprint_cache — SELALU dipanggil ke URL terpisah
    # ------------------------------------------------------------------
    def fingerprint_cache(self, url: str) -> Dict[str, Any]:
        """Deteksi layer cache tanpa merusak URL yang akan diuji.

        Pemanggil WAJIB mengirim URL yang berbeda dari URL target uji (gunakan
        cache buster), karena request ini akan mengisi cache.
        """
        self._wait()
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            log.error(f"Fingerprint gagal untuk {url}: {e}")
            return {"cache_detected": False, "error": str(e), "headers": {}}

        headers = self._cache_header_of(resp)
        detected = any(h in headers for h in CACHE_INDICATORS if h != "Age")
        return {
            "url": url,
            "status_code": resp.status_code,
            "cache_detected": detected,
            "cache_status": self.classify_cache(headers.get("X-Cache", "")),
            "headers": headers,
            "server": resp.headers.get("Server", ""),
        }

    # ------------------------------------------------------------------
    # b) probe unkeyed header — satu header, satu cache-buster
    # ------------------------------------------------------------------
    def probe_header(self, base_url: str, header_name: str) -> Dict[str, Any]:
        """Uji satu header di URL unik. Kembalikan refleksi + bukti mentah.

        Karena URL-nya unik per tes, tidak ada kontaminasi silang antar header.
        """
        marker = uuid.uuid4().hex
        url = self.with_cache_buster(base_url, self.cache_buster())
        req_headers = {header_name: marker}

        self._wait()
        try:
            resp = self.session.get(
                url, timeout=self.timeout, headers=req_headers, allow_redirects=True
            )
        except requests.RequestException as e:
            return {
                "header": header_name,
                "url": url,
                "marker": marker,
                "reflected": False,
                "error": str(e),
                "request_headers": req_headers,
            }

        body = resp.text or ""
        reflected = marker.lower() in body.lower()
        cache_hdrs = self._cache_header_of(resp)

        return {
            "header": header_name,
            "url": url,
            "marker": marker,
            "reflected": reflected,
            "status_code": resp.status_code,
            "cache_status": self.classify_cache(cache_hdrs.get("X-Cache", "")),
            "cache_headers": cache_hdrs,
            "request_headers": req_headers,
            # bukti mentah: potongan body di sekitar marker
            "evidence": self._snippet(body, marker) if reflected else "",
        }

    @staticmethod
    def _snippet(body: str, marker: str, pad: int = 90) -> str:
        """Ambil potongan body di sekitar marker sebagai bukti refleksi."""
        idx = body.lower().find(marker.lower())
        if idx < 0:
            return ""
        start = max(0, idx - pad)
        end = min(len(body), idx + len(marker) + pad)
        return body[start:end].replace("\n", " ").strip()

    # ------------------------------------------------------------------
    # c) verifikasi poisoning — replay TANPA header ke URL yang sama
    # ------------------------------------------------------------------
    def verify_poisoning(self, probe: Dict[str, Any]) -> Dict[str, Any]:
        """Buktikan cache benar-benar teracuni.

        Request ulang ke URL yang SAMA PERSIS tanpa header payload. Kalau marker
        masih muncul, berarti response dari cache sudah tercemar dan korban lain
        akan menerima konten yang sama.
        """
        if not probe.get("reflected"):
            return {"verified": False, "reason": "tidak ada refleksi"}

        url = probe["url"]
        marker = probe["marker"]

        self._wait()
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            return {"verified": False, "reason": f"replay gagal: {e}"}

        body = resp.text or ""
        marker_persists = marker.lower() in body.lower()
        cache_hdrs = self._cache_header_of(resp)
        cache_state = self.classify_cache(cache_hdrs.get("X-Cache", ""))

        verified = marker_persists and cache_state == "hit"
        reason = "ok"
        if not marker_persists:
            reason = "marker hilang saat replay (refleksi saja, bukan poison)"
        elif cache_state != "hit":
            reason = f"marker persist tapi cache tidak HIT (status: {cache_state})"

        return {
            "verified": verified,
            "reason": reason,
            "replay_url": url,
            "marker_persists": marker_persists,
            "cache_status": cache_state,
            "cache_headers": cache_hdrs,
            "status_code": resp.status_code,
            "evidence": self._snippet(body, marker) if marker_persists else "",
        }

    # ------------------------------------------------------------------
    # d) cache key differential matrix
    # ------------------------------------------------------------------
    def cache_key_matrix(self, base_url: str, headers: List[str]) -> List[Dict[str, Any]]:
        """Tentukan header mana yang IKUT jadi cache key dan mana yang tidak.

        Metode: untuk tiap header, kirim dua request ke URL yang SAMA (dengan
        cache-buster yang sama) tapi nilai header BERBEDA.
          - Kalau response kedua mengembalikan nilai pertama -> header TIDAK
            masuk cache key (unkeyed) -> kandidat poisoning.
          - Kalau response kedua mengembalikan nilai kedua -> header masuk cache
            key (keyed) -> aman.
        """
        results = []
        for h in headers:
            m1 = "refA" + uuid.uuid4().hex[:8]
            m2 = "refB" + uuid.uuid4().hex[:8]
            url = self.with_cache_buster(base_url, self.cache_buster())

            self._wait()
            try:
                r1 = self.session.get(url, timeout=self.timeout, headers={h: m1})
                body1 = r1.text or ""
            except requests.RequestException as e:
                results.append({"header": h, "keyed": None, "note": f"error: {e}"})
                continue

            first_present = m1.lower() in body1.lower()

            self._wait()
            try:
                r2 = self.session.get(url, timeout=self.timeout, headers={h: m2})
                body2 = r2.text or ""
            except requests.RequestException as e:
                results.append({"header": h, "keyed": None, "note": f"error: {e}"})
                continue

            saw_first = m1.lower() in body2.lower()
            saw_second = m2.lower() in body2.lower()

            if not first_present:
                verdict, note = None, "header tidak direfleksikan, tidak dapat disimpulkan"
            elif saw_first and not saw_second:
                verdict, note = False, "nilai lama disajikan ulang -> header UNKEYED"
            elif saw_second:
                verdict, note = True, "nilai baru diterima -> header masuk cache key"
            else:
                verdict, note = None, "response kedua tidak memuat nilai apa pun"

            results.append(
                {
                    "header": h,
                    "keyed": verdict,
                    "note": note,
                    "url": url,
                    "marker_first": m1,
                    "marker_second": m2,
                }
            )
        return results

    # ------------------------------------------------------------------
    # e) TTL
    # ------------------------------------------------------------------
    def calculate_ttl(self, url: str) -> Optional[int]:
        """Estimasi lama cache bertahan dari Age / Expires / max-age."""
        self._wait()
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as e:
            log.error(f"TTL gagal untuk {url}: {e}")
            return None

        cc = resp.headers.get("Cache-Control", "")
        m = re.search(r"max-age=(\d+)", cc, re.IGNORECASE)
        if m:
            return int(m.group(1))

        expires = resp.headers.get("Expires", "")
        if expires:
            from datetime import datetime, timezone
            from email.utils import parsedate_to_datetime

            try:
                exp = parsedate_to_datetime(expires)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                delta = (exp - datetime.now(timezone.utc)).total_seconds()
                if delta > 0:
                    return int(delta)
            except (TypeError, ValueError):
                pass

        age = resp.headers.get("Age", "")
        try:
            return int(float(age))
        except (TypeError, ValueError):
            return None