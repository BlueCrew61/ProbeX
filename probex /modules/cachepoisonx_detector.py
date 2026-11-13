"""Cache poisoning DETEKSI (read-only, bounded).

Mode SCAN — terpisah dari mode injeksi. Hanya mendeteksi apakah header
unkeyed direfleksikan di response dan response kelihatan cacheable, lalu
memverifikasi dengan replay tanpa header (harus cache HIT). Tidak menanam
payload dan tidak mengubah state cache target.
"""

from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.reporter import Reporter
from probex.modules.base import BaseModule

from probex.modules.cachepoisonx.poisoning import (
    CachePoisonTester,
    UNKEYED_HEADER_CANDIDATES,
)


class _ProbeXLimiter:
    """Adaptasi RequestManager ProbeX jadi antarmuka limiter CachePoisonX.

    Hanya mengatur pacing (delay antar request). Budget tetap dikelola oleh
    pemanggil (Scanner) melalui config.can_request() sebelum setiap tahap.
    """

    def __init__(self, rm: RequestManager):
        self.rm = rm

    def wait(self):
        self.rm._pace()


class CachePoisoningDetectorModule(BaseModule):
    name = "Cache Poisoning Detector (read-only)"

    def run(self) -> None:
        target = str(self.config.base_url)
        if not target:
            self.log("target kosong, lewati cache poisoning detector")
            return

        if not self.config.can_request():
            self.log("request budget habis, lewati")
            return

        tester = CachePoisonTester(
            limiter=_ProbeXLimiter(self.rm), timeout=self.config.timeout
        )

        # --- Tahap 1: fingerprint layer cache di URL terpisah ---------------
        fp_url = tester.with_cache_buster(target, tester.cache_buster())
        fingerprint = tester.fingerprint_cache(fp_url)
        self.log(
            "fingerprint: cache_detected="
            f"{fingerprint.get('cache_detected')}"
        )
        for h, v in (fingerprint.get("headers") or {}).items():
            self.log(f"  {h}: {v}")

        # --- Tahap 2: cache key differential matrix ------------------------
        matrix = tester.cache_key_matrix(target, UNKEYED_HEADER_CANDIDATES)
        for m in matrix:
            self.log(
                "  key matrix " + m["header"] +
                ": keyed=" + str(m.get("keyed")) +
                " — " + m.get("note")
            )

        # --- Tahap 3 & 4: probe per header + verifikasi replay --------------
        for header in UNKEYED_HEADER_CANDIDATES:
            if not self.config.can_request() or self.rm.stopped_by_429:
                self.log("budget habis atau 429, berhenti")
                break

            probe = tester.probe_header(target, header)
            if probe.get("error"):
                self.log(header + ": error — " + probe["error"])
                continue
            if not probe.get("reflected"):
                self.log(header + ": tidak direfleksikan")
                continue

            verdict = tester.verify_poisoning(probe)
            ttl = (
                tester.calculate_ttl(probe["url"])
                if verdict.get("verified")
                else None
            )

            verified = verdict.get("verified", False)
            detail = (
                "Header " + header + " direfleksikan di response. "
                "Verifikasi replay: "
            )
            if verified:
                detail += "BERHASIL (cache HIT menyajikan marker)"
            else:
                detail += "gagal — " + verdict.get("reason", "-")

            evidence = probe.get("evidence", "") or verdict.get("evidence", "")

            self.reporter.add_finding(
                title="Potential unkeyed-header cache poisoning (" + header + ")",
                severity="high" if verified else "medium",
                detail=detail,
                evidence=evidence,
                url=target,
                method="GET",
                parameter=header,
                evidence_snippet=evidence[:300],
            )

        self.log("selesai (cache poisoning detector)")
