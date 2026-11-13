"""Race condition / queue jump exploitation — authorized CTF labs only.

Staff importer is blocked at the gate; we try to jump the queue by firing many
identical requests at the same ticket/queue endpoint concurrently and watching
for responses that differ (e.g. a ticket granted to an early request while a
later one is rejected, or both accepted). Purely observational: we never
modify server state beyond the requests we send.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .base import BaseModule
from probex.utils.concurrency import bounded_parallel

# Common queue / ticket / import endpoints to probe.
QUEUE_PATHS = [
    "/ticket", "/tickets", "/queue", "/join", "/import", "/staff/import",
    "/api/ticket", "/api/queue", "/api/import", "/reserve", "/booking",
    "/checkout", "/submit", "/apply",
]


def _single_probe(url: str) -> Optional[Tuple[int, str]]:
    """Satu GET — dipanggil oleh pemanggil yang sudah punya RequestManager."""
    # Placeholder; RequestManager di-inject lewat closure di _race_test.
    raise NotImplementedError("use _race_test instead")


class RaceConditionModule(BaseModule):
    name = "Race Condition / Queue Jump"

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: active exploitation requires --no-safe")
            return

        self.log("Probing queue/ticket endpoints for race-condition jump")

        parsed = urlparse(self.config.base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found: List[dict] = []
        for path in QUEUE_PATHS:
            if not self.config.can_request():
                break
            url = urljoin(base + "/", path.lstrip("/"))
            # Satu probe dulu untuk lihat endpoint ada atau tidak.
            resp = self.rm.get(url, allow_redirects=False)
            if resp is None:
                continue
            if resp.status_code in (404, 405, 501):
                continue
            self.log(f"[{resp.status_code}] {url} — endpoint responds; testing race")
            result = self._race_test(url)
            if result:
                found.append(result)
                self.reporter.add_finding(
                    f"Race condition / queue jump: {url}",
                    severity="high",
                    detail=result["detail"],
                    evidence=result["evidence"][:500],
                    url=url,
                    method="GET",
                    parameter="",
                    evidence_snippet=result["evidence"][:500],
                )
        if not found:
            self.log("No exploitable race condition detected at queue endpoints")

    def _race_test(self, url: str) -> Optional[dict]:
        """Fire N identical requests concurrently; bandingkan status/body."""

        def fire() -> Optional[Tuple[int, str]]:
            if not self.config.can_request():
                return None
            resp = self.rm.get(url, allow_redirects=False)
            if resp is None:
                return None
            return (resp.status_code, (resp.text or "")[:500])

        count = 8 if not self.config.low_impact else 4
        results = bounded_parallel(
            fire,
            range(count),
            budget_ok=self.budget_ok,
            max_workers=count,
        )

        codes = [r[0] for r in results if r is not None and r[0] is not None]
        bodies = [r[1] or "" for r in results if r is not None and r[1] is not None]

        if not codes:
            return None

        unique_codes = set(codes)
        unique_bodies = set(bodies)

        # Race diduga ketika request identik mengembalikan status berbeda atau
        # body yang materiálně berbeda (ticket granted vs rejected).
        if len(unique_codes) > 1 or len(unique_bodies) > 1:
            detail = (
                f"{count} identical requests to {url} returned non-uniform "
                f"results: status codes {sorted(unique_codes)}, "
                f"{len(unique_bodies)} distinct body(s)"
            )
            return {
                "url": url,
                "detail": detail,
                "evidence": f"codes={sorted(unique_codes)} | bodies: "
                            + " || ".join(sorted(set(b[:120] for b in bodies))[:4]),
            }
        return None
