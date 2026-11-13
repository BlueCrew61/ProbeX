"""Parameter manipulation — authorized CTF labs only.

Looks for parameters that hint at privilege (admin, role, permission, access,
auth, user, ticket, state) and tries flipping them to privileged values
(true / 1 / admin / root / service). Also tests adding such parameters to
endpoints that lack them. Read-only observation: we report what changes, we
never modify server state.
"""

from __future__ import annotations

from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .base import BaseModule
from probex.utils.params import inject_param

# Kunci parameter yang biasanya berkaitan dengan hak istimewa.
PRIV_KEYS = (
    "admin", "administrator", "role", "roles", "permission", "permissions",
    "access", "access_level", "auth", "authenticated", "user", "username",
    "userid", "user_id", "uid", "account", "account_type", "is_admin",
    "is_admin=True", "staff", "superuser", "ticket", "state", "level",
    "privilege", "group", "groups",
)
# Nilai coba yang biasanya naikkan hak akses.
PRIV_VALUES = ("true", "1", "yes", "admin", "administrator", "root", "service", "superuser")


def _is_priv_key(key: str) -> bool:
    lk = key.lower()
    return any(k in lk for k in PRIV_KEYS)


class ParamManipModule(BaseModule):
    name = "Parameter Manipulation (admin=true / role bypass)"

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: active exploitation requires --no-safe")
            return

        self.log("Probing endpoints for privilege parameter manipulation")

        targets = self.endpoints()
        tested = 0
        for target in targets:
            if not self.budget_ok():
                self.log_skip("Budget habis atau target rate-limit, berhenti")
                break
            if not target.startswith(("http://", "https://")):
                continue
            tested += 1
            hit = self._test_url(target)
            if hit:
                self.reporter.add_finding(
                    f"Privilege parameter manipulation: {target}",
                    severity="high",
                    detail=hit["detail"],
                    evidence=hit["evidence"][:500],
                    url=target,
                    method="GET",
                    parameter="",
                    evidence_snippet=hit["evidence"][:300],
                )
                self.log_hit(f"Privilege param change affected response: {target}")
        if tested == 0:
            self.log("No endpoints available for parameter manipulation")

    def _test_url(self, url: str) -> Optional[dict]:
        """Baseline GET, lalu balik/tambah parameter hak istimewa dan bandingkan."""
        baseline = self.rm.get(url, allow_redirects=False)
        if baseline is None:
            return None
        base_code = baseline.status_code
        base_body = baseline.text or ""

        changed: List[dict] = []

        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        # Balik parameter yang nilainya menunjukkan hak istimewa.
        for key, value in params:
            if _is_priv_key(key):
                for newval in PRIV_VALUES:
                    if newval.lower() == value.lower():
                        continue
                    test_url = inject_param(url, key, newval)
                    hit = self._compare(url, test_url, base_code, base_body)
                    if hit:
                        changed.append(hit)
                        break

        # Tambah parameter hak istimewa yang belum ada.
        if not any(_is_priv_key(k) for k, _ in params):
            for newval in ("true", "1", "admin"):
                test_url = inject_param(url, "admin", newval)
                hit = self._compare(url, test_url, base_code, base_body)
                if hit:
                    changed.append(hit)
                    break

        if changed:
            details = "; ".join(c["detail"] for c in changed[:3])
            evidence = " | ".join(c["evidence"] for c in changed[:3])
            return {"detail": details, "evidence": evidence}
        return None

    def _compare(self, original: str, test_url: str,
                 base_code: int, base_body: str) -> Optional[dict]:
        if not self.config.can_request():
            return None
        resp = self.rm.get(test_url, allow_redirects=False)
        if resp is None:
            return None
        if resp.status_code != base_code or (resp.text or "") != base_body:
            return {
                "detail": (
                    f"Changing params produced status {resp.status_code} "
                    f"(baseline {base_code}) and body differs at {test_url}"
                ),
                "evidence": f"{original} -> {test_url} | status={resp.status_code} | "
                            f"body={(resp.text or '')[:200]}",
            }
        return None
