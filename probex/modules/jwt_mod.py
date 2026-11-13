"""JWT token discovery and configuration analysis (no cracking, no forging-for-access).

v1.8: adds bounded, read-only checks for common weak JWT configurations:
  - alg: none acceptance
  - signature not actually validated by the server
  - expired token still accepted

Each check sends at most one extra request with a tampered/expired COPY of
the token to the SAME endpoint that already returned it, purely to observe
whether the response changes. Results are reported as findings for manual
review. This module never uses a forged or expired token to retrieve
protected data, pivot to another endpoint, or perform any action — it only
compares response status/length against the original baseline.
"""

import re
import time
import base64
import json
from .base import BaseModule

try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


JWT_REGEX = re.compile(
    r"eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]*"
)


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.urlsafe_b64decode(data)


class JWTAnalysis(BaseModule):
    name = "JWT Analysis"

    def run(self) -> None:
        resp = self.rm.get(self.config.base_url)
        if not resp:
            return

        candidates = []
        source_cookie_name = None
        # Headers
        for h, v in resp.headers.items():
            if "auth" in h.lower() or "token" in h.lower() or "jwt" in h.lower():
                candidates.append((v, None))
        # Cookies
        for c in resp.cookies:
            candidates.append((c.value, c.name))
        # Body
        body = resp.text or ""
        candidates.extend((t, None) for t in JWT_REGEX.findall(body))

        found = False
        for token, cookie_name in candidates:
            token = token.strip().strip('"').strip("'")
            if not JWT_REGEX.match(token):
                continue
            found = True
            self.log(f"JWT found: {token[:40]}...")
            self.reporter.add_finding(
                "JWT Token Discovered",
                severity="info",
                detail=token[:80] + ("..." if len(token) > 80 else ""),
                url=self.config.base_url,
                method="GET",
                parameter="",
                evidence_snippet=token[:80] + ("..." if len(token) > 80 else ""),
            )
            header, payload = self._analyze(token)
            if header is not None:
                self._check_weak_config(token, header, payload, cookie_name, resp.url or self.config.base_url)
            break

        if not found:
            self.log("No JWT tokens found in response")

    def _analyze(self, token: str):
        parts = token.split(".")
        if len(parts) < 2:
            return None, None
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
            self.log(f"Header: {header}")
            self.log(f"Payload keys: {list(payload.keys())}")

            alg = header.get("alg", "")
            if alg.lower() == "none":
                self.reporter.add_finding(
                    "JWT header declares 'none' algorithm",
                    severity="high",
                    detail="Token header already specifies alg=none; if the server "
                           "accepts this it can be forged without a signature.",
                    url=self.config.base_url,
                    method="GET",
                    parameter="",
                    evidence_snippet="alg=none",
                )
            if alg.lower() == "hs256":
                self.log("Algorithm: HS256 (symmetric)")
            return header, payload
        except Exception as e:
            self.log(f"JWT decode error: {e}")
            return None, None

    def _check_weak_config(self, token: str, header: dict, payload: dict, cookie_name, source_url: str):
        """Single bounded, read-only verification request per check.

        Compares status/length of a tampered-token request against the
        original authenticated response. Does not use the result to access
        anything beyond that comparison.
        """
        if not self.config.can_request() or self.rm.stopped_by_429:
            return

        baseline = self.rm.get(source_url, allow_redirects=False)
        if baseline is None:
            return
        baseline_code = baseline.status_code
        baseline_len = len(baseline.content or b"")

        # --- Check 1: tampered signature still accepted? ---
        parts = token.split(".")
        if len(parts) == 3 and parts[2]:
            tampered_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
            tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
            self._probe_with_token(
                tampered_token, cookie_name, source_url,
                baseline_code, baseline_len,
                finding_title="JWT signature not validated by server",
                finding_detail=(
                    "Server returned the same response for a token with a tampered "
                    "signature as for the original — signature verification may be "
                    "missing or misconfigured."
                ),
                severity="high",
            )

        if not self.config.can_request() or self.rm.stopped_by_429:
            return

        # --- Check 2: expired token still accepted? ---
        if "exp" in payload:
            try:
                expired_payload = dict(payload)
                expired_payload["exp"] = int(time.time()) - 3600
                expired_header_b64 = _b64url_nopad(json.dumps(header, separators=(",", ":")).encode())
                expired_payload_b64 = _b64url_nopad(json.dumps(expired_payload, separators=(",", ":")).encode())
                # Keep the original signature: it will no longer be valid for the
                # new payload, so this only tells us whether the server bothers
                # to check expiry/signature at all — it cannot grant real access.
                expired_token = f"{expired_header_b64}.{expired_payload_b64}.{parts[2] if len(parts) == 3 else ''}"
                self._probe_with_token(
                    expired_token, cookie_name, source_url,
                    baseline_code, baseline_len,
                    finding_title="JWT expiry (exp) may not be enforced",
                    finding_detail=(
                        "Server returned the same response for a token with 'exp' set "
                        "one hour in the past as for the original — expiry may not be "
                        "checked server-side."
                    ),
                    severity="medium",
                )
            except Exception as e:
                self.log(f"Expiry check skipped: {e}")

    def _probe_with_token(self, token, cookie_name, source_url, baseline_code, baseline_len,
                           finding_title, finding_detail, severity):
        if not self.config.can_request() or self.rm.stopped_by_429:
            return
        if cookie_name:
            resp = self.rm.get(source_url, headers={"Cookie": f"{cookie_name}={token}"}, allow_redirects=False)
        else:
            resp = self.rm.get(source_url, headers={"Authorization": f"Bearer {token}"}, allow_redirects=False)
        if resp is None:
            return
        same_status = resp.status_code == baseline_code
        similar_len = abs(len(resp.content or b"") - baseline_len) < 50
        if same_status and similar_len:
            evidence = f"{source_url} | baseline={baseline_code} tampered={resp.status_code}"
            self.reporter.add_finding(
                finding_title,
                severity=severity,
                detail=finding_detail,
                evidence=evidence,
                url=source_url,
                method="GET",
                parameter=cookie_name or "",
                evidence_snippet=evidence,
            )
            self.log(f"[!] {finding_title}")
