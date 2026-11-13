"""Authentication / session flaw.

- Cek flag cookie (HttpOnly, Secure, SameSite) pada cookie yang diamati.
- Deteksi form login; uji hingga 10 percobaan login salah (tanpa brute force
  asli). Jika tidak ada pembatasan/lockout/CAPTCHA -> tandai potensial.
- Pergantian ID sesi setelah login dan masa berlaku token setelah logout
  membutuhkan kredensial uji; tanpa kredensial, dicatat sebagai pembatasan.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from probex.core.vuln import (
    CONF_LOW,
    CONF_MEDIUM,
    Location,
    Finding,
    PARAM_IN_BODY,
    SEVERITY_HIGH,
    TYPE_AUTH_SESSION,
)
from .base import BaseModule

MAX_LOGIN_ATTEMPTS = 10
PASSWORD_FIELD_RE = re.compile(r"password|passwd|sandi|kata_sandi", re.I)
LOGIN_FIELD_RE = re.compile(r"login|signin|masuk|auth", re.I)


class AuthSessionDetection(BaseModule):
    name = "Vuln Scan: Authentication / Session"

    def _cookie_issues(self) -> list[str]:
        issues: list[str] = []
        session = getattr(self.rm, "session", None)
        cookies = getattr(session, "cookies", None) if session else None
        if cookies is None:
            return issues
        for cookie in cookies:
            name = getattr(cookie, "name", str(cookie))
            secure = getattr(cookie, "secure", False)
            rest = getattr(cookie, "_rest", {}) or {}
            httponly = "httponly" in rest
            samesite = rest.get("samesite", "")
            missing = []
            if not secure:
                missing.append("Secure")
            if not httponly:
                missing.append("HttpOnly")
            if not samesite:
                missing.append("SameSite")
            if missing:
                issues.append(f"{name} (hilang: {', '.join(missing)})")
        return issues

    def _find_login_forms(self) -> list[dict[str, Any]]:
        forms = getattr(self.reporter, "runtime_context", {}).get("forms", []) or []
        out = []
        for form in forms:
            fields = form.get("fields", []) or []
            names = " ".join(
                str(f.get("name", "")) for f in fields
            ).lower()
            if PASSWORD_FIELD_RE.search(names) and LOGIN_FIELD_RE.search(
                str(form.get("action", "")) + " " + names
            ):
                out.append(form)
        return out

    def run(self) -> None:
        if not self.budget_ok():
            self.log_skip("Auth/session: budget habis atau rate-limited")
            return
        found = 0

        # --- Cookie flags ---
        issues = self._cookie_issues()
        if issues:
            found += 1
            self.reporter.add_vuln_finding(Finding(
                type=TYPE_AUTH_SESSION,
                severity=SEVERITY_HIGH,
                confidence=CONF_MEDIUM,
                title="Cookie sesi tanpa flag perlindungan",
                description=(
                    "Beberapa cookie sesi tidak memiliki flag HttpOnly, Secure, dan/atau SameSite. "
                    "Cookie dapat terbaca JavaScript (XSS), dikirim melalui HTTP (pencurian sesi), "
                    "atau dikirim dalam lintas situs (CSRF)."
                ),
                location=Location(
                    url=str(getattr(self.config, "base_url", "")),
                    method="GET",
                    parameter_in="cookie",
                    snippet="; ".join(issues[:5]),
                ),
                evidence="Cookie tanpa flag: " + "; ".join(issues),
                recommendation=(
                    "Setel flag HttpOnly, Secure, dan SameSite=Strict (atau Lax) pada setiap cookie "
                    "sesi dan token autentikasi. Gunakan HTTPS untuk seluruh situs."
                ),
                references=[
                    "OWASP Top 10 2021 A07:2021 – Identification and Authentication Failures",
                    "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                ],
            ))
            self.log_hit("Cookie sesi tanpa flag perlindungan ditemukan")
        else:
            self.log("Auth/session: tidak ada cookie diamati atau semua cookie lengkap flag")

        # --- Login attempt limit (maksimal 10 percobaan uji, tanpa brute force) ---
        forms = self._find_login_forms()
        if forms:
            form = forms[0]
            action = form.get("action") or str(getattr(self.config, "base_url", ""))
            fields = form.get("fields", []) or []
            method = (form.get("method") or "POST").upper()
            data = {}
            for f in fields:
                name = f.get("name") or ""
                if not name:
                    continue
                if PASSWORD_FIELD_RE.search(name):
                    data[name] = "salah123"
                elif re.search(r"user|email|username|nama", name, re.I):
                    data[name] = "uji_salah"
                else:
                    data[name] = f.get("value", "")

            locked = False
            for i in range(MAX_LOGIN_ATTEMPTS):
                if not self.budget_ok():
                    break
                if method == "POST":
                    r = self.rm.post(action, data=data)
                else:
                    r = self.rm.get(action, params=data)
                if r is None:
                    break
                text = (r.text or "").lower()
                if r.status_code == 429 or "terlalu banyak" in text or "captcha" in text or "akun terkunci" in text:
                    locked = True
                    break

            if not locked:
                found += 1
                self.reporter.add_vuln_finding(Finding(
                    type=TYPE_AUTH_SESSION,
                    severity=SEVERITY_HIGH,
                    confidence=CONF_MEDIUM,
                    title="Tidak terlihat pembatasan percobaan login",
                    description=(
                        f"{MAX_LOGIN_ATTEMPTS} percobaan login salah dikirim berurutan tanpa "
                        "terlihat lockout, HTTP 429, atau CAPTCHA. Indikasi form rentan brute force."
                    ),
                    location=Location(
                        url=action,
                        method=method,
                        parameter_in=PARAM_IN_BODY,
                        snippet=f"{MAX_LOGIN_ATTEMPTS} percobaan login salah tanpa pembatasan",
                    ),
                    evidence=f"{MAX_LOGIN_ATTEMPTS} login gagal berurutan tanpa respon pembatasan/lockout.",
                    recommendation=(
                        "Terapkan pembatasan percobaan login (maksimal 10 percobaan gagal, lalu "
                        "kunci sementara atau CAPTCHA), rate login per IP, dan akun terkunci setelah "
                        "ambang batas gagal."
                    ),
                    references=[
                        "OWASP Top 10 2021 A07:2021 – Identification and Authentication Failures",
                        "CWE-307: Improper Restriction of Excessive Authentication Attempts",
                    ],
                ))
                self.log_hit("Tidak terlihat pembatasan percobaan login")
            else:
                self.log("Auth/session: pembatasan percobaan login terlihat")
        else:
            self.log("Auth/session: tidak ada form login yang ditemukan (pengujian login dilewati)")
        if not found:
            self.log("Auth/session: tidak ada temuan konklusif")
