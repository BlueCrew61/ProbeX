"""Security Header Analysis."""

from .base import BaseModule

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing – enables HTTPS enforcement",
    "Content-Security-Policy": "CSP missing – XSS mitigation reduced",
    "X-Content-Type-Options": "X-Content-Type-Options missing (nosniff recommended)",
    "X-Frame-Options": "X-Frame-Options missing – clickjacking risk",
    "X-XSS-Protection": "X-XSS-Protection missing (legacy but still useful)",
    "Referrer-Policy": "Referrer-Policy missing",
    "Permissions-Policy": "Permissions-Policy missing",
    "Cross-Origin-Opener-Policy": "COOP missing",
    "Cross-Origin-Resource-Policy": "CORP missing",
}


class HeaderAnalysis(BaseModule):
    name = "Header Analysis"

    def run(self) -> None:
        resp = self.rm.get(self.config.base_url)
        if not resp:
            self.log("Failed to fetch headers")
            return

        present = []
        missing = []
        for header, desc in SECURITY_HEADERS.items():
            if header in resp.headers:
                present.append(header)
                self.log(f"Present: {header} = {resp.headers[header][:60]}")
            else:
                missing.append(header)
                self.reporter.add_finding(
                    f"Missing Security Header: {header}",
                    severity="low",
                    detail=desc,
                    url=self.config.base_url,
                    method="GET",
                    parameter="",
                    evidence_snippet=header,
                )

        if missing:
            self.log(f"Missing {len(missing)} security header(s)")
        else:
            self.log("All common security headers present")

        # Interesting headers
        for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
            if h in resp.headers:
                val = resp.headers[h]
                self.log(f"Interesting: {h}: {val}")
                self.reporter.add_finding(
                    f"Information Disclosure: {h}",
                    severity="info",
                    detail=val,
                    url=self.config.base_url,
                    method="GET",
                    parameter="",
                    evidence_snippet=val,
                )
