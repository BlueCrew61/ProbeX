"""Safe, low-impact SQL Injection detection (error-based only, no destructive payloads)."""

from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse
from .base import BaseModule

# Only benign error-inducing payloads – no time-based, no UNION heavy, no destructive
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "1'",
    '1"',
]

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysqli_",
    "pg_query",
    "postgresql",
    "sqlite3",
    "ora-",
    "oracle error",
    "microsoft ole db",
    "odbc sql",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "you have an error in your sql",
    "warning: mysql",
    "pdoexception",
    "sqlstate",
]

class SQLiDetection(BaseModule):
    name = "SQL Injection Detection"

    def run(self) -> None:
        # Only test on root and a couple of discovered endpoints that look like they take params
        candidates = [self.config.base_url]
        for ep in self.reporter.endpoints[:5]:
            if ep not in candidates:
                candidates.append(ep)

        tested = 0
        for base_url in candidates:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            if tested >= 8:  # hard limit inside module
                break

            # Append a simple query parameter if none exists
            parsed = urlparse(base_url)
            qs = parse_qs(parsed.query)
            if not qs:
                test_url = base_url.rstrip("/") + "/?id=1"
            else:
                test_url = base_url

            for payload in ERROR_PAYLOADS:
                if not self.config.can_request():
                    break
                # Inject into 'id' or first param
                if "id=" in test_url:
                    attack_url = test_url.replace("id=1", f"id={payload}")
                else:
                    attack_url = test_url + ("&" if "?" in test_url else "?") + f"id={payload}"

                resp = self.rm.get(attack_url)
                tested += 1
                if not resp:
                    continue

                body = (resp.text or "").lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        self.log(f"Possible SQLi indicator: {sig}")
                        self.reporter.add_finding(
                            "Possible SQL Injection (unconfirmed)",
                            severity="medium",
                            detail=f"Error signature '{sig}' with payload",
                            evidence=payload,
                            url=test_url,
                            method="GET",
                            parameter="id",
                            evidence_snippet=payload,
                        )
                        return  # one finding is enough for safe mode

        self.log("No obvious SQL error signatures detected")
