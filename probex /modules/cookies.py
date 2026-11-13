"""Cookie and PHP session inspection (values are never logged or reported)."""
from urllib.parse import urlparse
from .base import BaseModule


class CookieInspection(BaseModule):
    name = "Cookie / PHP Session Inspection"

    def run(self) -> None:
        resp = self.rm.get(self.config.base_url)
        if resp is None:
            self.log("No response; cookie inspection skipped")
            return

        host = (urlparse(self.config.base_url).hostname or "").lower()
        cookies = []
        try:
            cookies = [c for c in self.rm.session.cookies if not c.domain or
                       host == c.domain.lstrip(".").lower() or
                       host.endswith("." + c.domain.lstrip(".").lower())]
        except Exception:
            cookies = list(resp.cookies)

        if not cookies:
            self.log("No cookies set")
            return

        names = []
        session_names = []
        for c in cookies:
            name = str(c.name)
            names.append(name)
            lname = name.lower()
            flags = []
            if bool(getattr(c, "secure", False)):
                flags.append("Secure")
            rest = getattr(c, "_rest", {}) or getattr(c, "rest", {}) or {}
            if any(str(k).lower() == "httponly" for k in rest):
                flags.append("HttpOnly")
            self.log(f"Cookie detected: {name} (value redacted); flags={flags or 'none'}")

            if lname == "phpsessid" or lname in ("sessionid", "connect.sid", "jsessionid", "laravel_session"):
                session_names.append(name)
                if lname == "phpsessid":
                    self.log("PHPSESSID session cookie detected (value redacted)", style="yellow")

            if not bool(getattr(c, "secure", False)) and self.config.use_https:
                self.reporter.add_finding(
                    f"Cookie without Secure flag: {name}",
                    severity="medium",
                    detail="Cookie was observed on HTTPS without the Secure attribute.",
                    url=self.config.base_url,
                    method="GET",
                    parameter="",
                    evidence_snippet=name,
                )
            if not any(str(k).lower() == "httponly" for k in rest):
                self.reporter.add_finding(
                    f"Cookie without HttpOnly: {name}",
                    severity="low",
                    detail="Cookie lacks HttpOnly; assess whether it contains a sensitive session value.",
                    url=self.config.base_url,
                    method="GET",
                    parameter="",
                    evidence_snippet=name,
                )

        self.reporter.runtime_context["cookie_names"] = names
        self.reporter.runtime_context["session_cookie_names"] = session_names
        self.reporter.extra["cookie_summary"] = {
            "names": names,
            "session_cookie_names": session_names,
            "values_redacted": True,
        }

        if not session_names:
            self.log("No common PHP/framework session cookie name detected")
