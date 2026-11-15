"""Technology Detection."""

import re
from .base import BaseModule


class TechDetection(BaseModule):
    name = "Technology Detection"

    FINGERPRINTS = [
        (r"wp-content|wordpress", "WordPress"),
        (r"drupal", "Drupal"),
        (r"joomla", "Joomla"),
        (r"laravel", "Laravel"),
        (r"django", "Django"),
        (r"flask|werkzeug", "Flask/Werkzeug"),
        (r"express|node\.js", "Node.js/Express"),
        (r"nginx", "Nginx"),
        (r"apache", "Apache"),
        (r"iis|microsoft-iis", "Microsoft IIS"),
        (r"php/?([\d.]+)?", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"react", "React"),
        (r"vue\.js|vuejs", "Vue.js"),
        (r"angular", "Angular"),
        (r"jquery", "jQuery"),
        (r"bootstrap", "Bootstrap"),
        (r"tomcat", "Apache Tomcat"),
        (r"gunicorn|uvicorn", "Python WSGI"),
    ]

    def run(self) -> None:
        resp = self.rm.get(self.config.base_url)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:20000].lower() if resp.text else ""

        # Server header
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            self.reporter.add_tech(server.split("/")[0])
            self.log(f"Server: {server}")
        if powered:
            self.reporter.add_tech(powered)
            self.log(f"X-Powered-By: {powered}")

        combined = f"{server} {powered} {body}"
        found = set()
        for pattern, name in self.FINGERPRINTS:
            if re.search(pattern, combined, re.I):
                found.add(name)

        for tech in sorted(found):
            self.reporter.add_tech(tech)
            self.log(f"Detected: {tech}")

        if not found and not server:
            self.log("No strong technology fingerprint")