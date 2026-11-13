"""robots.txt Analysis."""

from urllib.parse import urljoin
from .base import BaseModule


class RobotsAnalysis(BaseModule):
    name = "robots.txt Analysis"

    def run(self) -> None:
        url = urljoin(self.config.base_url + "/", "robots.txt")
        resp = self.rm.get(url)
        if not resp or resp.status_code != 200:
            self.log("robots.txt not found or not accessible")
            return

        self.reporter.add_endpoint(url)
        text = resp.text[:10000]
        self.log(f"robots.txt found ({len(text)} bytes)")

        disallows = []
        allows = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallows.append(path)
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    allows.append(path)

        for path in disallows[:15]:
            self.log(f"Disallow: {path}")
            full = urljoin(self.config.base_url + "/", path.lstrip("/"))
            self.reporter.add_endpoint(full)
            # Interesting paths often hide admin/debug
            interesting = ("admin", "login", "api", "debug", "console", "config", "backup", "secret", "flag", "private")
            if any(k in path.lower() for k in interesting):
                self.reporter.add_finding(
                    f"Interesting path in robots.txt: {path}",
                    severity="info",
                    detail="Disallowed but potentially sensitive",
                    evidence=path,
                    url=url,
                    method="GET",
                    parameter=path,
                    evidence_snippet=path,
                )

        if allows:
            self.log(f"Allow entries: {len(allows)}")
