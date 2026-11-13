"""CTF Job module — fetch challenge details by job ID and run appropriate modules.

Authorized CTF labs only. When config.job_id is set, this module attempts to
retrieve challenge metadata (target URL, category) from common
CTF platform endpoints and configures the scanner to go after it.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from probex.modules.base import BaseModule


class JobModule(BaseModule):
    name = "CTF Job Fetcher"

    def __init__(self, config, request_manager, reporter, console):
        super().__init__(config, request_manager, reporter, console)
        self.job_id = config.job_id or ""

    def run(self) -> None:
        if not self.job_id:
            self.console.print("[dim]  No job ID configured; skipping Job module.[/dim]")
            return

        self.console.print(f"[bold cyan][+][/bold cyan] Fetching CTF job: {self.job_id}")

        challenge = self._fetch_challenge()
        if challenge is None:
            self.reporter.add_finding(
                "CTF Job Fetch Failed",
                severity="warning",
                detail=f"Could not retrieve challenge details for job {self.job_id}",
                evidence=self.job_id,
                url=self.config.base_url,
                method="GET",
                parameter="job_id",
                evidence_snippet=self.job_id,
            )
            self.console.print("[yellow]  [!] Could not fetch challenge details.[/yellow]")
            return

        target = challenge.get("target", "")
        category = challenge.get("category", "web")

        self.console.print(f"  Target   : {target}")
        self.console.print(f"  Category : {category}")

        # Override scanner config so later modules use the job's target
        if target:
            self.config.base_url_override = target.rstrip("/")

        # Pick modules based on category
        cat = (category or "").lower()
        modules: list[str] = []
        if "web" in cat or "http" in cat:
            modules = [
                "headers", "cookies", "tech", "robots", "flow",
                "html", "xss", "ssti", "sqli", "lfi", "auth",
            ]
        elif "pwn" in cat or "binary" in cat:
            modules = ["recon"]
        elif "crypto" in cat:
            modules = ["recon"]
        elif "rev" in cat or "reverse" in cat:
            modules = ["recon"]
        elif "misc" in cat:
            modules = ["recon"]
        else:
            modules = ["headers", "cookies", "tech", "flow"]

        self.config.modules = modules
        self.console.print(f"  Modules  : {', '.join(modules)}")

        self.reporter.add_finding(
            "CTF Job Loaded",
            severity="info",
            detail=f"Job {self.job_id}: {category} challenge targeting {target}",
            evidence=target,
            url=target or self.config.base_url,
            method="GET",
            parameter="job_id",
            evidence_snippet=target,
        )

    # --- internal helpers -------------------------------------------------

    def _fetch_challenge(self) -> Optional[Dict[str, Any]]:
        """Try common CTF platform API patterns to get challenge details."""
        bases = [
            f"http://103.160.212.211/api/jobs/{self.job_id}",
            f"http://103.160.212.211/api/challenges/{self.job_id}",
            f"http://103.160.212.211/job/{self.job_id}",
            f"https://103.160.212.211/api/jobs/{self.job_id}",
        ]
        for url in bases:
            try:
                resp = self.rm.get(url, timeout=8)
                if resp is None:
                    continue
                data = resp.json()
                if isinstance(data, dict) and ("target" in data or "challenge" in data):
                    return self._normalize(data)
            except Exception:
                continue
        return None

    @staticmethod
    def _normalize(data: Dict[str, Any]) -> Dict[str, Any]:
        """Map platform-specific keys to common fields."""
        challenge = data.get("challenge", data)
        return {
            "target": challenge.get("target") or challenge.get("url") or challenge.get("host", ""),
            "category": challenge.get("category") or challenge.get("type") or "web",
        }
