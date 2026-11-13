"""Subdomain discovery (passive CT + light DNS brute).

Inspired by subfinder workflow – no external binary required.
Sources:
  - Certificate Transparency (crt.sh)
  - Common subdomain wordlist DNS resolution
"""

import socket
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
from urllib.parse import quote

from .base import BaseModule

# Compact high-value wordlist for DNS brute
COMMON_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "portal", "api", "dev", "staging", "test", "beta",
    "app", "cdn", "static", "assets", "img", "images", "media",
    "blog", "shop", "store", "vpn", "remote", "git", "gitlab",
    "jenkins", "ci", "dashboard", "panel", "cpanel", "whm",
    "db", "mysql", "postgres", "redis", "mongo", "elastic",
    "monitor", "grafana", "status", "health", "docs", "wiki",
    "support", "help", "secure", "login", "sso", "auth",
    "m", "mobile", "old", "new", "backup", "bak", "internal",
    "intranet", "corp", "office", "hr", "finance", "pay",
    "payment", "gateway", "bank", "redpay", "sandbox", "demo",
    "uat", "qa", "preprod", "prod", "www2", "web", "server",
    "host", "cloud", "aws", "azure", "gcp", "k8s", "docker",
    "registry", "nexus", "sonar", "jira", "confluence",
    "exchange", "owa", "autodiscover", "lync", "sip",
    "vpn1", "vpn2", "remote1", "fw", "firewall", "proxy",
    "mx", "mx1", "mx2", "ns", "dns", "ntp", "time",
    "ftp2", "sftp", "ssh", "bastion", "jump",
]


class SubdomainEnum(BaseModule):
    name = "Subdomain Discovery"

    def run(self) -> None:
        domain = getattr(self.config, "root_domain", None) or self.config.target_ip
        # Strip scheme/path if user passed a URL-ish domain
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        domain = domain.split(":")[0].lower().strip(".")

        self.log(f"Root domain: {domain}")
        found: Set[str] = set()

        # 1) Certificate Transparency
        ct = self._from_crtsh(domain)
        found.update(ct)
        self.log(f"crt.sh: {len(ct)} unique subdomain(s)")

        # 2) DNS brute (limited, respects budget via thread pool)
        if self.config.can_request():
            brute = self._dns_brute(domain)
            found.update(brute)
            self.log(f"DNS brute: {len(brute)} resolved")

        # Always include apex
        found.add(domain)
        found = {s for s in found if s == domain or s.endswith("." + domain)}

        sorted_subs = sorted(found)
        self.log(f"Total unique: {len(sorted_subs)}")
        for s in sorted_subs[:50]:
            self.log(f"  {s}")
        if len(sorted_subs) > 50:
            self.log(f"  ... and {len(sorted_subs) - 50} more")

        # Store for next stages
        self.reporter.extra["subdomains"] = sorted_subs
        for s in sorted_subs:
            self.reporter.add_endpoint(f"http://{s}")

    def _from_crtsh(self, domain: str) -> Set[str]:
        subs: Set[str] = set()
        if not self.config.can_request():
            return subs
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        try:
            # Use raw requests via our manager (counts as 1 request)
            resp = self.rm.get(url, timeout=20)
            if not resp or resp.status_code != 200:
                return subs
            data = resp.json()
            for entry in data:
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if "@" in name or " " in name or not name:
                        continue
                    if name == domain or name.endswith("." + domain):
                        if re.match(r"^[a-z0-9._-]+$", name):
                            subs.add(name)
        except Exception as e:
            self.log(f"crt.sh error: {e}")
        return subs

    def _dns_brute(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        workers = min(self.config.threads, 2)

        def resolve(sub: str):
            host = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(host)
                return host
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(resolve, s): s for s in COMMON_SUBS[:40]}
            for fut in as_completed(futs):
                host = fut.result()
                if host:
                    found.add(host)
        return found