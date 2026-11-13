"""Sourcemap exposure scanner — authorized CTF labs only.

Deteksi file .map (Webpack/Vite/Rollup/Parcel sourcemap) yang terekspos pada
target web. Jika ditemukan, ambil isinya, cari secrets/endpoints tersembunyi,
dan lapor fungsi undocumented yang bisa dieksploitasi.

Semua probe read-only: setiap .map diambil sekali, tidak menulis payload.
Diposisikan agar endpoint baru dari sourcemap juga dicek modul lain.
"""

from __future__ import annotations

import json
import re
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

from .base import BaseModule

# Path umum tempat file .map biasanya diletakkan.
COMMON_MAP_PATHS = [
    "/static/js/main.js.map",
    "/static/js/app.js.map",
    "/static/js/bundle.js.map",
    "/assets/index.js.map",
    "/assets/main.js.map",
    "/js/app.js.map",
    "/js/main.js.map",
    "/bundle.js.map",
    "/_next/static/chunks/main.js.map",
    "/webpack.map",
    "/source.map",
    "/dist/main.js.map",
    "/dist/bundle.js.map",
    "/build/static/js/main.js.map",
]

# Kata kunci yang mencurigakan dalam isi source (dipasangkan dengan label).
SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[:=]\s*[\"']([^\"']+)[\"']", "API key"),
    (r"(?i)secret[_-]?key\s*[:=]\s*[\"']([^\"']+)[\"']", "Secret key"),
    (r"(?i)password\s*[:=]\s*[\"']([^\"']+)[\"']", "Password"),
    (r"(?i)access[_-]?token\s*[:=]\s*[\"']([^\"']+)[\"']", "Access token"),
    (r"(?i)jwt\s*[:=]\s*[\"']([^\"']+)[\"']", "JWT"),
    (r"(?i)stripe[_-]?secret[_-]?key\s*[:=]\s*[\"']([^\"']+)[\"']", "Stripe secret key"),
    (r"(?i)mongodb[s]?\+srv://[^\"'\\s]+", "MongoDB connection string"),
    (r"(?i)postgres(?:ql)?://[^\"'\\s]+", "PostgreSQL connection string"),
    (r"(?i)mysql://[^\"'\\s]+", "MySQL connection string"),
    (r"(?i)aws_access_key_id\s*[:=]\s*[\"']([^\"']+)[\"']", "AWS access key"),
    (r"(?i)private[_-]?key\s*[:=]\s*[\"']([^\"']+)[\"']", "Private key"),
]

# Pola endpoint/API path dalam source JS.
ENDPOINT_PATTERNS = [
    r"/[a-zA-Z0-9_/.-]*(?:api|auth|user|admin|update|delete|create|upload|config|env|secret|key|token)[a-zA-Z0-9_/.-]*",
]


def _extract_strings(text: str) -> List[str]:
    """Ambil string literal dari source code (untuk cari endpoint/secret)."""
    return re.findall('[\'"]([^\'"]+)[\'"]', text)


class SourcemapModule(BaseModule):
    name = "Sourcemap Exposure Scanner"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        parsed_base = urlparse(base)
        netloc = parsed_base.netloc
        scheme = parsed_base.scheme

        found_any = False

        # Coba path .map umum.
        for path in COMMON_MAP_PATHS:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break
            url = f"{scheme}://{netloc}{path}"
            resp = self.rm.get(url, allow_redirects=False, timeout=10)
            if resp is None:
                continue
            if resp.status_code != 200:
                continue
            content_type = (resp.headers.get("content-type") or "").lower()
            body = resp.text or ""
            if not body.strip().startswith("{"):
                continue

            self.log(f"[+] Sourcemap ditemukan: {url} (HTTP {resp.status_code})")
            self.reporter.add_endpoint(url)
            found_any = True

            # Parse JSON sourcemap.
            try:
                smap = json.loads(body)
            except json.JSONDecodeError:
                self.log("    Gagal parse JSON sourcemap")
                continue

            sources = smap.get("sources", []) or []
            sources_content = smap.get("sourcesContent") or []
            names = smap.get("names", []) or []
            output_file = smap.get("file", "")

            self.log(f"    sources={len(sources)}, names={len(names)}, output={output_file}")

            # Cari secrets dan endpoints di sourcesContent.
            for idx, src in enumerate(sources):
                content = sources_content[idx] if idx < len(sources_content) else ""
                if not content:
                    continue

                # Secret detection.
                for pat, label in SECRET_PATTERNS:
                    for m in re.finditer(pat, content):
                        val = m.group(1) if m.groups() else m.group(0)
                        safe_val = "<redacted>" if len(val) > 4 else val
                        detail = f"{label} di {src} ({url})"
                        self.reporter.add_finding(
                            f"Sourcemap exposed {label}",
                            severity="high",
                            detail=detail,
                            evidence=safe_val,
                            url=url,
                            method="GET",
                            parameter="",
                            evidence_snippet=safe_val,
                        )
                        self.log(f"    [!] {label} di {src}: {safe_val}")
                        found_any = True

                # Endpoint detection.
                for ep_pat in ENDPOINT_PATTERNS:
                    for m in re.finditer(ep_pat, content):
                        endpoint = m.group(0)
                        if len(endpoint) < 4:
                            continue
                        detail = f"Endpoint tersembunyi di {src}: {endpoint}"
                        self.reporter.add_finding(
                            "Sourcemap exposed hidden endpoint",
                            severity="medium",
                            detail=detail,
                            evidence=endpoint,
                            url=endpoint,
                            method="GET",
                            parameter="",
                            evidence_snippet=endpoint,
                        )
                        self.reporter.add_endpoint(
                            urljoin(base, endpoint) if endpoint.startswith("/") else endpoint
                        )
                        self.log(f"    [*] Endpoint: {endpoint}")
                        found_any = True

            # Cari function names yang mencurigakan di names array.
            suspicious_names = [
                n for n in names
                if any(k in n.lower() for k in ("admin", "secret", "key", "token", "password", "update", "delete", "debug"))
            ]
            for n in suspicious_names[:10]:
                self.log(f"    [*] Nama fungsi mencurigakan: {n}")
                found_any = True

        if not found_any:
            self.log("Tidak ada sourcemap .map yang terekspos")
