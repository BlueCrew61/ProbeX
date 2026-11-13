"""Base64 detection & decode module.

Scans response bodies and headers for base64-looking strings, decodes them,
and checks whether the decoded payload looks like source code
(PHP / Python / HTML / JS). Purely passive — no exploitation, safe to run
in safe mode.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from .base import BaseModule

# Rough base64 token: runs of [A-Za-z0-9+/=] with length >= 8 (to avoid noise)
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")

# Code heuristics after decoding
_CODE_HINTS = (
    "<?php", "<?=", "eval(", "system(", "exec(", "shell_exec(", "passthru(",
    "import ", "from ", "def ", "class ", "<script", "<html", "<!DOCTYPE",
    "function(", "const ", "let ", "var ", "$_GET", "$_POST", "$_REQUEST",
    "base64_decode", "file_get_contents", "print(", "console.log",
)


def _looks_like_code(text: str) -> bool:
    low = text.lower()
    return any(h.lower() in low for h in _CODE_HINTS)


def _try_decode(token: str) -> Optional[str]:
    """Try to decode a base64 token; return decoded string or None."""
    # Strip padding so we can re-add the correct amount
    clean = token.rstrip("=")
    if len(clean) < 4:
        return None
    # Pad to multiple of 4
    pad = (-len(clean)) % 4
    padded = clean + ("=" * pad)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # Try latin-1 so binary-ish payloads still surface as text
        try:
            return raw.decode("latin-1", errors="replace")
        except Exception:
            return None


class Base64DecodeModule(BaseModule):
    name = "Base64 Decode / Detection"

    def run(self) -> None:
        self.log("Scanning responses for base64-encoded payloads...")

        targets = [self.config.base_url]
        for ep in self.reporter.endpoints:
            if ep not in targets:
                targets.append(ep)

        seen_urls: set[str] = set()
        decoded_code: list[str] = []
        total_decoded = 0

        for url in targets:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if not self.config.can_request() or self.rm.stopped_by_429:
                break

            resp = self.rm.get(url, allow_redirects=True)
            if resp is None:
                continue

            count = self._scan_response(resp, url, decoded_code)
            total_decoded += count

        self.log(f"Base64 tokens decoded: {total_decoded}")

        if decoded_code:
            for snippet in decoded_code:
                self.reporter.add_finding(
                    "Decoded source code (base64)",
                    severity="medium",
                    detail="Decoded payload resembles source code",
                    evidence=snippet[:300],
                    url=url,
                    method="GET",
                    parameter="",
                    evidence_snippet=snippet,
                )

        if not decoded_code:
            self.log("No source code found in base64-decoded payloads")

    def _scan_response(
        self,
        resp,
        url: str,
        decoded_code: list,
    ) -> int:
        """Scan body + headers for base64 tokens; decode and inspect."""
        body = resp.text or ""
        headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        combined = body + "\n" + headers_blob

        # Also try compacted whitespace (base64 sometimes split across lines/tags)
        compact = re.sub(r"\s+", "", combined)

        count = 0
        for text in (combined, compact):
            for token in _B64_TOKEN.findall(text):
                # Skip tokens that are clearly not base64 (e.g. long hex/css)
                if token.lower() in {"content-type", "texthtml", "applicationjson"}:
                    continue
                decoded = _try_decode(token)
                if not decoded:
                    continue
                count += 1

                # Does decoded text look like source code?
                if _looks_like_code(decoded):
                    snippet = decoded.strip()
                    if snippet and snippet not in decoded_code:
                        decoded_code.append(snippet)
                        self.log(f"Base64-decoded code @ {url}: {snippet[:120]}")

        return count
