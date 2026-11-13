#!/usr/bin/env python3
"""ProbeX API backend — GUI-friendly wrapper for CachePoisonX detector & injector.

Endpoints (JSON):
  GET  /api/status        — backend info
  POST /api/detect        — cache poisoning detection (read-only)
  POST /api/inject        — cache poisoning injection (attack mode, needs --no-safe equivalent)
  GET  /api/events        — webhook events from lab_cache_origin.py (if running)
  GET  /api/cache/clear   — clear lab cache
  POST /api/shutdown      — stop backend

Run:
    python3 probex_api.py 8777

Then open index.html in browser (same origin or CORS-enabled).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import sys as _sys
import os as _os

_HERE = _os.path.dirname(_os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

# --- import ProbeX modules ---
from probex.modules.cachepoisonx_detector import CachePoisoningDetectorModule
from probex.modules.cachepoisonx_injector import CachePoisoningInjectorModule
from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.reporter import Reporter

from rich.console import Console


class _DummyConsole:
    """Minimal console replacement so modules can print without Rich TTY issues."""
    def print(self, *a, **k):
        pass

    def input(self, *a, **k):
        return "ya"


def _run_detector(target_url: str, max_requests: int = 30, delay: float = 0.0):
    """Run detection module, return findings list."""
    config = Config(
        base_url_override=target_url,
        safe_mode=True,
        low_impact=True,
        max_requests=max_requests,
        delay=delay,
        threads=1,
        timeout=10,
        no_banner=True,
    )
    rm = RequestManager(config)
    reporter = Reporter(_DummyConsole())
    module = CachePoisoningDetectorModule(config, rm, reporter, _DummyConsole())
    module.run()
    return reporter.findings


def _run_injector(target_url: str, max_requests: int = 30, delay: float = 0.0,
                  payloads=None, headers=None):
    """Run injection module, return findings list."""
    config = Config(
        base_url_override=target_url,
        safe_mode=False,
        low_impact=True,
        max_requests=max_requests,
        delay=delay,
        threads=1,
        timeout=10,
        no_banner=True,
    )
    # Exploit allowed gate
    config._exploit_allowed = True
    if payloads:
        config.cache_inject_payload = payloads
    if headers:
        config.cache_inject_header = headers

    rm = RequestManager(config)
    reporter = Reporter(_DummyConsole())
    module = CachePoisoningInjectorModule(config, rm, reporter, _DummyConsole())
    module.run()
    return reporter.findings


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # silence

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json({"ok": True}, 200)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self._send_json({"ok": True, "backend": "probing", "version": "1.8-cachepoisonx-gui"})
            return

        if path == "/api/events":
            # Forward to lab webhook if available
            import requests
            try:
                resp = requests.get("http://127.0.0.1:8899/_events", timeout=3)
                self._send_json(resp.json(), resp.status_code)
            except Exception as e:
                self._send_json({"ok": False, "error": str(e), "hits": [], "count": 0}, 502)
            return

        if path == "/api/cache/clear":
            import requests
            try:
                resp = requests.get("http://127.0.0.1:8899/_cache/clear", timeout=3)
                self._send_json(resp.json(), resp.status_code)
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 502)
            return

        self._send_json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {}

        if path == "/api/detect":
            target = payload.get("target")
            if not target:
                self._send_json({"ok": False, "error": "target required"}, 400)
                return
            try:
                findings = _run_detector(target)
                self._send_json({"ok": True, "mode": "detect", "findings": findings,
                                 "count": len(findings)})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return

        if path == "/api/inject":
            target = payload.get("target")
            if not target:
                self._send_json({"ok": False, "error": "target required"}, 400)
                return
            try:
                findings = _run_injector(
                    target,
                    payloads=payload.get("payloads"),
                    headers=payload.get("headers"),
                )
                injected = [f for f in findings if f.get("severity") == "high"]
                self._send_json({"ok": True, "mode": "inject", "findings": findings,
                                 "injected": len(injected), "count": len(findings)})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return

        self._send_json({"ok": False, "error": "not found"}, 404)


def main():
    port = int(_sys.argv[1]) if len(_sys.argv) > 1 else 8777
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"ProbeX API listening on http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()
