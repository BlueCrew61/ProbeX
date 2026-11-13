"""Tes modul ip_scan (mock request_manager, tanpa jaringan asli)."""

from probex.core.config import Config
from probex.core.reporter import Reporter
from probex.modules.ip_scan import IpScanModule
from rich.console import Console


class FakeResponse:
    def __init__(self, status_code, headers, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class FakeRM:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
        self.config = Config("http://127.0.0.1:8080/", max_requests=100, delay=0)
        self.stopped_by_429 = False

    def request(self, method, url, headers=None):
        self.calls.append((method, url))
        if not self.responses:
            return FakeResponse(404, {})
        return self.responses.pop(0)


class FakeSocket:
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def _make_module(rm):
    reporter = Reporter(Console(), "/tmp")
    mod = IpScanModule(rm.config, rm, reporter, Console())
    return mod


def test_ip_scan_no_open_ports(monkeypatch):
    # Tidak ada port terbuka -> accessible_hosts kosong, tidak crash
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError))
    rm = FakeRM()
    mod = _make_module(rm)
    mod.run()
    assert mod.reporter.extra.get("accessible_hosts") == []
    assert rm.calls == []  # tidak ada HTTP probing


def test_ip_scan_reports_200_only(monkeypatch):
    # Satu port terbuka, respons HTTP 200 -> dicatat; 404 -> tidak
    calls = {"n": 0}

    def fake_connect(*a, **k):
        calls["n"] += 1
        return FakeSocket()

    monkeypatch.setattr("socket.create_connection", fake_connect)
    rm = FakeRM([
        FakeResponse(200, {"Server": "nginx"}, "<title>Home</title>"),  # http 200
    ])
    mod = _make_module(rm)
    mod.run()
    hosts = mod.reporter.extra.get("accessible_hosts", [])
    assert len(hosts) == 1
    assert hosts[0]["status"] == 200
    assert hosts[0]["url"].startswith("http://")
