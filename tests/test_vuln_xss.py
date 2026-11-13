"""Tes detektor XSS (vuln_xss)."""

from __future__ import annotations

from probex.modules.vuln_xss import XSSDetection

import random


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = {}
        self.url = ""
        self.cookies = []


class _RM:
    def __init__(self, responses=None, default=None):
        self.responses = responses or {}
        self.default = default or _Resp()
        self.calls = []
        self.stopped_by_429 = False
        self.stopped_by_overload = False
        self.session = type("S", (), {"cookies": []})()

    def can_request(self):
        return True

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return self.responses.get(url, self.default)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return self.default

    def is_same_origin(self, url):
        return True


class _Config:
    base_url = "http://127.0.0.1:8080/page?name=contoh"

    def can_request(self):
        return True


class _Console:
    def print(self, *a, **k):
        pass


class _Reporter:
    def __init__(self):
        self.findings = []
        self.endpoints = []
        self.runtime_context = {}

    def add_vuln_finding(self, finding):
        self.findings.append(finding.to_dict())

    def add_endpoint(self, url):
        if url not in self.endpoints:
            self.endpoints.append(url)


def _module(responses=None, endpoints=None):
    rm = _RM(responses)
    reporter = _Reporter()
    reporter.endpoints = endpoints or ["http://127.0.0.1:8080/page?name=contoh"]
    return XSSDetection(_Config(), rm, reporter, _Console()), rm, reporter


def test_xss_refleksi_ditemukan(monkeypatch):
    monkeypatch.setattr(random, "randint", lambda low, high: 123456)
    base = "http://127.0.0.1:8080/page?name=contoh"
    canary_url = "http://127.0.0.1:8080/page?name=ProbeXCanary123456"
    responses = {
        base: _Resp(200, "halaman contoh"),
        canary_url: _Resp(200, "halaman ProbeXCanary123456 tanpa encoding"),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    xss = [f for f in reporter.findings if f["type"] == "xss"]
    assert xss, f"harus ada temuan XSS, dapat: {reporter.findings}"
    assert xss[0]["severity"] == "Sedang"
    assert xss[0]["confidence"] == "Tinggi"
    assert xss[0]["location"]["parameter"] == "name"
    assert set(xss[0].keys()) >= {"id", "type", "severity", "confidence", "title",
                                  "description", "location", "evidence",
                                  "recommendation", "references"}


def test_xss_sink_dom_ditemukan():
    endpoints = ["http://127.0.0.1:8080/app.js"]
    responses = {
        "http://127.0.0.1:8080/page?name=contoh": _Resp(200, "halaman"),
        "http://127.0.0.1:8080/app.js": _Resp(200, "var x = location.hash; innerHTML = x;"),
    }
    mod, rm, reporter = _module(responses, endpoints)
    mod.run()
    sink = [f for f in reporter.findings if f["type"] == "xss"
            and f["location"].get("file") == "http://127.0.0.1:8080/app.js"]
    assert sink, f"harus ada temuan sink DOM, dapat: {reporter.findings}"
    assert sink[0]["location"]["line"] >= 1
    assert sink[0]["confidence"] == "Rendah"


def test_xss_terencode_tidak_dilaporkan():
    base = "http://127.0.0.1:8080/page?name=contoh"
    canary_url = "http://127.0.0.1:8080/page?name=ProbeXCanary123456"
    responses = {
        base: _Resp(200, "halaman"),
        canary_url: _Resp(200, "halaman &quot;ProbeXCanary123456&quot;"),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    xss = [f for f in reporter.findings if f["type"] == "xss"]
    assert xss == [], f"canary ter-encode tidak boleh temuan, dapat: {xss}"
