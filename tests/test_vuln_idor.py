"""Tes detektor IDOR (vuln_idor)."""

from __future__ import annotations

from probex.modules.vuln_idor import IDORDetection


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}
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

    def get_stats(self):
        return {"total_requests": len(self.calls)}


class _Config:
    base_url = "http://127.0.0.1:8080/item?id=1"
    ssrf_callback = None

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


def _module(responses=None):
    rm = _RM(responses)
    reporter = _Reporter()
    reporter.endpoints = ["http://127.0.0.1:8080/item?id=1"]
    return IDORDetection(_Config(), rm, reporter, _Console()), rm, reporter


def test_idor_potensial_ditemukan():
    """Dua nilai ID, keduanya HTTP 200, konten berbeda, nilai baru dipantulkan."""
    responses = {
        "http://127.0.0.1:8080/item?id=1": _Resp(200, "item 1"),
        "http://127.0.0.1:8080/item?id=2": _Resp(200, "item 2"),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    assert reporter.findings, "harus ada setidaknya satu temuan IDOR"
    f = reporter.findings[0]
    assert f["type"] == "idor"
    assert f["severity"] == "Tinggi"
    assert f["location"]["parameter"] == "id"
    assert f["location"]["url"] == "http://127.0.0.1:8080/item?id=1"
    assert set(f.keys()) >= {"id", "type", "severity", "confidence", "title",
                             "description", "location", "evidence",
                             "recommendation", "references"}
    assert f["location"]["parameter_in"] == "query"


def test_idor_tidak_ada_indikasi():
    """Keduanya HTTP 200 tapi konten identik -> tidak ada temuan konklusif."""
    body = "item 1"
    responses = {
        "http://127.0.0.1:8080/item?id=1": _Resp(200, body),
        "http://127.0.0.1:8080/item?id=2": _Resp(200, body),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    idor = [f for f in reporter.findings if f["type"] == "idor"]
    assert idor == [], f"tidak boleh ada temuan IDOR, dapat: {idor}"
