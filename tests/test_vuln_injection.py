"""Tes detektor Injection (vuln_injection)."""

from __future__ import annotations

from probex.modules.vuln_injection import InjectionDetection


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
    base_url = "http://127.0.0.1:8080/search?q=laptop"

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


def _module(responses):
    rm = _RM(responses)
    reporter = _Reporter()
    reporter.endpoints = ["http://127.0.0.1:8080/search?q=laptop"]
    return InjectionDetection(_Config(), rm, reporter, _Console()), rm, reporter


def test_sql_injection_ditemukan():
    base = "http://127.0.0.1:8080/search?q=laptop"
    responses = {
        base: _Resp(200, "hasil pencarian"),
        base + "'": _Resp(200, "You have an error in your SQL syntax near 'laptop''"),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    sql = [f for f in reporter.findings if f["type"] == "injection"
           and "SQL" in f["title"]]
    assert sql, f"harus ada temuan SQL Injection, dapat: {reporter.findings}"
    f = sql[0]
    assert f["severity"] == "Tinggi"
    assert f["location"]["parameter"] == "q"
    assert set(f.keys()) >= {"id", "type", "severity", "confidence", "title",
                             "description", "location", "evidence",
                             "recommendation", "references"}


def test_template_injection_ditemukan():
    base = "http://127.0.0.1:8080/search?q=laptop"
    responses = {
        base: _Resp(200, "hasil pencarian"),
        "http://127.0.0.1:8080/search?q={{7*7}}": _Resp(200, "hasil pencarian 49"),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    tpl = [f for f in reporter.findings if f["type"] == "injection"
           and "Template" in f["title"]]
    assert tpl, f"harus ada temuan SSTI, dapat: {reporter.findings}"
    assert tpl[0]["severity"] == "Tinggi"
    assert tpl[0]["location"]["parameter"] == "q"


def test_injection_bersih_tidak_ada_temuan():
    base = "http://127.0.0.1:8080/search?q=laptop"
    responses = {base: _Resp(200, "hasil pencarian")}
    mod, rm, reporter = _module(responses)
    mod.run()
    inj = [f for f in reporter.findings if f["type"] == "injection"]
    assert inj == [], f"tidak boleh ada temuan injection, dapat: {inj}"
