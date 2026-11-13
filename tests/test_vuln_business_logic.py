"""Tes detektor Business Logic (vuln_business_logic)."""

from __future__ import annotations

from probex.modules.vuln_business_logic import BusinessLogicDetection


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = {}
        self.url = ""
        self.cookies = []


class _RM:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.default = _Resp()
        self.calls = []
        self.stopped_by_429 = False
        self.stopped_by_overload = False
        self.session = type("S", (), {"cookies": []})()

    def can_request(self):
        return True

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return self.default

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return self.default

    def is_same_origin(self, url):
        return True


class _Config:
    base_url = "http://127.0.0.1:8080/checkout?harga=10000"

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


def _module(responses=None, endpoints=None, runtime_context=None, config=None):
    rm = _RM(responses)
    reporter = _Reporter()
    reporter.endpoints = endpoints or ["http://127.0.0.1:8080/checkout?harga=10000"]
    reporter.runtime_context = runtime_context or {}
    return BusinessLogicDetection(config or _Config(), rm, reporter, _Console()), rm, reporter


def test_form_dengan_field_bisnis():
    reporter = _Reporter()
    reporter.runtime_context = {
        "forms": [{"action": "http://127.0.0.1:8080/checkout", "method": "POST",
                   "fields": [{"name": "harga", "type": "number", "value": "10000"},
                              {"name": "kupon", "type": "text", "value": ""}]}]
    }
    mod, rm, reporter = _module(runtime_context=reporter.runtime_context,
                                endpoints=["http://127.0.0.1:8080/about"])
    mod.run()
    bl = [f for f in reporter.findings if f["type"] == "business_logic"]
    assert bl, f"harus ada temuan business logic, dapat: {reporter.findings}"
    assert bl[0]["severity"] == "Bervariasi"
    assert bl[0]["confidence"] == "Rendah"
    assert "verifikasi manual" in bl[0]["title"]
    assert set(bl[0].keys()) >= {"id", "type", "severity", "confidence", "title",
                                 "description", "location", "evidence",
                                 "recommendation", "references"}


def test_parameter_bisnis_di_url():
    mod, rm, reporter = _module()
    mod.run()
    bl = [f for f in reporter.findings if f["type"] == "business_logic"
          and f["location"]["parameter_in"] == "query"]
    assert bl, f"harus ada temuan parameter bisnis, dapat: {reporter.findings}"
    assert bl[0]["location"]["parameter"] == "harga"


def test_tanpa_logika_bisnis_tidak_ada_temuan():
    config = _Config()
    config.base_url = "http://127.0.0.1:8080/about"
    reporter = _Reporter()
    reporter.runtime_context = {"forms": []}
    mod, rm, reporter = _module(runtime_context=reporter.runtime_context,
                                endpoints=["http://127.0.0.1:8080/about"],
                                config=config)
    mod.run()
    bl = [f for f in reporter.findings if f["type"] == "business_logic"]
    assert bl == [], f"tidak boleh ada temuan, dapat: {bl}"
