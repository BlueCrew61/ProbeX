"""Tes detektor Sensitive Data Exposure (vuln_data_exposure)."""

from __future__ import annotations

from probex.modules.vuln_data_exposure import DataExposureDetection


class _Resp:
    def __init__(self, status_code=200, text="", headers=None, url=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}
        self.url = url


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
        return self.responses.get(url, self.default)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return self.default

    def is_same_origin(self, url):
        return True


class _Config:
    base_url = "http://127.0.0.1:8080/page?token=abc123"
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


def _module(config=None, responses=None, endpoints=None):
    rm = _RM(responses)
    reporter = _Reporter()
    reporter.endpoints = endpoints or ["http://127.0.0.1:8080/page?token=abc123"]
    return DataExposureDetection(config or _Config(), rm, reporter, _Console()), rm, reporter


def test_http_tanpa_https():
    mod, rm, reporter = _module(responses={"http://127.0.0.1:8080/page?token=abc123": _Resp(200, "ok")})
    mod.run()
    http = [f for f in reporter.findings if f["type"] == "data_exposure"
            and "HTTP" in f["title"]]
    assert http, f"harus ada temuan HTTP, dapat: {reporter.findings}"
    assert http[0]["severity"] == "Sedang"


def test_rahasia_dalam_body():
    config = _Config()
    config.base_url = "https://127.0.0.1:8080/page"
    body = '<script>const api_key = "sk-live_abcdef123456";</script>'
    responses = {"https://127.0.0.1:8080/page": _Resp(200, body, {"content-type": "text/html"})}
    mod, rm, reporter = _module(config=config, responses=responses,
                                endpoints=["https://127.0.0.1:8080/page"])
    mod.run()
    sec = [f for f in reporter.findings if f["type"] == "data_exposure"
           and "rahasia" in f["title"].lower()]
    assert sec, f"harus ada temuan rahasia, dapat: {reporter.findings}"
    assert "sk-live" not in sec[0]["evidence"], "rahasia harus disamarkan"


def test_parameter_sensitif_di_url():
    mod, rm, reporter = _module(responses={"http://127.0.0.1:8080/page?token=abc123": _Resp(200, "ok")})
    mod.run()
    url = [f for f in reporter.findings if f["type"] == "data_exposure"
           and "URL" in f["title"]]
    assert url, f"harus ada temuan parameter sensitif di URL, dapat: {reporter.findings}"
    assert url[0]["location"]["parameter"] == "token"


def test_field_berlebih_json():
    config = _Config()
    config.base_url = "https://127.0.0.1:8080/api/user"
    responses = {"https://127.0.0.1:8080/api/user": _Resp(
        200, '{"id":1,"password":"hash","nik":"123"}',
        {"content-type": "application/json"})}
    mod, rm, reporter = _module(config=config, responses=responses,
                                endpoints=["https://127.0.0.1:8080/api/user"])
    mod.run()
    field = [f for f in reporter.findings if f["type"] == "data_exposure"
             and "berlebih" in f["title"].lower()]
    assert field, f"harus ada temuan field berlebih, dapat: {reporter.findings}"
    assert field[0]["severity"] == "Sedang"
