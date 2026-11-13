"""Tes detektor Security Misconfiguration (vuln_misconfig)."""

from __future__ import annotations

from probex.modules.vuln_misconfig import MisconfigDetection


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
    base_url = "http://127.0.0.1:8080/"

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
    reporter.endpoints = ["http://127.0.0.1:8080/"]
    return MisconfigDetection(_Config(), rm, reporter, _Console()), rm, reporter


def test_header_keamanan_hilang():
    responses = {"http://127.0.0.1:8080/": _Resp(
        200, "ok", {"content-type": "text/html"})}
    mod, rm, reporter = _module(responses)
    mod.run()
    mis = [f for f in reporter.findings if f["type"] == "misconfig"
           and "Header" in f["title"]]
    assert mis, f"harus ada temuan header hilang, dapat: {reporter.findings}"
    assert mis[0]["severity"] == "Sedang"


def test_cors_longgar():
    responses = {"http://127.0.0.1:8080/": _Resp(
        200, "ok", {"access-control-allow-origin": "*"})}
    mod, rm, reporter = _module(responses)
    mod.run()
    cors = [f for f in reporter.findings if f["type"] == "misconfig"
            and "CORS" in f["title"]]
    assert cors, f"harus ada temuan CORS, dapat: {reporter.findings}"


def test_directory_listing():
    responses = {"http://127.0.0.1:8080/": _Resp(
        200, "Index of /assets", {"content-type": "text/html"})}
    mod, rm, reporter = _module(responses)
    mod.run()
    dl = [f for f in reporter.findings if f["type"] == "misconfig"
          and "Directory" in f["title"]]
    assert dl, f"harus ada temuan directory listing, dapat: {reporter.findings}"


def test_path_sensitif_ditemukan():
    responses = {
        "http://127.0.0.1:8080/": _Resp(200, "ok"),
        "http://127.0.0.1:8080/.env": _Resp(200, "api_key=sekret", {"content-type": "text/plain"}),
    }
    mod, rm, reporter = _module(responses)
    mod.run()
    env = [f for f in reporter.findings if f["type"] == "misconfig"
           and ".env" in f["title"]]
    assert env, f"harus ada temuan .env, dapat: {reporter.findings}"
    assert env[0]["location"]["url"].endswith("/.env")
