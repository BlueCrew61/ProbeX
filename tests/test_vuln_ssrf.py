"""Tes detektor SSRF (vuln_ssrf)."""

from __future__ import annotations

from probex.modules.vuln_ssrf import SSRFDetection


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
    base_url = "http://127.0.0.1:8080/fetch?url=http://contoh.com"
    ssrf_callback = "https://callback-contoh.com/cb"

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
    reporter.endpoints = endpoints or ["http://127.0.0.1:8080/fetch?url=http://contoh.com"]
    return SSRFDetection(config or _Config(), rm, reporter, _Console()), rm, reporter


def test_ssrf_uji_callback_publik():
    base = "http://127.0.0.1:8080/fetch?url=http://contoh.com"
    cb = "https://callback-contoh.com/cb"
    test_url = base + "&url=" + cb
    responses = {test_url: _Resp(200, "dikirim")}
    mod, rm, reporter = _module(responses=responses)
    mod.run()
    assert any(f["type"] == "ssrf" for f in reporter.findings), reporter.findings
    f = [f for f in reporter.findings if f["type"] == "ssrf"][0]
    assert f["severity"] == "Tinggi"
    assert f["location"]["parameter"] == "url"
    assert set(f.keys()) >= {"id", "type", "severity", "confidence", "title",
                             "description", "location", "evidence",
                             "recommendation", "references"}


def test_ssrf_callback_internal_diblokir():
    """Callback ke alamat internal tidak boleh menghasilkan uji aktif."""
    config = _Config()
    config.ssrf_callback = "http://169.254.169.254/latest/meta-data/"
    mod, rm, reporter = _module(config=config)
    mod.run()
    ssrf = [f for f in reporter.findings if f["type"] == "ssrf"]
    assert ssrf == [], f"callback internal harus diblokir, dapat: {ssrf}"


def test_ssrf_tanpa_callback_hanya_identifikasi():
    config = _Config()
    config.ssrf_callback = None
    mod, rm, reporter = _module(config=config)
    mod.run()
    ssrf = [f for f in reporter.findings if f["type"] == "ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0]["confidence"] == "Rendah"
    assert ssrf[0]["location"]["parameter"] == "url"
