"""Tes detektor Authentication / Session (vuln_auth_session)."""

from __future__ import annotations

from probex.modules.vuln_auth_session import AuthSessionDetection


class _Cookie:
    def __init__(self, name, secure=False, httponly=False, samesite=""):
        self.name = name
        self.secure = secure
        self._rest = {"httponly": httponly, "samesite": samesite}


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()
        self.headers = {}
        self.url = ""
        self.cookies = []


class _RM:
    def __init__(self, responses=None, cookies=None):
        self.responses = responses or {}
        self.default = _Resp()
        self.calls = []
        self.stopped_by_429 = False
        self.stopped_by_overload = False
        self.session = type("S", (), {"cookies": cookies or []})()

    def can_request(self):
        return True

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return self.default

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        return self.responses.get(url, self.default)

    def is_same_origin(self, url):
        return True


class _Config:
    base_url = "http://127.0.0.1:8080/"
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


def _module(rm, reporter=None):
    reporter = reporter or _Reporter()
    reporter.endpoints = ["http://127.0.0.1:8080/"]
    return AuthSessionDetection(_Config(), rm, reporter, _Console()), rm, reporter


def test_cookie_tanpa_flag_dilaporkan():
    rm = _RM(cookies=[_Cookie("sessionid", secure=False, httponly=False)])
    mod, rm, reporter = _module(rm)
    mod.run()
    auth = [f for f in reporter.findings if f["type"] == "auth_session"]
    assert auth, f"harus ada temuan cookie, dapat: {reporter.findings}"
    assert auth[0]["severity"] == "Tinggi"
    assert "HttpOnly" in auth[0]["evidence"] or "Secure" in auth[0]["evidence"]


def test_login_tanpa_pembatasan_dilaporkan():
    rm = _RM()
    for i in range(10):
        rm.responses[f"http://127.0.0.1:8080/login?attempt={i}"] = _Resp(200, "login gagal")
    reporter = _Reporter()
    reporter.runtime_context = {
        "forms": [{"action": "http://127.0.0.1:8080/login", "method": "POST",
                   "fields": [{"name": "user", "type": "text", "value": "uji"},
                              {"name": "password", "type": "password", "value": ""}]}]
    }
    mod, rm, reporter = _module(rm, reporter)
    mod.run()
    auth = [f for f in reporter.findings if f["type"] == "auth_session"
            and "pembatasan" in f["title"]]
    assert auth, f"harus ada temuan pembatasan login, dapat: {reporter.findings}"
    assert auth[0]["severity"] == "Tinggi"


def test_login_dengan_pembatasan_tidak_dilaporkan():
    rm = _RM()
    rm.responses["http://127.0.0.1:8080/login"] = _Resp(429, "terlalu banyak")
    reporter = _Reporter()
    reporter.runtime_context = {
        "forms": [{"action": "http://127.0.0.1:8080/login", "method": "POST",
                   "fields": [{"name": "user", "type": "text", "value": "uji"},
                              {"name": "password", "type": "password", "value": ""}]}]
    }
    mod, rm, reporter = _module(rm, reporter)
    mod.run()
    auth = [f for f in reporter.findings if f["type"] == "auth_session"
            and "pembatasan" in f["title"]]
    assert auth == [], f"dengan pembatasan tidak boleh temuan, dapat: {auth}"
