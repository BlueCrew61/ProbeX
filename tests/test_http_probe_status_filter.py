"""Tes filter status 200 pada http_probe (tanpa jaringan, request_manager di-mock)."""

from probex.core.config import Config
from probex.modules.http_probe import HTTPProbe
from rich.console import Console


class _FakeResp:
    def __init__(self, code, url, title="T", server="S"):
        self.status_code = code
        self.text = f"<title>{title}</title>"
        self.content = self.text.encode()
        self.headers = {"Server": server}
        self.url = url


class _FakeRM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.index = 0
        self.calls = []
        self.stopped_by_429 = False
        self.stopped_by_overload = False

    def can_request(self):
        return True

    def get(self, url, allow_redirects=True, timeout=8):
        self.calls.append(url)
        if self.index >= len(self.responses):
            return None
        resp = self.responses[self.index]
        self.index += 1
        return resp


class _Reporter:
    def __init__(self, all_status=False):
        self.endpoints = []
        self.extra = {"subdomains": ["evil.test", "admin.test", "good.test"]}
        self.findings = []
        self.all_status = all_status

    def add_endpoint(self, url):
        self.endpoints.append(url)

    def add_finding(self, title, severity="info", detail="", evidence="", **kw):
        self.findings.append({"title": title, "severity": severity, "detail": detail, "evidence": evidence, **kw})


def _make_module(all_status=False):
    cfg = Config(base_url_override="http://127.0.0.1:8080/", all_status=all_status)
    reporter = _Reporter(all_status=all_status)
    # evil.test=200, admin.test=403, good.test=200
    responses = [
        _FakeResp(200, "https://evil.test/", title="Evil Admin"),
        _FakeResp(403, "https://admin.test/", title="Admin"),
        _FakeResp(200, "http://good.test/", title="Good"),
    ]
    rm = _FakeRM(responses)
    return HTTPProbe(cfg, rm, reporter, Console()), reporter, rm


def test_http_probe_only_200_live_by_default():
    m, reporter, rm = _make_module(all_status=False)
    m.run()
    live = reporter.extra["live_hosts"]
    urls = [r["url"] for r in live]
    assert "https://evil.test/" in urls
    assert "http://good.test/" in urls
    assert "https://admin.test/" not in urls  # 403 difilter
    endpoints = reporter.endpoints
    assert "https://evil.test/" in endpoints
    assert "http://good.test/" in endpoints
    # Finding "Live interesting host" hanya untuk yang menarik (admin/login/dashboard/api di title atau url)
    interesting = [f for f in reporter.findings if f.get("title", "").startswith("Live interesting host")]
    # evil.test title mengandung "admin" -> finding
    assert len(interesting) == 1
    assert interesting[0]["method"] == "GET"
    assert interesting[0]["evidence_snippet"].startswith("HTTP 200")


def test_http_probe_all_status_reports_all():
    m, reporter, rm = _make_module(all_status=True)
    m.run()
    live = reporter.extra["live_hosts"]
    assert len(live) == 3  # semua status masuk


def test_http_probe_respects_budget_stop():
    m, reporter, rm = _make_module(all_status=False)
    rm.stopped_by_429 = True
    m.run()
    assert reporter.extra["live_hosts"] == []
