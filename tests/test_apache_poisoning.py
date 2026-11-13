"""Tes modul apache_poisoning (mock request_manager, tanpa jaringan asli)."""

from probex.core.config import Config
from probex.core.reporter import Reporter
from probex.modules.apache_poisoning import ApachePoisoningModule
from rich.console import Console


class FakeResponse:
    def __init__(self, status_code, headers, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class FakeRM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.config = Config("http://127.0.0.1:8080/", max_requests=100, delay=0)
        self.stopped_by_429 = False

    def request(self, method, url, headers=None):
        self.calls.append((method, url, headers))
        if not self.responses:
            return FakeResponse(404, {})
        return self.responses.pop(0)


def _make_module(rm):
    reporter = Reporter(Console(), "/tmp")
    mod = ApachePoisoningModule(rm.config, rm, reporter, Console())
    return mod


def test_apache_poisoning_read_only_findings():
    # Fingerprint: Apache 2.4.49 (rentan) + marker reflected + cacheable -> findings
    rm = FakeRM([
        FakeResponse(200, {"Server": "Apache/2.4.49"}, ""),          # fingerprint
        FakeResponse(200, {"Server": "Apache/2.4.49"}, "probex-marker-abc"),  # header X-Forwarded-Host reflected
        FakeResponse(200, {"Server": "Apache/2.4.49"}, "<script>alert(1)</script>"),  # cache-poisoned indicator
    ])
    mod = _make_module(rm)
    mod.run()
    titles = [f["title"] for f in mod.reporter.findings]
    assert any("Apache" in t or "cache" in t.lower() or "poisoning" in t.lower() or "injected" in t.lower() for t in titles), titles
    assert len(rm.calls) <= 10  # bounded


def test_apache_poisoning_patched_apache():
    rm = FakeRM([FakeResponse(200, {"Server": "Apache/2.4.56"}, "")])
    mod = _make_module(rm)
    mod.run()
    assert len(rm.calls) <= 10
    # Tidak crash meski tidak ada temuan kritis
