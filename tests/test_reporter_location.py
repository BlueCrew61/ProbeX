"""Tes fitur lokasi terstruktur pada finding (Reporter.add_finding).
Tidak memakai jaringan: request_manager di-mock.
"""

import json
from pathlib import Path

from probex.core.reporter import Reporter
from rich.console import Console


def _make_reporter():
    return Reporter(Console())


def test_add_finding_stores_location_fields():
    reporter = _make_reporter()
    reporter.add_finding(
        title="SQLi indicator",
        severity="high",
        detail="error signature found",
        evidence="' OR '1'='1",
        url="http://127.0.0.1:8080/item?id=1",
        method="GET",
        parameter="id",
        evidence_snippet="' OR '1'='1",
    )
    finding = reporter.findings[0]
    assert finding["title"] == "SQLi indicator"
    assert finding["severity"] == "high"
    assert finding["detail"] == "error signature found"
    assert finding["evidence"] == "' OR '1'='1"
    assert finding["url"] == "http://127.0.0.1:8080/item?id=1"
    assert finding["method"] == "GET"
    assert finding["parameter"] == "id"
    assert finding["evidence_snippet"] == "' OR '1'='1"


def test_add_finding_backward_compatible_defaults():
    reporter = _make_reporter()
    reporter.add_finding("Old style finding", "info", "detail only", "evidence only")
    finding = reporter.findings[0]
    assert finding["url"] == ""
    assert finding["method"] == ""
    assert finding["parameter"] == ""
    assert finding["evidence_snippet"] == "evidence only"  # fallback ke evidence


def test_save_report_keeps_location_fields(tmp_path):
    reporter = _make_reporter()
    reporter.output_dir = tmp_path
    reporter.add_finding(
        "Located finding",
        "medium",
        "has location",
        "snip",
        url="http://127.0.0.1:8080/admin",
        method="GET",
        parameter="",
        evidence_snippet="snip",
    )
    saved = reporter.save_report("http://127.0.0.1:8080/", 0)
    data = json.loads(Path(saved).read_text())
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["url"] == "http://127.0.0.1:8080/admin"
    assert f["method"] == "GET"
    assert f["parameter"] == ""
    assert f["evidence_snippet"] == "snip"


def test_print_summary_shows_location(capsys):
    reporter = _make_reporter()
    reporter.add_finding(
        "Located finding",
        "high",
        "has location",
        "snip",
        url="http://127.0.0.1:8080/admin",
        method="GET",
        parameter="id",
        evidence_snippet="snip",
    )
    reporter.print_summary("http://127.0.0.1:8080/", 0)
    captured = capsys.readouterr().out
    assert "→ Lokasi:" in captured
    assert "http://127.0.0.1:8080/admin" in captured
    assert "param: id" in captured
