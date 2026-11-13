"""CachePoisonX Modules Package

Struktur:
- modules.poisoning : mode DETEKSI — fingerprint, cache key matrix, probe, verify
- modules.injector  : mode INJEKSI — tanam payload, timeline, korban, webhook
- modules.report    : laporan JSON + HTML (dua mode)
"""

from .poisoning import CachePoisonTester, UNKEYED_HEADER_CANDIDATES
from .injector import CacheInjector, INJECT_HEADERS, PAYLOAD_PROFILES
from .report import generate_json_report, generate_html_report

__all__ = [
    "CachePoisonTester",
    "UNKEYED_HEADER_CANDIDATES",
    "CacheInjector",
    "INJECT_HEADERS",
    "PAYLOAD_PROFILES",
    "generate_json_report",
    "generate_html_report",
]