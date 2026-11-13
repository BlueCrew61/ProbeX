"""CachePoisonX Modules Package

Struktur:
- modules.recon     : enumerasi subdomain, probe host, path discovery
- modules.poisoning : mode DETEKSI — fingerprint, cache key matrix, probe, verify
- modules.injector  : mode INJEKSI — tanam payload, timeline, korban, webhook
- modules.report    : laporan JSON + HTML (dua mode)
"""

from .recon import enumerate_subdomains, probe_hosts, discover_paths
from .poisoning import CachePoisonTester
from .injector import CacheInjector, INJECT_HEADERS, PAYLOAD_PROFILES
from .report import generate_json_report, generate_html_report

__all__ = [
    "enumerate_subdomains",
    "probe_hosts",
    "discover_paths",
    "CachePoisonTester",
    "CacheInjector",
    "INJECT_HEADERS",
    "PAYLOAD_PROFILES",
    "generate_json_report",
    "generate_html_report",
]