#!/usr/bin/env python3
"""ProbeX v1.8 — Web Exploitation Scanner for CTF (authorized labs only).

Adds active exploitation modules on top of the passive scanner:
- HTTP request smuggling (CL.TE / TE.CL)   -> Queue Jump style challenges
- Race condition / queue jump               -> ticket race challenges
- Parameter manipulation                    -> admin=true / role bypass
- SSTI / XSS / PHP / HTML injection payloads

Usage:
    python3 probex.py <IP> <PORT>
    python3 probex.py https://challenge.example

Examples:
    python3 probex.py 103.160.212.211 8080 --smuggle --race
    python3 probex.py 103.160.212.211 30106 --ssti-exploit
    python3 probex.py http://127.0.0.1:8080 --param-manip --xss-payload
"""
from __future__ import annotations

import argparse
import importlib.util as _importlib_util
import os as _os
import sys as _sys
from typing import List

_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PKG_DIR = _os.path.join(_HERE, "probex")
if "probex" not in _sys.modules:
    _spec = _importlib_util.spec_from_file_location(
        "probex", _os.path.join(_PKG_DIR, "__init__.py"),
        submodule_search_locations=[_PKG_DIR],
    )
    _probex_pkg = _importlib_util.module_from_spec(_spec)
    _sys.modules["probex"] = _probex_pkg
    _spec.loader.exec_module(_probex_pkg)

from probex.core.branding import print_banner
from probex.core.console import console
from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.scanner import Scanner
from probex.core.reporter import Reporter
from probex.modules.ssh_shutdown import execute_ssh_shutdown
from probex.modules.ssh_bruteforce import run_ssh_shutdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ProbeX v1.8 — Web Exploitation Scanner (authorized labs only)."
    )
    p.add_argument("target", help="IP, host, or full URL (e.g. 103.160.212.211:8080 or https://example.com)")

    # Safety / scope
    p.add_argument("--safe", action="store_true", default=True, help="Safe mode (default on): passive checks only")
    p.add_argument("--no-safe", action="store_true", help="Disable safe mode: enable active exploitation modules")
    p.add_argument("--low-impact", action="store_true", help="One worker, longer delay, max 50 requests")
    p.add_argument("--max-requests", type=int, default=300, help="Global request budget (default 300)")
    p.add_argument("--budget", type=int, help="Alias for --max-requests")
    p.add_argument("--delay", type=float, default=1.0, help="Minimum delay between requests (default 1.0)")
    p.add_argument("--threads", type=int, default=1, choices=[1, 2, 3], help="Concurrency 1-3 (default 1)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout seconds (default 10)")
    p.add_argument("--all-status", action="store_true", help="Laporkan semua status code (bukan cuma 200) pada http_probe (default off)")
    p.add_argument("--no-banner", action="store_true", help="Matikan banner ASCII dan warna (fallback teks polos untuk log/non-TTY)")
    p.add_argument("--https", action="store_true", help="Force HTTPS for IP/port format")

    # Module selection
    p.add_argument("--module", help="Comma-separated module list (passive modules)")
    p.add_argument("--ssti", action="store_true", help="Run SSTI detector")
    p.add_argument("--flow", action="store_true", help="Flow mode: form/ticket + guided")

    # New: active exploitation (require --no-safe)
    p.add_argument("--smuggle", action="store_true", help="HTTP request smuggling (CL.TE / TE.CL) — needs --no-safe")
    p.add_argument("--race", action="store_true", help="Race condition / queue jump exploitation — needs --no-safe")
    p.add_argument("--param-manip", action="store_true", help="Parameter manipulation (admin=true / role bypass) — needs --no-safe")
    p.add_argument("--ssti-exploit", action="store_true", help="SSTI payload exploitation (read files / execute) — needs --no-safe")
    p.add_argument("--xss-payload", action="store_true", help="XSS payload testing — needs --no-safe")
    p.add_argument("--php-payload", action="store_true", help="PHP payload injection testing — needs --no-safe")
    p.add_argument("--html-inject", action="store_true", help="HTML injection exploitation — needs --no-safe")
    p.add_argument("--sourcemap", action="store_true", help="Scan for exposed .map sourcemap files — needs --no-safe")
    p.add_argument("--docker-ssh", action="store_true", help="Scan target host for active Docker (2375/2376) and SSH (22) — needs --no-safe")
    p.add_argument("--ssh-shutdown", action="store_true", help="SSH brute force & shutdown — needs --no-safe")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    p.add_argument("--ssh-key", help="Path to SSH private key (default ~/.ssh/id_rsa)")
    p.add_argument("--ssh-cupp", action="store_true", help="Use CUPP profiler for wordlist")
    p.add_argument("--ssh-confirm", action="store_true", help="Confirm authorization for shutdown")
    p.add_argument("--sensitive-files", action="store_true", help="Scan exposed .env / .sql / .db / config files — needs --no-safe")
    p.add_argument("--all-exploit", action="store_true", help="Enable all active exploitation modules — needs --no-safe")

    # Guided / tokens
    p.add_argument("--show-tokens", action="store_true", help="Show ticket/CSRF field values in terminal only")
    p.add_argument("--guided", action="store_true", help="Pilih dan kirim satu form setelah discovery; perlu konfirmasi")
    p.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Jalankan semua 8 detektor celah (Vulnerability Scanner, OWASP Top 10)",
    )
    p.add_argument(
        "--ssrf-callback",
        help="URL callback milik pengguna untuk uji SSRF (jangan gunakan alamat internal/metadata cloud)",
    )

    # CTF Job
    p.add_argument("--job-id", help="CTF job ID: ambil detail tantangan dan jalankan modul sesuai — needs --no-safe for active modules")

    # SHD
    p.add_argument("-shd", action="store_true", help="SHD pipeline: discovery, probing, cookie, workflow, checks")

    return p


def resolve_target(target: str, force_https: bool) -> str:
    """Normalize target into a base URL."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return target
    if ":" in target and not target.startswith("["):
        host, _, port = target.partition(":")
        scheme = "https" if force_https else "http"
        return f"{scheme}://{host}:{port}"
    scheme = "https" if force_https else "http"
    return f"{scheme}://{target}"


def select_modules(args: argparse.Namespace) -> List[str]:
    """Build ordered module list from CLI flags. Safe mode = passive only."""
    active = args.no_safe or args.all_exploit

    passive = []
    if args.module:
        passive = [m.strip() for m in args.module.split(",") if m.strip()]
    elif args.ssti:
        passive = ["ssti"]
    elif args.flow:
        passive = ["flow"]
    elif args.shd:
        passive = ["subdomain", "probe", "cookie", "flow", "headers", "cookies", "tech", "robots", "html", "xss", "ssti", "sqli", "lfi", "auth", "base64_decode"]
    else:
        passive = ["headers", "cookies", "tech", "robots", "flow", "html", "xss", "ssti", "sqli", "lfi", "auth", "base64_decode"]

    exploit = []
    if active or args.all_exploit:
        if args.smuggle or args.all_exploit:
            exploit.append("smuggling")
        if args.race or args.all_exploit:
            exploit.append("race_condition")
        if args.param_manip or args.all_exploit:
            exploit.append("param_manip")
        if args.ssti_exploit or args.all_exploit:
            exploit.append("ssti_exploit")
        if args.xss_payload or args.all_exploit:
            exploit.append("xss_exploit")
        if args.php_payload or args.all_exploit:
            exploit.append("php_payload")
        if args.html_inject or args.all_exploit:
            exploit.append("html_inject_exploit")
        if args.sourcemap or args.all_exploit:
            exploit.append("sourcemap")
        if args.docker_ssh or args.all_exploit:
            exploit.append("docker_ssh")
        if args.sensitive_files or args.all_exploit:
            exploit.append("sensitive_files")
        if args.all_exploit:
            exploit.append("ip_scan")
        if args.ssh_shutdown:
            exploit.append("ssh_shutdown")

    VULN_MODULES = [
        "Vuln Scan: IDOR / Broken Access Control",
        "Vuln Scan: Injection (SQL / Command / Template)",
        "Vuln Scan: SSRF",
        "Vuln Scan: Authentication / Session",
        "Vuln Scan: XSS",
        "Vuln Scan: Security Misconfiguration",
        "Vuln Scan: Sensitive Data Exposure",
        "Vuln Scan: Business Logic",
    ]

    if args.vuln_scan:
        return list(VULN_MODULES)

    ordered = []
    for m in passive + exploit:
        if m not in ordered:
            ordered.append(m)
    return ordered


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_safe and (
        args.smuggle or args.race or args.param_manip or args.ssti_exploit
        or args.xss_payload or args.php_payload or args.html_inject
        or args.all_exploit
        or args.sourcemap or args.docker_ssh
        or args.sensitive_files
        or args.ssh_shutdown
        or args.vuln_scan
    ):
        console.print(
            "[yellow]Active exploitation flags require --no-safe. "
            "Re-run with --no-safe to enable them.[/yellow]"
        )
        return 1

    if not args.no_banner:
        print_banner(console)

    base_url = resolve_target(args.target, args.https)
    if args.budget is not None:
        args.max_requests = args.budget
    console.print(f"[cyan]Target:[/cyan] {base_url}")
    console.print(f"[cyan]Safe mode:[/cyan] {args.safe and not args.no_safe}")
    if args.job_id:
        console.print(f"[cyan]Job ID:[/cyan] {args.job_id}")

    config = Config(
        base_url_override=base_url,
        safe_mode=args.safe and not args.no_safe,
        low_impact=args.low_impact,
        max_requests=args.max_requests,
        delay=args.delay,
        threads=args.threads,
        timeout=args.timeout,
        use_https=args.https,
        all_status=args.all_status,
        no_banner=args.no_banner,
        show_tokens=args.show_tokens,
        guided=args.guided,
        shd_mode=args.shd,
        job_id=args.job_id,
    )

    rm = RequestManager(config)
    reporter = Reporter(console)
    scanner = Scanner(config, console, rm, reporter)

    modules = select_modules(args)
    console.print(f"[cyan]Modules:[/cyan] {', '.join(modules)}")

    # Allow active exploitation only when --no-safe was passed; gate is
    # enforced inside each exploit module via config._exploit_allowed.
    config._exploit_allowed = bool(args.no_safe or args.all_exploit)
    config.ssrf_callback = args.ssrf_callback

    # Konsentrasi izin uji (wajib): scan tidak berjalan tanpa pernyataan
    # izin dari pengguna. Lewati prompt saat PROBEX_CONSENT=1 (CI/non-TTY).
    if not _os.environ.get("PROBEX_CONSENT") and _sys.stdin.isatty():
        try:
            jawab = (
                console.input(
                    "[yellow]Apakah Anda memiliki izin untuk menguji target ini? (ya/tidak): [/yellow]"
                )
                .strip()
                .lower()
            )
        except EOFError:
            jawab = "tidak"
        if jawab != "ya":
            console.print("[red]Scan dibatalkan: izin uji target tidak diberikan.[/red]")
            return 1

    # Standalone SSH shutdown / brute force action (runs before scanner if requested).
    if args.ssh_shutdown:
        return run_ssh_shutdown(
            target=args.target,
            private_key=args.ssh_key or "~/.ssh/id_rsa",
            port=args.ssh_port,
            use_cupp=args.ssh_cupp,
            confirm=args.ssh_confirm,
        )

    try:
        scanner.run(module_names=modules)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130

    return 0


if __name__ == "__main__":
    _sys.exit(main())
