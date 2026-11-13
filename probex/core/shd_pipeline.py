"""SHD Pipeline: Subdomain → HTTP Probe → Cookie → optional checks.

Triggered by: python3 probex.py -shd example.go.id
"""

from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import time

from .config import Config
from .request_manager import RequestManager
from .reporter import Reporter


class SHDPipeline:
    """Bounded subdomain discovery, HTTP probing, and vulnerability checks."""

    def __init__(self, config: Config, console: Optional[Console] = None):
        self.config = config
        self.config.shd_mode = True  # type: ignore
        self.console = console or Console()
        self.rm = RequestManager(config)
        self.reporter = Reporter(self.console)

    def _banner(self):
        banner = r"""
██╗    ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██║    ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║███╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ╚════██║╚════██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ╚═══██╗
╚███╔███╔╝███████╗███████║╚█████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═══╝
"""
        self.console.print(banner, style="bold cyan")
        self.console.print(
            Panel.fit(
                "[bold white]WEB EXPLOITATION SCANNER[/bold white]\n"
                "[dim]ProbeX v1.6 — SHD MODE[/dim]\n"
                "[yellow]Subfinder → HTTPX → Exploit[/yellow]",
                border_style="cyan",
            )
        )
        self.console.print()
        self.console.print(f"[cyan][INFO][/cyan] Root Domain  : {self.config.root_domain}")
        self.console.print(f"[cyan][INFO][/cyan] Mode         : SHD (Subdomain Hunt + Discover)")
        self.console.print(f"[cyan][INFO][/cyan] Max Requests : {self.config.max_requests}")
        self.console.print(f"[cyan][INFO][/cyan] Threads      : {self.config.threads}")
        self.console.print(f"[cyan][INFO][/cyan] Delay        : {self.config.delay}s")
        self.console.print()

    def run(self) -> int:
        self._banner()

        from probex.modules.subdomain import SubdomainEnum
        from probex.modules.http_probe import HTTPProbe
        from probex.modules.auth_bypass import AuthBypass
        from probex.modules.flow_analysis import FlowAnalysis
        from probex.modules.headers import HeaderAnalysis
        from probex.modules.tech import TechDetection
        from probex.modules.sqli import SQLiDetection
        from probex.modules.xss import XSSDetection
        from probex.modules.ssti import SSTIDetection
        from probex.modules.lfi import LFIDetection
        from probex.modules.jwt_mod import JWTAnalysis
        from probex.modules.api import APIDiscovery
        from probex.modules.cookies import CookieInspection
        from probex.modules.html_injection import HTMLInjectionDetection

        # Phase 1-3: discover
        discover_stages = [
            ("[1/3] Subdomain Discovery (subfinder)", SubdomainEnum),
            ("[2/3] HTTP Probe (httpx)", HTTPProbe),
        ]

        # Phase 3: exploit live / accessible targets
        exploit_stages = [
            ("Cookie / PHP Session Inspection", CookieInspection),
            ("Workflow / Form / Identity Analysis", FlowAnalysis),
            ("Auth / Middleware Bypass", AuthBypass),
            ("Header Analysis", HeaderAnalysis),
            ("Technology Detection", TechDetection),
            ("SQL Injection Detection", SQLiDetection),
            ("HTML Injection Detection", HTMLInjectionDetection),
            ("XSS Detection", XSSDetection),
            ("SSTI Detection", SSTIDetection),
            ("LFI Detection", LFIDetection),
            ("JWT Analysis", JWTAnalysis),
            ("API Discovery", APIDiscovery),
        ]

        all_stages = discover_stages + [
            (f"[3/3] Analyze: {n}", cls) for n, cls in exploit_stages
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]SHD Pipeline...", total=len(all_stages))

            for name, Cls in all_stages:
                if self.rm.stopped_by_429:
                    self.console.print("[bold yellow][!] Stopped: HTTP 429[/bold yellow]")
                    break
                if self.rm.stopped_by_overload:
                    self.console.print("[bold yellow][!] Stopped: HTTP 503 (server overload)[/bold yellow]")
                    break
                if not self.config.can_request():
                    self.console.print("[bold yellow][!] Request budget exhausted[/bold yellow]")
                    break

                progress.update(task, description=f"[cyan]{name}")
                self.console.print(f"[bold green][+][/bold green] {name}")

                # For exploit stages, retarget config.base_url to each live host
                if Cls in (c for _, c in exploit_stages):
                    live = self.reporter.extra.get("live_hosts") or []
                    targets = []
                    if live:
                        from urllib.parse import urlparse
                        for h in live[:3]:
                            u = h.get("url") or h.get("input")
                            if u:
                                p = urlparse(u)
                                targets.append(f"{p.scheme}://{p.netloc}")
                    if not targets:
                        targets = [self.config.base_url]

                    for t in targets:
                        if not self.config.can_request():
                            break
                        # Temporarily point scanner at this host
                        old_override = self.config.base_url_override
                        self.config.base_url_override = t
                        try:
                            mod = Cls(self.config, self.rm, self.reporter, self.console)
                            mod.run()
                        except Exception as e:
                            self.console.print(f"[dim]    error on {t}: {e}[/dim]")
                        finally:
                            self.config.base_url_override = old_override
                else:
                    try:
                        mod = Cls(self.config, self.rm, self.reporter, self.console)
                        mod.run()
                    except Exception as e:
                        self.console.print(f"[dim]    Module error: {e}[/dim]")

                progress.advance(task)
                time.sleep(0.1)

        stats = self.rm.get_stats()
        status = "COMPLETED"
        if self.rm.stopped_by_429:
            status = "STOPPED (429)"
        elif stats.get("stopped_by_overload"):
            status = "STOPPED (server returned 503)"
        elif stats["remaining_budget"] == 0:
            status = "COMPLETED (budget exhausted)"

        # Extra SHD summary
        self.console.print()
        subs = self.reporter.extra.get("subdomains") or []
        live = self.reporter.extra.get("live_hosts") or []
        paths = self.reporter.extra.get("accessible_paths") or []
        self.console.print(f"[cyan][SHD][/cyan] Subdomains found : {len(subs)}")
        self.console.print(f"[cyan][SHD][/cyan] Live HTTP hosts  : {len(live)}")
        self.console.print(f"[cyan][SHD][/cyan] Accessible paths : {len(paths)}")

        target_label = self.config.root_domain or self.config.base_url
        self.reporter.print_summary(
            target=f"SHD:{target_label}",
            requests_used=stats["total_requests"],
            status=status,
        )
        self.reporter.save_report(
            target=f"SHD:{target_label}",
            requests_used=stats["total_requests"],
            status=status,
        )
        return 0
