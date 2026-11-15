"""Main scanner orchestrator."""

import socket
import time
from typing import List, Optional, Type
from urllib.parse import urljoin
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from .branding import banner_text
from .config import Config
from .request_manager import RequestManager
from .reporter import Reporter


class Scanner:
    """Orchestrates all scanning modules under a global request budget."""

    def __init__(self, config: Config, console: Optional[Console] = None,
                 rm: Optional[RequestManager] = None,
                 reporter: Optional[Reporter] = None):
        self.config = config
        self.console = console or Console()
        self.rm = rm or RequestManager(config)
        self.reporter = reporter or Reporter(self.console)
        self.modules_run: List[str] = []

    def _print_banner(self) -> None:
        """Tampilkan banner ASCII 'PROBEX' tanpa border/frame luar."""
        from .branding import print_banner

        if not self.console.is_terminal or self.config.no_banner:
            return

        print_banner(self.console)

    def _print_init_info(self) -> None:
        """Baris info header [+] Target / [+] IP + timestamp rata kanan [HH:MM:SS]."""
        import datetime

        target = str(self.config.base_url)
        ip = self._resolve_ip(target)

        now = datetime.datetime.now().strftime("[%H:%M:%S]")

        mode = "SAFE" if self.config.safe_mode else "STANDARD"
        if self.config.low_impact:
            mode = "LOW-IMPACT"

        tbl = Table.grid(padding=(0, 2), expand=True)
        tbl.add_column(style="#00FF41", no_wrap=True)
        tbl.add_column(no_wrap=True)
        tbl.add_column(justify="right", style="#888888", no_wrap=True)
        tbl.add_row("[+] Target", target, now)
        tbl.add_row("[+] IP", ip, "")
        tbl.add_row("[+] Mode", mode, "")
        tbl.add_row("[+] Max Requests", str(self.config.max_requests), "")
        tbl.add_row("[+] Threads", str(self.config.threads), "")
        tbl.add_row("[+] Delay", f"{self.config.delay}s", "")

        self.console.print(
            Panel(tbl, title="[bold #FF0033]SCAN START[/bold #FF0033]", border_style="#FF0033", style="#0D0D0D")
        )
        self.console.print()

    def _resolve_ip(self, target: str) -> str:
        """Resolusi host target ke IP; kembali '-nya jika gagal (non-fatal)."""
        try:
            host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            return socket.gethostbyname(host)
        except Exception:
            return "-"


    def _load_modules(self) -> List:
        """Dynamically load modules based on config."""
        from probex.modules import (
            recon,
            headers,
            cookies,
            tech,
            robots,
            directory,
            auth_bypass,
            flow_analysis,
            sqli,
            xss,
            ssti,
            lfi,
            jwt_mod,
            api,
            html_injection,
            smuggling,
            race_condition,
            param_manip,
            ssti_exploit,
            xss_exploit,
            php_payload,
            html_inject_exploit,
            job,
            base64_decode,
            backend_access,
            sourcemap,
            docker_ssh,
            sensitive_files,
            ssh_shutdown,
            ssh_bruteforce,
            ddos_scanner,
            ddos_attacker,
            dettack_scan,
            apache_poisoning,
            ip_scan,
            vuln_idor,
            vuln_injection,
            vuln_ssrf,
            vuln_auth_session,
            vuln_xss,
            vuln_misconfig,
            vuln_data_exposure,
            vuln_business_logic,
        )

        all_modules = [
            ("HTTP Reconnaissance", recon.HTTPRecon),
            ("Header Analysis", headers.HeaderAnalysis),
            ("Cookie / PHP Session Inspection", cookies.CookieInspection),
            ("Technology Detection", tech.TechDetection),
            ("robots.txt Analysis", robots.RobotsAnalysis),
            ("Workflow / Form / Identity Analysis", flow_analysis.FlowAnalysis),
            # Run bounded SSTI checks immediately after form discovery so they
            # can reuse discovered fields/session before request-heavy modules.
            ("SSTI Detection", ssti.SSTIDetection),
            ("Directory Discovery", directory.DirectoryDiscovery),
            ("Auth / Middleware Bypass", auth_bypass.AuthBypass),
            ("SQL Injection Detection", sqli.SQLiDetection),
            ("HTML Injection Detection", html_injection.HTMLInjectionDetection),
            ("XSS Detection", xss.XSSDetection),
            ("LFI Detection", lfi.LFIDetection),
            ("JWT Analysis", jwt_mod.JWTAnalysis),
            ("API Discovery", api.APIDiscovery),
            # Active exploitation modules (gate: honor --no-safe / safe_mode).
            ("HTTP Request Smuggling CL.TE/TE.CL", smuggling.SmugglingModule),
            ("Race Condition / Queue Jump", race_condition.RaceConditionModule),
            ("Parameter Manipulation", param_manip.ParamManipModule),
            ("SSTI Exploitation", ssti_exploit.SSTIExploitModule),
            ("XSS Exploitation", xss_exploit.XSSExploitModule),
            ("PHP Payload Injection", php_payload.PHPExploitModule),
            ("HTML Injection Exploitation", html_inject_exploit.HTMLInjectExploitModule),
            ("CTF Job Fetcher", job.JobModule),
            ("Base64 Decode / Detection", base64_decode.Base64DecodeModule),
            # Backend access / SSRF probes: reach internal services behind the
            # frontend before finalizing.
            ("Backend Access / SSRF", backend_access.BackendAccessModule),
            ("Sourcemap Exposure Scanner", sourcemap.SourcemapModule),
            ("Docker / SSH Active Scan", docker_ssh.DockerSSHModule),
            ("SSH Shutdown", ssh_shutdown.SSHShutdownModule),
            ("SSH Brute Force & Shutdown", ssh_bruteforce.SSHBruteForceModule),
            ("Sensitive File Exposure Scanner", sensitive_files.SensitiveFilesModule),
            ("DDoS Vulnerability Scanner", ddos_scanner.DDoSVulnScannerModule),
            ("DDoS Attacker SIMULATION", ddos_attacker.DDoSAttackerSimulationModule),
            ("Dettack Scan Pipeline", dettack_scan.DettackScanModule),
            (
                "Apache Cache Poisoning / Vuln Detector",
                apache_poisoning.ApachePoisoningModule,
            ),
            ("IP / Host Accessible Scanner", ip_scan.IpScanModule),
            ("Vuln Scan: IDOR / Broken Access Control", vuln_idor.IDORDetection),
            (
                "Vuln Scan: Injection (SQL / Command / Template)",
                vuln_injection.InjectionDetection,
            ),
            ("Vuln Scan: SSRF", vuln_ssrf.SSRFDetection),
            ("Vuln Scan: Authentication / Session", vuln_auth_session.AuthSessionDetection),
            ("Vuln Scan: XSS", vuln_xss.XSSDetection),
            (
                "Vuln Scan: Security Misconfiguration",
                vuln_misconfig.MisconfigDetection,
            ),
            (
                "Vuln Scan: Sensitive Data Exposure",
                vuln_data_exposure.DataExposureDetection,
            ),
            ("Vuln Scan: Business Logic", vuln_business_logic.BusinessLogicDetection),
        ]

        if self.config.modules:
            selected = []
            name_map = {
                "recon": "HTTP Reconnaissance",
                "headers": "Header Analysis",
                "cookies": "Cookie / PHP Session Inspection",
                "cookie": "Cookie / PHP Session Inspection",
                "tech": "Technology Detection",
                "robots": "robots.txt Analysis",
                "directory": "Directory Discovery",
                "dir": "Directory Discovery",
                "auth": "Auth / Middleware Bypass",
                "bypass": "Auth / Middleware Bypass",
                "middleware": "Auth / Middleware Bypass",
                "flow": "Workflow / Form / Identity Analysis",
                "workflow": "Workflow / Form / Identity Analysis",
                "forms": "Workflow / Form / Identity Analysis",
                "ticket": "Workflow / Form / Identity Analysis",
                "identity": "Workflow / Form / Identity Analysis",
                "params": "Workflow / Form / Identity Analysis",
                "http-framing": "Workflow / Form / Identity Analysis",
                "sqli": "SQL Injection Detection",
                "html": "HTML Injection Detection",
                "html-injection": "HTML Injection Detection",
                "xss": "XSS Detection",
                "ssti": "SSTI Detection",
                "lfi": "LFI Detection",
                "jwt": "JWT Analysis",
                "api": "API Discovery",
                "smuggle": "HTTP Request Smuggling CL.TE/TE.CL",
                "smuggling": "HTTP Request Smuggling CL.TE/TE.CL",
                "cl.te": "HTTP Request Smuggling CL.TE/TE.CL",
                "te.cl": "HTTP Request Smuggling CL.TE/TE.CL",
                "race": "Race Condition / Queue Jump",
                "race-condition": "Race Condition / Queue Jump",
                "queue": "Race Condition / Queue Jump",
                "jump": "Race Condition / Queue Jump",
                "param-manip": "Parameter Manipulation",
                "param": "Parameter Manipulation",
                "admin": "Parameter Manipulation",
                "ssti-exploit": "SSTI Exploitation",
                "xss-payload": "XSS Exploitation",
                "xss-exploit": "XSS Exploitation",
                "php": "PHP Payload Injection",
                "php-payload": "PHP Payload Injection",
                "html-inject-exploit": "HTML Injection Exploitation",
                "job": "CTF Job Fetcher",
                "job-id": "CTF Job Fetcher",
                "base64": "Base64 Decode / Detection",
                "b64": "Base64 Decode / Detection",
                "decode": "Base64 Decode / Detection",
                "backend": "Backend Access / SSRF",
                "ssrf": "Backend Access / SSRF",
                "internal": "Backend Access / SSRF",
                "proxy": "Backend Access / SSRF",
                "sourcemap": "Sourcemap Exposure Scanner",
                "source-map": "Sourcemap Exposure Scanner",
                "map": "Sourcemap Exposure Scanner",
                "docker": "Docker / SSH Active Scan",
                "ssh": "Docker / SSH Active Scan",
                "docker-ssh": "Docker / SSH Active Scan",
                "ssh-shutdown": "SSH Shutdown",
                "sshshutdown": "SSH Shutdown",
                "ssh-brute": "SSH Brute Force & Shutdown",
                "ssh-brute-force": "SSH Brute Force & Shutdown",
                "ssh-shutdown-brute": "SSH Brute Force & Shutdown",
                "sensitive": "Sensitive File Exposure Scanner",
                "env": "Sensitive File Exposure Scanner",
                "dot-env": "Sensitive File Exposure Scanner",
                "sql": "Sensitive File Exposure Scanner",
                "database": "Sensitive File Exposure Scanner",
                "config": "Sensitive File Exposure Scanner",
                "ddos": "DDoS Vulnerability Scanner",
                "ddos-scan": "DDoS Vulnerability Scanner",
                "ddos-vuln": "DDoS Vulnerability Scanner",
                "ddos-attack": "DDoS Attacker SIMULATION",
                "ddos-attacker": "DDoS Attacker SIMULATION",
                "ddos-sim": "DDoS Attacker SIMULATION",
                "apache": "Apache Cache Poisoning / Vuln Detector",
                "apache-poisoning": "Apache Cache Poisoning / Vuln Detector",
                "poisoning": "Apache Cache Poisoning / Vuln Detector",
                "cache": "Apache Cache Poisoning / Vuln Detector",
                "ip": "IP / Host Accessible Scanner",
                "ip-scan": "IP / Host Accessible Scanner",
                "ips": "IP / Host Accessible Scanner",
                "ip_scan": "IP / Host Accessible Scanner",
                "vuln-idor": "Vuln Scan: IDOR / Broken Access Control",
                "idor": "Vuln Scan: IDOR / Broken Access Control",
                "vuln-injection": "Vuln Scan: Injection (SQL / Command / Template)",
                "injection": "Vuln Scan: Injection (SQL / Command / Template)",
                "vuln-ssrf": "Vuln Scan: SSRF",
                "ssrf": "Vuln Scan: SSRF",
                "vuln-auth": "Vuln Scan: Authentication / Session",
                "auth-session": "Vuln Scan: Authentication / Session",
                "vuln-xss": "Vuln Scan: XSS",
                "vuln-misconfig": "Vuln Scan: Security Misconfiguration",
                "misconfig": "Vuln Scan: Security Misconfiguration",
                "data-exposure": "Vuln Scan: Sensitive Data Exposure",
                "vuln-data": "Vuln Scan: Sensitive Data Exposure",
                "business-logic": "Vuln Scan: Business Logic",
                "vuln-business": "Vuln Scan: Business Logic",
            }
            wanted = set()
            for m in self.config.modules:
                key = m.strip().lower()
                if key in name_map:
                    wanted.add(name_map[key])
                else:
                    # partial match
                    for k, v in name_map.items():
                        if key in k or key in v.lower():
                            wanted.add(v)
            for name, cls in all_modules:
                if name in wanted:
                    selected.append((name, cls))
            return selected

        return all_modules

    def _run_module_group(self, modules: List) -> None:
        """Run a group of modules with real-time progress (persentase + estimasi waktu tersisa)."""
        if not modules:
            return

        self.console.print(
            f"[ MODULES LOADED: {len(modules)} ]",
            style="bold #00FF41",
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=40, style="#FF0033", complete_style="#FF0033", finished_style="#00FF41"),
            TaskProgressColumn(),
            TextColumn("{task.fields[eta]}", justify="right"),
            console=self.console,
            transient=False,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(modules), eta="--:--")
            start = time.time()
            for name, ModuleCls in modules:
                if self.rm.stopped_by_429:
                    self.console.print("[bold yellow][!] Stopped: received HTTP 429 (rate limited)[/bold yellow]")
                    break
                if self.rm.stopped_by_overload:
                    self.console.print("[bold yellow][!] Stopped: server returned HTTP 503 (overload protection)[/bold yellow]")
                    break
                if not self.config.can_request():
                    self.console.print("[bold yellow][!] Request budget exhausted[/bold yellow]")
                    break

                progress.update(task, description=f"[cyan][+] {name}")
                self.console.print(f"[bold green][+][/bold green] {name}")
                try:
                    module = ModuleCls(self.config, self.rm, self.reporter, self.console)
                    module.run()
                    self.modules_run.append(name)
                except Exception as exc:
                    self.console.print(f"[dim]    Module error (non-fatal): {exc}[/dim]")

                elapsed = time.time() - start
                done = progress.tasks[task].completed + 1
                remaining = (elapsed / done) * (len(modules) - done) if done else 0
                mins, secs = divmod(int(remaining), 60)
                progress.update(task, advance=1, eta=f"{mins:02d}:{secs:02d}")
                time.sleep(0.15)

    def _run_guided_workflow(self) -> None:
        """Let the operator submit one discovered same-origin HTML form."""
        import getpass

        forms = self.reporter.runtime_context.get("forms", [])
        usable = [
            form for form in forms
            if form.get("method") in ("GET", "POST")
            and form.get("enctype", "").split(";", 1)[0] in (
                "application/x-www-form-urlencoded", "multipart/form-data"
            )
            and self.rm.is_same_origin(form.get("action", ""))
        ]
        self.console.print()
        self.console.rule("[bold cyan]GUIDED FORM WORKFLOW[/bold cyan]")
        if not usable:
            self.console.print("[yellow]No supported same-origin GET/POST forms were discovered.[/yellow]")
            return

        self.console.print(
            "[dim]The HTTP session and cookies from discovery are retained. "
            "Only one same-origin form can be submitted in this run.[/dim]"
        )
        for index, form in enumerate(usable, start=1):
            field_summary = []
            for field in form.get("fields", []):
                kind = field.get("type", "text")
                flags = []
                if field.get("hidden"):
                    flags.append("hidden")
                if field.get("required"):
                    flags.append("required")
                suffix = f" ({', '.join(flags)})" if flags else ""
                field_summary.append(f"{field.get('name', '?')}:{kind}{suffix}")
            summary = ", ".join(field_summary) if field_summary else "no named fields"
            self.console.print(
                f"  [{index}] {form['method']} {form['action']} "
                f"[{summary}]"
            )
        try:
            choice = self.console.input("[cyan]Select form number (or q to skip): [/cyan]").strip().lower()
        except EOFError:
            self.console.print("[dim]No interactive input available; guided workflow skipped.[/dim]")
            return
        if choice in ("q", "quit", ""):
            self.console.print("[dim]Guided workflow skipped.[/dim]")
            return
        try:
            selected = usable[int(choice) - 1]
        except (ValueError, IndexError):
            self.console.print("[yellow]Invalid selection; guided workflow skipped.[/yellow]")
            return

        fields = selected.get("fields", [])
        payload = []
        for field in fields:
            name = field.get("name", "")
            kind = field.get("type", "text")
            current = str(field.get("value", ""))
            if not name:
                continue
            if field.get("sensitive") and current:
                payload.append((name, current))
                self.console.print(f"  [dim]{name}: hidden token auto-filled[/dim]")
                continue
            if kind == "password":
                try:
                    entered = getpass.getpass(f"  {name} (leave empty to omit): ")
                except EOFError:
                    entered = ""
                if entered:
                    payload.append((name, entered))
                continue
            if kind in ("submit", "button", "image", "reset") and not current:
                continue
            prompt_default = current[:80]
            field_label = f"{name} <{kind}>"
            if field.get("hidden"):
                field_label += " [hidden input]"
            if field.get("required"):
                field_label += " [required]"
            try:
                entered = self.console.input(
                    f"  {field_label} [{prompt_default}] (Enter keeps default): "
                )
            except EOFError:
                entered = ""
            value = entered if entered != "" else current
            if kind in ("checkbox", "radio") and not value:
                continue
            payload.append((name, value))

        method = selected["method"]
        action = selected["action"]
        if selected.get("enctype", "").startswith("multipart/form-data"):
            self.console.print("[yellow]Multipart/file-upload forms are not submitted by guided mode. Use Burp for this form.[/yellow]")
            return
        if not self.rm.is_same_origin(action):
            self.console.print("[red]Form action is outside the exact target origin; refusing to submit.[/red]")
            return
        self.console.print(f"[bold]Ready:[/bold] {method} {action} with {len(payload)} field value(s)")
        self.console.print(
            "[yellow]The next step sends one request to the selected form action. "
            "Type Y or YES to submit; anything else cancels.[/yellow]"
        )
        try:
            confirm = self.console.input("[yellow]Confirm submission [y/N]: [/yellow]").strip().lower()
        except EOFError:
            confirm = "n"
        if confirm not in ("y", "yes"):
            self.console.print(
                f"[dim]Submission cancelled; no form request was sent (confirmation was {confirm!r}).[/dim]"
            )
            return
        if not self.config.can_request():
            self.console.print("[yellow]Request budget exhausted; form was not sent.[/yellow]")
            return

        response = self.rm.request(
            method,
            action,
            params=payload if method == "GET" else None,
            data=payload if method == "POST" else None,
            allow_redirects=True,
        )
        if response is None:
            self.console.print("[red]No response (scope, budget, timeout, or connection issue).[/red]")
            return
        response_url = response.url or action
        self.reporter.add_endpoint(response_url)
        self.reporter.add_finding(
            "Guided form request submitted",
            severity="info",
            detail=f"{method} {action} returned HTTP {response.status_code}; field values are not stored.",
        )
        self.console.print(f"[green][+][/green] HTTP {response.status_code} from guided form request")
        body = response.text or ""

        # Treat the response as the next workflow page. Collect only bounded,
        # same-origin references so subsequent modules can inspect
        # newly revealed pages without leaving the authorized target origin.
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body[:250_000], "html.parser")
            discovered = 0
            candidates = []
            for tag_name, attr_name in (("a", "href"), ("script", "src"),
                                        ("iframe", "src"), ("form", "action")):
                for tag in soup.find_all(tag_name):
                    value = str(tag.get(attr_name) or "").strip()
                    if value:
                        candidates.append(urljoin(response_url, value))
            for candidate in candidates:
                if discovered >= 20:
                    break
                if self.rm.is_same_origin(candidate):
                    self.reporter.add_endpoint(candidate)
                    discovered += 1
            if discovered:
                self.console.print(
                    f"[cyan][*][/cyan] Added {discovered} same-origin reference(s) "
                    "from the form response for follow-up inspection"
                )
        except Exception as exc:
            self.console.print(f"[dim]Could not parse follow-up references: {exc}[/dim]")

    def _crawl_discovery(self) -> None:
        """Crawl terbatas (depth 1, maks. 20 halaman) dari halaman utama untuk
        menemukan link dan form dalam satu origin, sebelum detektor dijalankan."""
        from bs4 import BeautifulSoup

        base = str(self.config.base_url)
        visited = {base}
        queue = [base]
        while queue and len(visited) <= 20:
            if self.rm.get_stats().get("remaining_budget", 1) <= 0 or self.rm.stopped_by_429 or self.rm.stopped_by_overload:
                break
            url = queue.pop(0)
            resp = self.rm.get(url)
            if resp is None:
                continue
            body = resp.text or ""
            self.reporter.add_endpoint(url)
            try:
                soup = BeautifulSoup(body[:250_000], "html.parser")
                for tag_name, attr_name in (("a", "href"), ("form", "action")):
                    for tag in soup.find_all(tag_name):
                        value = str(tag.get(attr_name) or "").strip()
                        if not value or value.startswith("#"):
                            continue
                        if tag_name == "form":
                            fields = [
                                {
                                    "name": str(i.get("name") or ""),
                                    "type": str(i.get("type") or "text"),
                                    "value": str(i.get("value") or ""),
                                }
                                for i in tag.find_all(["input", "select", "textarea"])
                            ]
                            entry = {
                                "action": value,
                                "method": str(tag.get("method") or "GET").upper(),
                                "fields": fields,
                            }
                            ctx = getattr(self.reporter, "runtime_context", None)
                            if ctx is None:
                                ctx = {}
                                self.reporter.runtime_context = ctx
                            forms = ctx.setdefault("forms", [])
                            if entry not in forms:
                                forms.append(entry)
                        candidate = urljoin(url, value)
                        if candidate in visited:
                            continue
                        if self.rm.is_same_origin(candidate):
                            visited.add(candidate)
                            self.reporter.add_endpoint(candidate)
                            if len(visited) < 20:
                                queue.append(candidate)
            except Exception:
                pass

    def run(self, module_names: Optional[List[str]] = None) -> int:
        """Execute the full scan. Returns exit code."""
        self._print_init_info()

        # CLI-selected module names (e.g. ["smuggling", "race_condition"]) are
        # mapped to module classes inside _load_modules via config.modules.
        if module_names is not None:
            self.config.modules = module_names

        # Connectivity check
        self.console.print("[cyan][*][/cyan] Checking connectivity...")
        resp = self.rm.get(self.config.base_url)
        if resp is None:
            self.console.print("[bold red][!] Cannot connect to target. Aborting.[/bold red]")
            return 1
        self.console.print(f"[green][+][/green] Target is reachable (HTTP {resp.status_code})")
        self.reporter.add_endpoint(self.config.base_url)
        self.console.print()

        # Crawl terbatas (depth 1, maks. 20 halaman) dari halaman utama untuk
        # menemukan link dan form dalam satu origin (mode URL/dinamis) sebelum
        # detektor dijalankan.
        self._crawl_discovery()

        modules = self._load_modules()
        total = len(modules)

        # In guided mode, pause the progress display immediately after workflow
        # discovery so terminal input prompts remain readable. The selected form
        # is submitted only after the operator confirms it.
        if self.config.interactive_workflow:
            flow_index = next(
                (i for i, (name, _cls) in enumerate(modules)
                 if name == "Workflow / Form / Identity Analysis"),
                None,
            )
        else:
            flow_index = None

        if flow_index is not None:
            self._run_module_group(modules[:flow_index + 1])
            if self.config.can_request() and not self.rm.stopped_by_429 and not self.rm.stopped_by_overload:
                self._run_guided_workflow()
            else:
                self.console.print("[yellow]Guided workflow skipped because the request budget is exhausted or the target asked us to stop.[/yellow]")
            self._run_module_group(modules[flow_index + 1:])
        else:
            self._run_module_group(modules)

        stats = self.rm.get_stats()
        status = "COMPLETED"
        if self.rm.stopped_by_429:
            status = "STOPPED (429)"
        elif stats.get("stopped_by_overload"):
            status = "STOPPED (server returned 503)"
        elif stats["remaining_budget"] == 0:
            status = "COMPLETED (budget exhausted)"

        self.reporter.print_summary(
            target=self.config.base_url,
            requests_used=stats["total_requests"],
            status=status,
        )
        self.reporter.save_report(
            target=self.config.base_url,
            requests_used=stats["total_requests"],
            status=status,
        )
        return 0
