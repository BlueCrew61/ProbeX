"""Report generation and summary display."""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from probex.core.vuln import Finding, SEVERITY_LEGACY


class Reporter:
    def __init__(self, console: Console, output_dir: str = "reports"):
        self.console = console
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[str] = []
        self.flags_found: List[str] = []
        self.tech_stack: List[str] = []
        self.extra: Dict[str, Any] = {}
        # Ephemeral in-memory context (cookies/ticket values/forms). This is
        # deliberately excluded from JSON reports.
        self.runtime_context: Dict[str, Any] = {}

    def add_finding(
        self,
        title: str,
        severity: str = "info",
        detail: str = "",
        evidence: str = "",
        url: str = "",
        method: str = "",
        parameter: str = "",
        evidence_snippet: str = "",
    ):
        self.findings.append({
            "title": title,
            "severity": severity,
            "detail": detail,
            "evidence": evidence[:500] if evidence else "",
            "url": url,
            "method": method,
            "parameter": parameter,
            "evidence_snippet": (evidence_snippet or evidence)[:500]
            if (evidence_snippet or evidence)
            else "",
        })

    def add_vuln_finding(self, finding: Finding) -> None:
        """Simpan temuan dalam format wajib Vulnerability Scanner (JSON siap pakai)."""
        if not finding.id:
            finding.id = f"vuln-{len(self.findings) + 1:03d}"
        data = finding.to_dict()
        # Flat keys agar ringkasan terminal dan laporan lama tetap kompatibel.
        data["url"] = finding.location.url
        data["method"] = finding.location.method
        data["parameter"] = finding.location.parameter
        data["evidence_snippet"] = finding.evidence[:300]
        data["severity_legacy"] = SEVERITY_LEGACY.get(finding.severity, "info")
        self.findings.append(data)

    def add_endpoint(self, url: str):
        if url not in self.endpoints:
            self.endpoints.append(url)

    def add_flag(self, flag: str):
        if flag and flag not in self.flags_found:
            self.flags_found.append(flag)

    def add_tech(self, tech: str):
        if tech and tech not in self.tech_stack:
            self.tech_stack.append(tech)

    def print_summary(self, target: str, requests_used: int, status: str = "COMPLETED"):
        self.console.print()
        self.console.rule("[bold #FF0033]========== PROBEX REPORT ==========[/bold #FF0033]")
        self.console.print(f"[bold]Target[/bold]          : {target}")
        self.console.print(f"[bold]Scan Status[/bold]     : {status}")
        self.console.print(f"[bold]Requests Used[/bold]   : {requests_used}")
        self.console.print(f"[bold]Endpoints Found[/bold] : {len(self.endpoints)}")
        self.console.print(f"[bold]Findings[/bold]        : {len(self.findings)}")

        if self.findings:
            self.console.print()
            self.console.print("[bold #FF0033][!] FINDINGS:[/bold #FF0033]")
            for f in self.findings:
                sev = (f.get("severity") or "info").lower()
                if sev in ("critical", "high"):
                    prefix = "[!]"
                    sev_label = sev.upper()
                    sev_style = "red"
                elif sev == "info":
                    prefix = "[i]"
                    sev_label = "INFO"
                    sev_style = "cyan"
                elif sev == "low":
                    prefix = "[+]"
                    sev_label = "SAFE"
                    sev_style = "#00FF41"
                else:
                    # medium / not-found / gagal
                    prefix = "[-]"
                    sev_label = sev.upper()
                    sev_style = "yellow"
                loc = f.get("url") or "-"
                param = f.get("parameter") or ""
                loc_part = f" [{param}]" if param else ""
                self.console.print(
                    f"  {prefix} {sev_label:<7} : [bold {sev_style}]{f['title']}[/bold {sev_style}] "
                    f"on {loc}{loc_part}"
                )
                if f.get("detail"):
                    self.console.print(f"    {f['detail']}")
                loc = f.get("url") or ""
                param = f.get("parameter")
                if loc:
                    loc_part = f" [param: {param}]" if param else ""
                    self.console.print(f"    [dim]→ Lokasi: {loc}{loc_part}[/dim]", markup=False)

            # Ringkasan temuan per tipe celah (format Vulnerability Scanner)
            per_type: dict[str, int] = {}
            for f in self.findings:
                t = f.get("type") or "lainnya"
                per_type[t] = per_type.get(t, 0) + 1
            if per_type:
                self.console.print()
                self.console.print("[bold cyan][TEMAU PER TIPE CELAH][/bold cyan]")
                for t, count in sorted(per_type.items()):
                    self.console.print(f"  • {t}: {count}")

        # ---------- Risk conclusion (weighted by severity) ----------
        self.console.print()
        self.console.print(
            Panel(
                self._risk_panel_content(),
                title="[bold #FF0033]RISK CONCLUSION[/bold #FF0033]",
                border_style="#FF0033",
                style="#0D0D0D",
            )
        )

        # Ringkasan berdasarkan judul finding (kategori)
        if self.findings:
            self.console.print()
            self.console.print("[bold cyan][VULNERABILITIES DETECTED][/bold cyan]")
            categories: dict[str, int] = {}
            for f in self.findings:
                title = f["title"]
                if title.startswith("Missing Security Header:"):
                    key = "Missing Security Header"
                elif title.startswith("Protected candidate"):
                    key = "Auth / Middleware Bypass"
                elif title.startswith("Identity / callback"):
                    key = "Input / URL Injection"
                elif title.startswith("HTTP intermediary"):
                    key = "HTTP Intermediary / Framing"
                else:
                    key = title
                categories[key] = categories.get(key, 0) + 1
            for key, count in categories.items():
                self.console.print(f"  • {key}: {count} finding(s)")

            # Ringkasan celah per lokasi/endpoint
            per_location: dict[str, int] = {}
            for f in self.findings:
                url = f.get("url") or "-"
                param = f.get("parameter")
                key = f"{url} [{param}]" if param else url
                per_location[key] = per_location.get(key, 0) + 1
            if per_location:
                self.console.print()
                self.console.print("[bold cyan][CELAH PER LOKASI / ENDPOINT][/bold cyan]")
                for key, count in sorted(per_location.items(), key=lambda kv: -kv[1])[:15]:
                    self.console.print(f"  • {key}: {count} finding(s)")

        # Accessible hosts (200 OK) section dari http_probe / ip_scan
        accessible_hosts = self.extra.get("accessible_hosts") or []
        if accessible_hosts:
            self.console.print()
            self.console.print("[bold #00FF41][+] ACCESSIBLE HOSTS (200 OK)[/bold #00FF41]")
            for h in accessible_hosts:
                title = h.get("title") or "-"
                server = h.get("server") or "-"
                self.console.print(f"  • {h.get('url')}  (title: {title}, server: {server})")

        if self.tech_stack:
            self.console.print()
            self.console.print(f"[dim]Detected technologies: {', '.join(self.tech_stack)}[/dim]")

        self.console.rule()

    def _risk_panel_content(self) -> str:
        """Kembalikan teks ringkasan risiko berbobot severity untuk panel."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in self.findings:
            sev = (f.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

        weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
        score = sum(counts[k] * weights[k] for k in counts)
        if score >= 30:
            level, color = "CRITICAL RISK", "red"
        elif score >= 15:
            level, color = "HIGH RISK", "red"
        elif score >= 6:
            level, color = "MEDIUM RISK", "yellow"
        elif score >= 1:
            level, color = "LOW RISK", "blue"
        else:
            level, color = "SAFE", "#00FF41"

        lines = [
            f"[{color}][RISK CONCLUSION][/{color}] {level} (score: {score})",
            f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']} | Info: {counts['info']}",
        ]
        return "\n".join(lines)

    def risk_summary(self) -> dict[str, Any]:
        """Kembalikan dict ringkasan risiko untuk disimpan ke JSON report."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in self.findings:
            sev = (f.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

        weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
        score = sum(counts[k] * weights[k] for k in counts)
        if score >= 30:
            level = "CRITICAL RISK"
        elif score >= 15:
            level = "HIGH RISK"
        elif score >= 6:
            level = "MEDIUM RISK"
        elif score >= 1:
            level = "LOW RISK"
        else:
            level = "SAFE"

        return {
            "risk_level": level,
            "risk_score": score,
            "severity_breakdown": counts,
            "thresholds": {"critical": 30, "high": 15, "medium": 6, "low": 1, "safe": 0},
            "weights": weights,
        }

    def save_markdown_report(
        self, target: str, requests_used: int, status: str = "COMPLETED"
    ) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace(":", "_").replace("/", "_")
        path = self.output_dir / f"ProbeX_{safe_target}_{timestamp}.md"

        risk = self.risk_summary()
        lines: list[str] = [
            f"# Laporan ProbeX - {target}",
            f"Tanggal: {datetime.now().isoformat()}",
            f"Status pemindaian: {status}",
            f"Permintaan terpakai: {requests_used}",
            "",
            "## Ringkasan risiko",
            f"- Tingkat risiko: {risk['risk_level']} (skor: {risk['risk_score']})",
            f"- Tinggi: {risk['severity_breakdown'].get('high', 0)}",
            f"- Sedang: {risk['severity_breakdown'].get('medium', 0)}",
            f"- Rendah/Info: {risk['severity_breakdown'].get('low', 0) + risk['severity_breakdown'].get('info', 0)}",
            "",
            "## Temuan",
        ]
        if not self.findings:
            lines.append("Tidak ada temuan.")
        else:
            for f in self.findings:
                loc = f.get("location", {})
                if not loc and f.get("url"):
                    loc = {
                        "url": f.get("url", ""),
                        "method": f.get("method", ""),
                        "parameter": f.get("parameter", ""),
                        "parameter_in": "",
                        "file": "",
                        "line": 0,
                        "snippet": f.get("evidence_snippet", ""),
                    }
                lines.append(f"### {f.get('title', '(tanpa judul)')}")
                lines.append(f"- Tipe: {f.get('type', '-')}")
                lines.append(f"- Tingkat: {f.get('severity', '-')} | Keyakinan: {f.get('confidence', '-')}")
                lines.append(f"- Deskripsi: {f.get('description', '-')}")
                lines.append(f"- Lokasi: {loc.get('url', '-')} [{loc.get('method', '-')}] param={loc.get('parameter', '-')} ({loc.get('parameter_in', '-')})")
                if loc.get("file"):
                    lines.append(f"- Berkas: {loc['file']}:{loc.get('line', 0)}")
                lines.append(f"- Bukti: {f.get('evidence', '-')}")
                lines.append(f"- Rekomendasi: {f.get('recommendation', '-')}")
                refs = f.get("references") or []
                if refs:
                    lines.append("- Referensi: " + ", ".join(refs))
                lines.append("")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        self.console.print(f"[dim]Markdown report saved: {path}[/dim]")
        return str(path)

    def save_report(self, target: str, requests_used: int, status: str = "COMPLETED") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace(":", "_").replace("/", "_")
        filename = f"ProbeX_{safe_target}_{timestamp}.json"
        path = self.output_dir / filename

        report = {
            "target": target,
            "scan_status": status,
            "timestamp": datetime.now().isoformat(),
            "requests_used": requests_used,
            "endpoints_found": self.endpoints,
            "findings": self.findings,
            "risk_summary": self.risk_summary(),
            "technologies": self.tech_stack,
            "extra": self.extra,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.console.print(f"[dim]Report saved: {path}[/dim]")
        return str(path)
