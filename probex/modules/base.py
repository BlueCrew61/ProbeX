"""Base class for all scanner modules."""

from abc import ABC, abstractmethod
from typing import List, Optional
from rich.console import Console

from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.reporter import Reporter

from probex.utils.urls import discover_endpoints


class BaseModule(ABC):
    """Abstract base for every scanning module."""

    name: str = "BaseModule"

    def __init__(
        self,
        config: Config,
        request_manager: RequestManager,
        reporter: Reporter,
        console: Console,
    ):
        self.config = config
        self.rm = request_manager
        self.reporter = reporter
        self.console = console

    @abstractmethod
    def run(self) -> None:
        """Execute the module logic."""
        ...

    def log(self, msg: str, style: str = "dim"):
        self.console.print(f"    [{style}]{msg}[/{style}]")

    def log_hit(self, msg: str):
        """Temuan positif — style hijau."""
        self.console.print(f"    [green][!][/green] {msg}")

    def log_skip(self, msg: str):
        """Dilewati — style kuning."""
        self.console.print(f"    [yellow][-][/yellow] {msg}")

    def endpoints(self, extra: Optional[List[str]] = None) -> List[str]:
        """Daftar endpoint deduplikasi (reporter.endpoints + base_url + extra)."""
        return discover_endpoints(self.reporter, self.config.base_url, extra=extra)

    def budget_ok(self) -> bool:
        """Masih ada request budget dan target belum rate-limit (429)."""
        return self.config.can_request() and not self.rm.stopped_by_429