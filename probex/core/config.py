"""Global configuration and safety controls for ProbeX."""

from dataclasses import dataclass, field
from typing import Optional, List
import re


@dataclass
class Config:
    """Scanner configuration with safe defaults."""

    # Legacy positional-style fields (kept for backward compatibility)
    target_ip: str = ""
    target_port: int = 80
    flag_prefix: str = ""

    # New flexible fields
    base_url_override: Optional[str] = None
    flag_format: Optional[str] = None
    custom_flag_regex: Optional[str] = None

    use_https: bool = False
    root_domain: Optional[str] = None
    shd_mode: bool = False
    safe_mode: bool = True
    low_impact: bool = False
    max_requests: int = 300
    delay: float = 1.0
    threads: int = 1
    timeout: int = 10
    max_response_size: int = 512_000
    modules: Optional[List[str]] = None
    find_flag_only: bool = False
    show_workflow_tokens: bool = False
    show_tokens: bool = False
    guided: bool = False
    interactive_workflow: bool = False
    # SSH brute force / shutdown config (gated behind --no-safe + --ssh-confirm)
    ssh_port: int = 22
    ssh_private_key: Optional[str] = None
    ssh_cupp: bool = False
    ssh_confirm: bool = False
    # CTF job ID: when set, scanner fetches challenge details and runs
    # appropriate modules to solve the job.
    job_id: Optional[str] = None
    user_agent: str = (
        "ProbeX/1.7 (Web Exploitation Scanner; authorized CTF labs only)"
    )
    ssrf_callback: Optional[str] = None
    max_redirects: int = 3
    stop_on_429: bool = True
    request_budget_remaining: int = field(init=False)
    all_status: bool = False
    no_banner: bool = False

    def __post_init__(self):
        if self.flag_format:
            self.flag_prefix = self.flag_format
        elif self.flag_prefix:
            self.flag_format = self.flag_prefix

        self.max_requests = max(1, int(self.max_requests))
        if self.threads < 1:
            self.threads = 1
        if self.threads > 3:
            self.threads = 3
        if self.delay < 0.2:
            self.delay = 0.2
        if self.low_impact:
            self.safe_mode = True
            self.threads = 1
            self.delay = max(self.delay, 1.5)
            self.max_requests = min(self.max_requests, 50)
        self.request_budget_remaining = self.max_requests

    @property
    def base_url(self) -> str:
        if self.base_url_override:
            return self.base_url_override.rstrip("/")
        scheme = "https" if self.use_https else "http"
        if (self.use_https and self.target_port == 443) or (
            not self.use_https and self.target_port == 80
        ):
            return f"{scheme}://{self.target_ip}"
        return f"{scheme}://{self.target_ip}:{self.target_port}"

    @property
    def flag_regex(self) -> re.Pattern:
        if self.custom_flag_regex:
            return re.compile(self.custom_flag_regex, re.IGNORECASE)
        if self.flag_prefix:
            prefix = re.escape(self.flag_prefix)
            pattern = prefix + r"\{[^}]+\}"
            return re.compile(pattern, re.IGNORECASE)
        return re.compile(r"$^")

    def can_request(self) -> bool:
        return self.request_budget_remaining > 0

    def consume_request(self, n: int = 1) -> bool:
        if self.request_budget_remaining >= n:
            self.request_budget_remaining -= n
            return True
        return False

    def remaining_requests(self) -> int:
        return self.request_budget_remaining
