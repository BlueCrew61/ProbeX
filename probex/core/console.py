"""ProbeX console — Rich Console dengan tema hacker/cyberpunk merah-hijau di latar gelap."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

PROBE_X_THEME = Theme({
    "critical":       "bold white on #FF3333",  # Critical: teks putih latar merah
    "high":           "bold #FF3333",            # High: merah cerah tebal
    "medium":         "bold yellow",             # Medium: kuning tebal
    "low":            "bold blue",               # Low: biru tebal
    "info":           "bold cyan",               # Info: cyan
    "safe":           "bold bright_green",       # Safe / passed: hijau neon
    "banner":         "bold bright_green",       # Banner logo: hijau neon
    "border":         "bold red",                # Border/frame: merah tebal
    "label":          "bold white",              # Label teks biasa
    "path":           "bold red",                # Path/endpoint highlight: merah
    "timestamp":      "bold red",                # Timestamp [HH:MM:SS]: merah
    "prompt":         "bold green",              # Prompt user@host: hijau
    "modules":        "bold yellow",             # Module list header: kuning
    "active":         "bold bright_red",         # [ ACTIVE ] tag: merah cerah
    "dim":            "#888888",                 # Teks sekunder redup
    "muted":          "#555555",                 # Teks paling redup
    "progress_bar":   "bold red",                # Progress bar fill: merah
    "progress_track": "dim red",                 # Progress bar track: merah redup
})

console = Console(theme=PROBE_X_THEME, force_terminal=None)

__all__ = ["console", "PROBE_X_THEME"]
