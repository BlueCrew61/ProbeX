"""ProbeX branding — warna, tema, dan ASCII banner startup (hacker/cyberpunk)."""

from __future__ import annotations

# Warna utama (tema merah-hijau gelap)
PROBE_X_RED = "#FF3333"        # Bright red (primary / critical)
PROBE_X_DARK_RED = "#CC0022"   # Darker red (secondary)
PROBE_X_GREEN = "#00FF41"      # Neon green (logo / safe / success)
PROBE_X_BLACK = "#0A0A0A"      # Background (deep black)
PROBE_X_GRAY = "#1A1A1A"       # Panel background
PROBE_X_WHITE = "#FFFFFF"      # Primary text
PROBE_X_DIM = "#888888"        # Secondary text

PROBE_X_NAME = "PROBEX"
PROBE_X_VERSION = "1.8"

LOGO_LINES = [
    r" ██████╗ ██████╗  ██████╗ ██████╗ ███████╗██╗  ██╗",
    r" ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝",
    r" ██████╔╝██████╔╝██║   ██║██████╔╝█████╗   ╚███╔╝ ",
    r" ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝   ██╔██╗ ",
    r" ██║     ██║  ██║╚██████╔╝██████╔╝███████╗██╔╝ ██╗",
    r" ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝",
]


def print_banner(console=None) -> None:
    """Cetak banner PROBEX langsung ke console dengan warna rich (tanpa frame/border luar)."""
    import shutil
    from rich.console import Console as RichConsole
    from rich.text import Text

    con = console or RichConsole(highlight=False)
    width = min(shutil.get_terminal_size().columns, 90)

    con.print()
    for line in LOGO_LINES:
        centered = line.center(width)
        con.print(Text(centered, style="bold bright_green"))
    con.print()


def banner_text(use_gradient: bool = True) -> str:
    """Kompatibilitas mundur — kembalikan string teks logo saja (tanpa border/frame).

    Disarankan pakai print_banner() langsung agar warna rich tampil benar.
    Pyfiglet hanya sebagai fallback.
    """
    art = "\n".join(LOGO_LINES)
    return art
