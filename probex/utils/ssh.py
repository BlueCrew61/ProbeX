"""Utilitas SSH bersama untuk modul eksploitasi ProbeX (CTF lab only).

Berisi fungsi brute_force_ssh_username yang sebelumnya tersebar di beberapa
modul, kini dikonsolidasi di satu tempat agar mudah dipelihara.
"""

from __future__ import annotations

import paramiko

COMMON_SSH_USERNAMES: list[str] = [
    "root",
    "ubuntu",
    "blue_crew61",
    "admin",
    "user",
    "kali",
    "debian",
    "ctf",
    "player",
]


def brute_force_ssh_username(
    host: str, port: int, private_key_path: str
) -> str:
    """Coba login dengan daftar username umum menggunakan private key lokal.

    Mengembalikan username yang berhasil, atau "root" sebagai fallback.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        kunci_privat = paramiko.RSAKey.from_private_key_file(private_key_path)
    except Exception as exc:
        print(f"[bold red][-[/bold red] Gagal membaca private key lokal: {exc}")
        return "root"

    print(
        "[bold yellow][*][/bold yellow] Mencari username SSH yang cocok pada target secara otomatis..."
    )

    for username in COMMON_SSH_USERNAMES:
        try:
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=kunci_privat,
                timeout=3,
            )
            ssh.close()
            print(
                f"[bold green][+][/bold green] Username valid ditemukan: "
                f"[bold cyan]{username}[/bold cyan]"
            )
            return username
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break

    return "root"
