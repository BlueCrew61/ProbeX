"""Sensitive file exposure scanner — authorized CTF labs only.

Probe path file yang sering bocor di server web dan bisa mengungkap rahasia /
struktur aplikasi:

  - .env, .env.local, .env.production, .env.development
  - wp-config.php, config.php, config.json, settings.py, web.config
  - database.sql, dump sql, *.db, *.sqlite
  - .git/config, .svn/entries, .htaccess
  - id_rsa, id_rsa.pub, authorized_keys
  - composer.lock, package-lock.json (versi library)
  - Docker, Kubernetes, CI/CD config files
  - Backup files (.bak, .save, .old, ~)

Semua probe read-only: satu GET per path, tidak menulis payload. Hanya
melaporkan path yang mengembalikan HTTP 200 dengan body yang mengandung
konten mencurigakan.
"""

from __future__ import annotations

import json
import re
from typing import List, Tuple
from urllib.parse import urlparse

from .base import BaseModule

# (path, deskripsi, penanda konten yang dicari di body respons)
SENSITIVE_FILES: List[Tuple[str, str, List[str]]] = [
    (".env", "Environment file", ["APP_KEY", "DB_", "MAIL_", "SECRET", "AWS_", "DATABASE_URL"]),
    (".env.local", "Environment file (local)", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    (".env.production", "Environment file (production)", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    (".env.development", "Environment file (development)", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    (".env.example", "Environment file (example)", ["APP_KEY", "DB_", "MAIL_"]),
    # WordPress & PHP config + backups
    ("wp-config.php", "WordPress config", ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]),
    ("wp-config.php.bak", "WordPress config backup", ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]),
    ("wp-config.php.save", "WordPress config save", ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]),
    ("wp-config.php.old", "WordPress config old", ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]),
    ("wp-config.php~", "WordPress config backup (tilde)", ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]),
    ("config.php", "PHP config", ["$db", "$host", "$user", "$pass", "mysqli", "PDO"]),
    ("config.php.bak", "PHP config backup", ["$db", "$host", "$user", "$pass"]),
    ("config.php.save", "PHP config save", ["$db", "$host", "$user", "$pass"]),
    ("config.php.old", "PHP config old", ["$db", "$host", "$user", "$pass"]),
    ("config.php~", "PHP config backup (tilde)", ["$db", "$host", "$user", "$pass"]),
    # Environment file backups
    (".env.bak", "Environment backup", ["APP_KEY", "DB_", "MAIL_", "SECRET", "AWS_", "DATABASE_URL"]),
    (".env.save", "Environment save", ["APP_KEY", "DB_", "MAIL_", "SECRET", "AWS_", "DATABASE_URL"]),
    (".env.old", "Environment old", ["APP_KEY", "DB_", "MAIL_", "SECRET", "AWS_", "DATABASE_URL"]),
    (".env~", "Environment backup (tilde)", ["APP_KEY", "DB_", "MAIL_", "SECRET", "AWS_", "DATABASE_URL"]),
    (".env.production.bak", "Production env backup", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    (".env.staging", "Staging environment", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    (".env.staging.bak", "Staging env backup", ["APP_KEY", "DB_", "MAIL_", "SECRET"]),
    # Docker & Kubernetes
    ("docker-compose.yml", "Docker Compose", ["environment:", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "REDIS_PASSWORD", "SECRET_KEY"]),
    ("docker-compose.yaml", "Docker Compose", ["environment:", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "REDIS_PASSWORD", "SECRET_KEY"]),
    ("docker-compose.override.yml", "Docker Compose override", ["environment:", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD"]),
    (".dockerignore", "Docker ignore", [".env", "secret", "key", "password"]),
    ("kubernetes.yaml", "Kubernetes config", ["password", "secret", "token", "key"]),
    ("k8s.yaml", "Kubernetes config", ["password", "secret", "token", "key"]),
    ("secret.yaml", "Kubernetes secret", ["password", "secret", "token", "key"]),
    # YAML configs
    ("config.yaml", "YAML config", ["password", "secret", "apiKey", "token", "key"]),
    ("config.yml", "YAML config", ["password", "secret", "apiKey", "token", "key"]),
    ("settings.yaml", "Settings YAML", ["password", "secret", "apiKey", "token"]),
    ("settings.yml", "Settings YAML", ["password", "secret", "apiKey", "token"]),
    # CI/CD configs
    (".github/workflows/ci.yml", "GitHub Actions CI", ["secret", "token", "key", "password"]),
    (".github/workflows/cd.yml", "GitHub Actions CD", ["secret", "token", "key", "password"]),
    (".gitlab-ci.yml", "GitLab CI", ["secret", "token", "key", "password", "variable"]),
    ("bitbucket-pipelines.yml", "Bitbucket Pipelines", ["secret", "token", "key", "password"]),
    (".drone.yml", "Drone CI", ["secret", "token", "key", "password"]),
    ("Jenkinsfile", "Jenkins pipeline", ["secret", "token", "key", "password", "credentialsId"]),
    (".travis.yml", "Travis CI", ["secret", "token", "key", "password", "secure:"]),
    ("circle.yml", "CircleCI", ["secret", "token", "key", "password"]),
    (".circleci/config.yml", "CircleCI config", ["secret", "token", "key", "password"]),
    # Other configs
    ("config.json", "JSON config", ["password", "secret", "connectionString", "apiKey"]),
    ("settings.py", "Django/Python settings", ["SECRET_KEY", "DATABASES", "DEBUG", "ALLOWED_HOSTS"]),
    ("web.config", "IIS web.config", ["connectionString", "<configuration>", "appSettings"]),
    # Database dumps
    ("database.sql", "SQL dump", ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "MySQL dump"]),
    ("db.sql", "SQL dump", ["CREATE TABLE", "INSERT INTO", "MySQL dump"]),
    ("dump.sql", "SQL dump", ["CREATE TABLE", "INSERT INTO", "MySQL dump"]),
    ("backup.sql", "SQL backup", ["CREATE TABLE", "INSERT INTO", "MySQL dump"]),
    ("site.sql", "SQL dump", ["CREATE TABLE", "INSERT INTO", "MySQL dump"]),
    (".db", "SQLite database", ["SQLite format 3"]),
    (".sqlite", "SQLite database", ["SQLite format 3"]),
    (".sqlite3", "SQLite database", ["SQLite format 3"]),
    # VCS
    (".git/config", "Git config", ["[core]", "repositoryformatversion", "url ="]),
    (".svn/entries", "SVN entries", ["dir", "svn:", "wcrd"]),
    # Web server
    (".htaccess", "Apache htaccess", ["AuthType", "Require", "RewriteEngine", "deny from"]),
    (".htpasswd", "Apache htpasswd", [":$apr1$", ":$1$", "{SHA}", "crypt("]),
    # SSH keys
    ("id_rsa", "SSH private key", ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY"]),
    ("id_rsa.pub", "SSH public key", ["ssh-rsa", "ssh-ed25519", "ssh-dss"]),
    ("authorized_keys", "SSH authorized keys", ["ssh-rsa", "ssh-ed25519", "ssh-dss"]),
    # Lock files
    ("composer.lock", "PHP Composer lock", ["content-hash", "packages", "name", "version"]),
    ("package-lock.json", "Node lock", ["lockfileVersion", "dependencies", "packages"]),
    ("yarn.lock", "Yarn lock", ["# yarn lockfile", "resolved", "version"]),
    # Credentials
    ("credentials.csv", "Credentials CSV", ["user", "pass", "password", "api_key", "secret"]),
    ("credentials.json", "Credentials JSON", ["password", "secret", "api_key", "access_key"]),
    # PHP info
    ("phpinfo.php", "PHP info page", ["phpinfo()", "PHP Version", "phpinfo"]),
    ("info.php", "PHP info page", ["phpinfo()", "PHP Version"]),
    ("test.php", "PHP test page", ["phpinfo", "<?php", "echo"]),
]

# Daftar path lengkap untuk pemindaian root domain.
COMMON_PATHS = [path for path, _, _ in SENSITIVE_FILES]


def _env_marker_found(body: str, markers: List[str]) -> bool:
    """.env: baris KEY=VALUE (bukan komentar), marker sebagai kunci."""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "//", "/*", "*")):
            continue
        if "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key.upper() in {m.upper() for m in markers}:
            return True
    return False


def _json_marker_found(body: str, markers: List[str]) -> bool:
    """JSON: marker sebagai kunci objek atau nilai string."""
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return False

    want = {m.lower() for m in markers}

    def walk(value) -> bool:
        if isinstance(value, dict):
            for k, v in value.items():
                if str(k).lower() in want:
                    return True
                if walk(v):
                    return True
        elif isinstance(value, list):
            for item in value:
                if walk(item):
                    return True
        elif isinstance(value, str) and value.lower() in want:
            return True
        return False

    return walk(obj)


def _php_marker_found(body: str, markers: List[str]) -> bool:
    """PHP: $var = ... atau define('MARKER', ...)."""
    want = {m.lower().lstrip("$") for m in markers}
    for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=", body):
        if m.group(1).lower() in want:
            return True
    for m in re.finditer(r"define\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", body):
        if m.group(1).lower() in want:
            return True
    return False


def _sql_marker_found(body: str, markers: List[str]) -> bool:
    """SQL dump: statement DDL/DML, bukan substring sembarang."""
    upper = body.upper()
    has_stmt = any(s in upper for s in ("CREATE TABLE", "INSERT INTO", "DROP TABLE", "MYSQL DUMP"))
    return has_stmt and _looks_sensitive_substring(body, markers)


def _gitconfig_marker_found(body: str, markers: List[str]) -> bool:
    """.git/config: INI-style [section] + key = value."""
    want = {m.lower() for m in markers}
    current_section = None
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        sec = re.match(r"^\[([^\]]+)\]$", stripped)
        if sec:
            current_section = sec.group(1).lower()
            continue
        if "=" in stripped and current_section:
            key = stripped.split("=", 1)[0].strip().lower()
            if key in want:
                return True
    return False


def _yaml_marker_found(body: str, markers: List[str]) -> bool:
    """YAML: key: value dengan marker sebagai kunci."""
    try:
        import yaml
        obj = yaml.safe_load(body)
    except Exception:
        return False

    want = {m.lower() for m in markers}

    def walk(value) -> bool:
        if isinstance(value, dict):
            for k, v in value.items():
                if str(k).lower() in want:
                    return True
                if walk(v):
                    return True
        elif isinstance(value, list):
            for item in value:
                if walk(item):
                    return True
        elif isinstance(value, str) and value.lower() in want:
            return True
        return False

    return walk(obj) if obj else False


def _looks_sensitive_substring(body: str, markers: List[str]) -> bool:
    upper = body.upper()
    for marker in markers:
        if marker.upper() in upper:
            return True
    return False


def _looks_sensitive(body: str, markers: List[str], path: str) -> bool:
    """Cek marker dengan konteks sesuai jenis file (bukan substring mentah)."""
    lower = path.lower()
    if lower.endswith((
        ".env", ".env.local", ".env.production", ".env.development", ".env.example",
        ".env.bak", ".env.save", ".env.old", ".env~", ".env.production.bak",
        ".env.staging", ".env.staging.bak",
    )):
        return _env_marker_found(body, markers)
    if lower.endswith((".json", ".lock")):
        return _json_marker_found(body, markers)
    if lower.endswith((".php",)):
        return _php_marker_found(body, markers)
    if lower.endswith((".sql", ".db", ".sqlite", ".sqlite3")):
        return _sql_marker_found(body, markers)
    if lower.endswith((".git/config", ".svn/entries")):
        return _gitconfig_marker_found(body, markers)
    if lower.endswith((".yaml", ".yml")):
        return _yaml_marker_found(body, markers)
    return _looks_sensitive_substring(body, markers)


class SensitiveFilesModule(BaseModule):
    name = "Sensitive File Exposure Scanner"

    def run(self) -> None:
        base = self.config.base_url.rstrip("/")
        parsed_base = urlparse(base)
        netloc = parsed_base.netloc
        scheme = parsed_base.scheme

        found_any = False

        for path, desc, markers in SENSITIVE_FILES:
            if not self.config.can_request() or self.rm.stopped_by_429:
                break

            url = f"{scheme}://{netloc}{path}"
            resp = self.rm.get(url, allow_redirects=False, timeout=8)
            if resp is None:
                continue
            if resp.status_code != 200:
                continue

            body = resp.text or ""
            if not _looks_sensitive(body, markers, path):
                continue

            self.log(f"[+] File sensitif ditemukan: {path} (HTTP {resp.status_code}) — {desc}")
            self.reporter.add_endpoint(url)
            self.reporter.add_finding(
                f"Sensitive file exposed: {path}",
                severity="high",
                detail=f"{desc} terekspos di {path}",
                evidence=f"HTTP {resp.status_code}, body markers: {markers[:3]}",
                url=url,
                method="GET",
                parameter="",
                evidence_snippet=f"HTTP {resp.status_code}, body markers: {markers[:3]}",
            )
            found_any = True

        if not found_any:
            self.log("Tidak ada file sensitif (.env, wp-config, sql, db, config, dst.) yang terekspos")
