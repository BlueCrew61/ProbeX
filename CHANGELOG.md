# ProbeX Changelog

## v1.8

- Terminal redesign tema cyberpunk (merah-hijau di atas background gelap) dengan `rich`: banner ASCII "PROBEX" bergradien merah→hijau di dalam panel border merah, header `[+] Target` / `[+] IP` dengan timestamp rata kanan `[HH:MM:SS]`, baris `[ MODULES LOADED: N ]` + progress bar `rich.progress.Progress` (bar merah di atas track abu-abu gelap) dengan persentase dan estimasi waktu tersisa, temuan real-time dengan prefix berwarna severity (`[!]` HIGH/CRITICAL merah, `[i]` INFO cyan, `[+]` SAFE/PASSED hijau, `[-]` gagal kuning), semua section dalam panel border merah.
- CLI opsi baru `--no-banner`; deteksi otomatis non-TTY (output di-redirect ke file) mematikan banner/warna dan fallback ke teks polos.
- Modul baru `apache_poisoning` (Apache Cache Poisoning / Vuln Detector, read-only/bounded): fingerprint versi Apache vs CVE-2021-41773 / CVE-2021-42013 (deteksi saja, tidak eksploitasi RCE/shell), cek permukaan cache poisoning header unkeyed (X-Forwarded-Host/Scheme/Proto, X-Original-URL) dengan marker inert, dan deteksi indikasi cache sudah terinjeksi. Maksimal ~8 request, hormati budget/delay/stop-on-429-503.
- Modul baru `ip_scan` (IP / Host Accessible Scanner): dukungan CIDR, rate limiting, parallel port scan (threads cap 1-3), probing HTTP(S) ke host dari `subdomains`/`live_hosts` + target utama, hanya melaporkan host dengan HTTP 200 ke `reporter.extra["accessible_hosts"]` dan section terminal "[+] ACCESSIBLE HOSTS (200 OK)".
- Panel kesimpulan risiko berbobot severity: critical=10, high=6, medium=3, low=1, info=0; threshold >=30 CRITICAL, >=15 HIGH, >=6 MEDIUM, >=1 LOW, 0 SAFE; ditampilkan sebagai panel dan disimpan ke JSON report di field baru `risk_summary` (`risk_level`, `risk_score`, breakdown per severity). Field findings lama (`title`, `severity`, `detail`, `evidence`) tetap utuh (backward compatible).
- Keduanya terdaftar di scanner pipeline dan dipilih via `--module apache_poisoning,ip_scan` sesuai pola modul lain.
- `pyfiglet` ditambahkan ke `requirements.txt` dengan graceful fallback jika belum ter-install.
- `python3 probex.py --help` tetap normal, tidak ada breaking change pada argumen CLI yang sudah ada, dan mekanisme safety (`--safe` default, `--max-requests`, `--delay`, `--threads` cap 1-3, stop-on-429/503, origin-check redirect) tetap utuh.
- Update README.md dan CHANGELOG.md; tes pytest (mock request_manager, tanpa jaringan) kembali lolos.

### Perbaikan bug (v1.8)
- `vuln_business_logic.py`: `str(getattr(self.config, "base_url", ""))` → `str(self.config.base_url)` (getattr fallback mengembalikan objek Config saat `base_url_override=None`).
- `vuln_ssrf.py`: `_is_public_url` kini menolak nama host internal/metadata (localhost, `.local`, `metadata.google.internal`, `169.254.169.254`) bukan hanya alamat IP privat.
- `vuln_data_exposure.py`: variabel `r` diubah menjadi `resp` untuk kejelasan (tidak ada variabel pendek satu huruf).
- `ssh_shutdown.py`: `brute_force_ssh_username` dan `COMMON_SSH_USERNAMES` dikonsolidasikan ke `probex/utils/ssh.py` (tidak lagi tersebar di dua modul).
- Semua modul dikompilasi ulang dengan `py_compile`; `pytest tests/` 36/36 lolos.

## v1.7

- Added structured location fields to every finding: `url`, `method`, `parameter`, and `evidence_snippet` (new optional parameters on `Reporter.add_finding()`, backward compatible with old call signature); `evidence_snippet` falls back to `evidence`.
- JSON report (`Reporter.save_report`) now stores location fields per finding.
- Terminal `print_summary` now shows `→ Lokasi: <url> [param: <nama>]` per finding and a grouped "CELAH PER LOKASI / ENDPOINT" summary (top 15) beside the per-category summary.
- Directory probe now reports only HTTP status 200 paths (`accessible_paths`, `add_endpoint`, finding "Accessible path"); requests still hit every candidate path.
- http_probe now records only status 200 hosts to `live_hosts`, adds them as endpoints, and can raise finding "Live interesting host".
- Added CLI option `--all-status` (default off) to restore reporting of every status code for http_probe/directory probing.
- Rewrote all `add_finding()` call sites across ~34 modules to pass structured location info where URL/parameter is known (fixes breakage from automatic transform script).
- All modules re-verified to compile cleanly with `py_compile`.

## v1.6

- Added inert reflected HTML injection checks for a small number of same-origin GET inputs.
- Added public HTTP directory-listing recognition and visible entry reporting.
