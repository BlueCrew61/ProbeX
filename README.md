# ProbeX — Vulnerability Scanner (OWASP Top 10)

Scanner deteksi kerentanan web untuk developer pemula, bagian dari proyek hackathon Codepolitan. Stack: Python (Flask untuk dashboard), tanpa dependensi berat. Semua deteksi bersifat **non-destruktif** (hanya deteksi dan pelaporan, tidak ada exploit, tidak ada perubahan data pada target).

## Detektor (8 kategori, arsitektur plugin)

| # | Kategori | Tingkat | File detektor |
|---|----------|---------|---------------|
| 1 | Broken Access Control / IDOR | Tinggi | `probex/modules/vuln_idor.py` |
| 2 | Injection: SQL, command, template | Tinggi | `probex/modules/vuln_injection.py` |
| 3 | SSRF | Tinggi | `probex/modules/vuln_ssrf.py` |
| 4 | Authentication / session flaw | Tinggi | `probex/modules/vuln_auth_session.py` |
| 5 | XSS | Sedang | `probex/modules/vuln_xss.py` |
| 6 | Security misconfiguration | Sedang | `probex/modules/vuln_misconfig.py` |
| 7 | Sensitive data exposure | Sedang | `probex/modules/vuln_data_exposure.py` |
| 8 | Business logic flaw | Bervariasi | `probex/modules/vuln_business_logic.py` |

Setiap detektor berdiri sendiri (subclass `BaseModule`) dan mudah ditambah: buat file baru di `probex/modules/`, daftarkan di `probex/core/scanner.py`.

## Format temuan (wajib JSON)

```json
{
  "id": "vuln-001",
  "type": "idor|injection|ssrf|auth_session|xss|misconfig|data_exposure|business_logic",
  "severity": "Tinggi|Sedang|Bervariasi",
  "confidence": "Tinggi|Sedang|Rendah",
  "title": "...",
  "description": "...",
  "location": {
    "url": "...",
    "method": "GET|POST",
    "parameter": "...",
    "parameter_in": "query|body|header|cookie",
    "file": "...",
    "line": 0,
    "snippet": "..."
  },
  "evidence": "...",
  "recommendation": "... (bahasa Indonesia)",
  "references": ["OWASP Top 10 2021 ...", "CWE-..."]
}
```

Lokasi selalu disertakan: URL + parameter untuk mode scan web, atau file + nomor baris untuk mode scan kode statis. Nilai rahasia disamarkan sebelum disimpan ke log/laporan.

## Mode scan

- **Mode URL (dinamis):** `python3 probex.py <URL> --vuln-scan`
  Crawling terbatas (halaman, form, parameter, header, cookie) dalam satu origin, rate limit default 5 req/detik, timeout, User-Agent jelas, dan User-Agent jelas. Hanya domain target diikuti.
- **Mode kode (statis):** deteksi pola berbahaya dalam source code; lokasi = file + baris.

## Konsensi dan etika (wajib)

Sebelum scan dimulai, pengguna harus menyetujui pernyataan izin uji target (`PROBEX_CONSENT=1` untuk non-TTY/CI). Scan tidak berjalan tanpa konsensi. Tidak ada akses ke alamat internal/metadata cloud (SSRF hanya diuji dengan callback URL milik pengguna). Tidak ada penyimpanan kredensial/rahasia mentah ke log.

## Contoh pemakaian

```bash
# Target latihan lokal (legal, mesin sendiri)
python3 probex.py http://127.0.0.1:8765 --vuln-scan --max-requests 200 --delay 0 --threads 1 --no-banner

# Dengan callback SSRF milik pengguna
python3 probex.py <target> --vuln-scan --ssrf-callback https://callback-contoh.example/cb

# Mode teks polos (non-TTY / redirect log)
python3 probex.py <target> --vuln-scan --no-banner
```

Laporan tersimpan di `reports/` sebagai JSON dan Markdown (nama berkas berstempel waktu). Dashboard Flask: `probex/ui/app.py` (ringkasan per tingkat risiko, tabel temuan filter/urutkan, halaman detail lokasi).

## Bukti berjalan (target latihan lokal)

Target: mini Flask rentan sengaja di `127.0.0.1:8765` (`/page`, `/item?id=`, `/search?q=`, `/fetch?url=`, `/.env`, `/.git/HEAD`, `/login`, `/checkout`).

Hasil scan akhir:
- 12 endpoint ditemukan oleh crawling terbatas
- 17 temuan: idor 2, injection 3, ssrf 1, auth_session 1, xss 4, misconfig 3, data_exposure 1, business_logic 2
- Semua temuan dalam format JSON di atas dengan lokasi (URL + parameter)
- Contoh: `idor` pada `/item?id=1001` (param `id`, query); `injection` SQL pada `/search?q=laptop` (param `q`); `auth_session` pada `/login` (body, tanpa pembatasan percobaan login)

## Pengujian otomatis

```bash
python3 -m pytest tests/      # 36/36 lolos (8 berkas, satu per detektor)
python3 -m py_compile probex/modules/*.py   # semua kompile
```

## Keterbatasan dan asumsi

- IDOR dengan satu sesi hanya berlabel "potensial" (perlu dua akun untuk konfirmasi).
- SSRF tidak pernah diuji aktif ke alamat internal/metadata; hanya identificatory parameter berisiko, kecuali callback publik dikonfigurasi pengguna.
- Command injection hanya dideteksi secara statis (tidak ada eksekusi perintah pada target).
- Business logic tidak dapat diotomasi sepenuhnya: selalu berconfidence rendah, ditandai "perlu verifikasi manual" dengan checklist.
- Crawling terbatas pada satu origin dan depth 1 (maks. 20 halaman).
- Asumsi aman: saat ambigu, pilih opsi paling tidak merusak dan dicatat di laporan.

## Fitur lain di CLI

Flag lama (`--module`, `--ssti`, `--find-flag`, `--guided`, `--flow`, dll.) masih tersedia untuk alur CTF; dokumentasi versi lama tersisa di riwayat repo. Fitur utama versi ini adalah Vulnerability Scanner di atas.
