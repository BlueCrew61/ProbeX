# ProbeX — Web Exploitation Scanner + CachePoisonX (CTF / Authorized Labs)

ProbeX adalah scanner deteksi dan eksploitasi web untuk CTF / lab resmi (hackathon Codepolitan).
Versi ini sudah terintegrasi dengan **CachePoisonX** (dari `demo.zip`): deteksi dan injeksi cache poisoning
lewat header unkeyed. Tersedia **CLI** dan **GUI berbasis browser** yang memanggil backend yang sama.

> ⚠️ **Hanya untuk lab milik sendiri atau target dengan izin eksplisit.** Scan tidak berjalan tanpa
> konsensi pengguna (`PROBEX_CONSENT=1` atau ketik `ya` saat prompt).

---

## Daftar Isi

1. [Panduan Cepat (CLI & GUI)](#panduan-cepat-cli--gui)
2. [ProbeX — Vulnerability Scanner](#probex---vulnerability-scanner)
3. [CachePoisonX — Deteksi & Injeksi Cache Poisoning](#cachepoisonx---deteksi--injeksi-cache-poisoning)
4. [GUI + API Backend (probing lewat browser)](#gui--api-backend-probing-lewat-browser)
5. [Cara Menjalankan Lab (tes_lab)](#cara-menjalankan-lab-tes_lab)
6. [Struktur Repository](#struktur-repository)
7. [CHANGELOG](#changelog)

---

## Panduan Cepat (CLI & GUI)

Keduanya memanggil modul CachePoisonX yang sama, hasilnya identik.

### CLI (terminal)

```bash
cd ProbeX

PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899 --module cache-poisoning --no-safe --no-banner

PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899/article/demo --cache-inject --no-safe --no-banner
```

Flag tambahan injeksi: `--payload` (profil / path file / literal, boleh diulang), `--header` (vektor, boleh diulang, default `X-Forwarded-Host`).

### GUI (browser, tanpa perlu hapal perintah CLI)

```bash
cd ProbeX/tes_lab
python3 lab_cache_origin.py 8899

cd ProbeX

python3 probex_api.py 8777

xdg-open /home/liiannn/Documents/ProbeX/index.html
```

Di GUI:
- **Pemindai** — masukkan target → **Mulai Pindai** (deteksi via `/api/detect`)
- **Injeksi** — masukkan target → **Jalankan Pengujian** (injeksi via `/api/inject`)
- **Monitor Poisoning** — pantau webhook events real-time via `/api/events`

---

## ProbeX — Vulnerability Scanner

Scanner deteksi kerentanan web. Stack Python, tanpa dependensi berat. Semua deteksi **non-destruktif**.

### Detektor (8 kategori)

| # | Kategori | Tingkat | File |
|---|----------|---------|------|
| 1 | Broken Access Control / IDOR | Tinggi | `probex/modules/vuln_idor.py` |
| 2 | Injection: SQL, command, template | Tinggi | `probex/modules/vuln_injection.py` |
| 3 | SSRF | Tinggi | `probex/modules/vuln_ssrf.py` |
| 4 | Authentication / session flaw | Tinggi | `probex/modules/vuln_auth_session.py` |
| 5 | XSS | Sedang | `probex/modules/vuln_xss.py` |
| 6 | Security misconfiguration | Sedang | `probex/modules/vuln_misconfig.py` |
| 7 | Sensitive data exposure | Sedang | `probex/modules/vuln_data_exposure.py` |
| 8 | Business logic flaw | Bervariasi | `probex/modules/vuln_business_logic.py` |

Contoh pemakaian:

```bash
python3 probex.py http://127.0.0.1:8765 --vuln-scan --max-requests 200 --delay 0 --threads 1 --no-banner
```

Laporan tersimpan di `reports/` (JSON + Markdown). Tes otomatis: `python3 -m pytest tests/`.

---

## CachePoisonX — Deteksi & Injeksi Cache Poisoning

Dua mode yang **dipisah** (tidak digabung dalam satu command):

| Mode | Perintah | Sifat |
|------|----------|-------|
| Deteksi | `python3 probex.py <target> --module cache-poisoning --no-safe` | Read-only, tidak menanam payload |
| Injeksi | `python3 probex.py <target> --cache-inject --no-safe` | Tanam payload ke cache (attack mode) |

### Alur injeksi (3 langkah)

1. **Clear cache** lab (`/_cache/clear`) — mencegah bug `CACHE_WARM`
2. **INJECT** — kirim request dengan `<header>: <payload>` ke URL target
3. **REPLAY** — request tanpa header (pura-pura korban), verifikasi `X-Cache: HIT` + payload masih ada di body

Verdikt: `INJECTED`, `NOT_STICKY`, `PERSISTS_NO_CACHE`, `IGNORED`, `CACHE_WARM`.

### 3 bukti (bukan klaim)

```
step 0  PROBE   (URL terpisah)  X-Cache: MISS    Content-Length: 495
step 1  INJECT  (kirim header)  X-Cache: MISS    Content-Length: 573  <- payload masuk
step 2  REPLAY  (tanpa header)  X-Cache: HIT     Content-Length: 573  <- payload masih ada
```

1. **Jejak cache** — `MISS -> MISS -> HIT`. Request ketiga tanpa header apa pun, tapi dapat versi yang sudah diubah.
2. **Content-Length berubah** — body yang disajikan ke korban beda dari asli.
3. **Callback webhook** — payload yang menunjuk ke webhook akan menghasilkan request ke server penyerang setiap kali korban membuka halaman.

### Catatan penting

- Target harus punya layer cache (contoh: `lab_cache_origin.py` sudah mensimulasikan ini). DVWA polos tidak punya cache → mode injeksi tidak akan berhasil.
- Payload `webhook.site` tidak akan dapat callback jika mesin lab tidak ada internet. Arahkan ke lab sendiri: `--payload "127.0.0.1:8899/_hook/proof"`.
- Payload untuk **header harus satu baris** (HTTP header tidak boleh newline). Payload file multiline (mis. PHP) akan ditolak oleh `requests`.
- Tidak ada temuan bukan berarti target aman.

---

## GUI + API Backend (probing lewat browser)

Jika tidak nyaman pakai CLI, gunakan GUI yang terhubung ke backend API.

### Komponen

| File | Fungsi |
|------|--------|
| `index.html` | GUI SPA — 6 halaman: Pemindai, Analisis AI, Pengaturan API, Monitor Poisoning, SSH Crack, Injeksi |
| `style.css` | Palet "Precision Instrument Dark" dari desain Stitch |
| `script.js` | Logika SPA + `fetch()` ke `probex_api.py` |
| `probex_api.py` | Backend API (Python stdlib `http.server`, port 8777) — `/api/detect`, `/api/inject`, `/api/events`, `/api/cache/clear`, `/api/status` |

### Cara pakai

```bash
cd ProbeX/tes_lab
python3 lab_cache_origin.py 8899

cd ProbeX

python3 probex_api.py 8777

xdg-open /home/liiannn/Documents/ProbeX/index.html
```

---

## Cara Menjalankan Lab (tes_lab)

Lab server ada di `tes_lab/lab_cache_origin.py` (origin + cache + webhook receiver, port 8899).

```bash
cd ProbeX/tes_lab
python3 lab_cache_origin.py 8899

Reset sebelum demo:

curl -s http://127.0.0.1:8899/_cache/clear
curl -s http://127.0.0.1:8899/_events/clear


Endpoint lab:
- `GET /article/<slug>` — halaman artikel (di-cache)
- `GET /_hook/<token>` — webhook receiver
- `GET /_monitor` — dashboard live
- `GET /_events` — JSON semua hit webhook
- `GET /_events/clear` — kosongkan log
- `GET /_cache/clear` — kosongkan cache

Buka `http://127.0.0.1:8899/_monitor` di browser untuk melihat webhook masuk secara real-time.

---

## Struktur Repository

```
/home/liiannn/Documents/ProbeX/
├── README.md                    <- file ini
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

## CHANGELOG

Lihat `CHANGELOG.md` di root repository untuk riwayat versi lengkap (v1.6 s/d v1.8, termasuk modul `apache_poisoning`, `ip_scan`, panel risiko berbobot severity, dll.).

---

**Dibuat untuk hackathon Codepolitan.** Gunakan bijak, hanya pada target yang Anda punya izin untuk menguji.
