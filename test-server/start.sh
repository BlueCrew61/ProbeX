#!/bin/bash
# Start test SSH server (vulnerable) untuk pengujian ProbeX
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if ! docker info >/dev/null 2>&1; then
    echo "[-] Docker tidak berjalan. Mulai Docker dulu."
    exit 1
fi

echo "[*] Membangun image test-ssh-vuln..."
docker build -t test-ssh-vuln . >/dev/null 2>&1

echo "[*] Menghapus container lama (jika ada)..."
docker rm -f probex-ssh-test >/dev/null 2>&1 || true

echo "[*] Menjalankan container SSH rentan di port 2222..."
docker run -d --name probex-ssh-test -p 2222:2222 test-ssh-vuln >/dev/null 2>&1

sleep 2

echo ""
echo "=============================================="
echo "Test SSH server berjalan di localhost:2222"
echo "=============================================="
echo "User / Password (coba dengan ProbeX):"
echo "  admin   / password123"
echo "  user    / 123456"
echo "  root    / toor"
echo "  ctf     / ctf123"
echo ""
echo "Flag di dalam container: /flag.txt"
echo "  FLAG{ssh_bruteforce_success}"
echo ""
echo "Contoh pakai Probex (bash):"
echo "  ./Probex -p 2222 -y localhost"
echo ""
echo "Contoh pakai probex.py (Python):"
echo "  python3 probex.py localhost --ssh-shutdown --ssh-port 2222 --ssh-confirm --no-safe"
echo ""
echo "Untuk matikan: docker stop probex-ssh-test && docker rm probex-ssh-test"
echo "=============================================="
