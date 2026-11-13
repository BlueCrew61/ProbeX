#!/usr/bin/env python3
"""Lab simulasi origin + cache + webhook untuk CachePoisonX (mode attack).

Meniru tiga komponen yang ada di setup nyata:

  1. CACHE  — cache key = path + query (setara nginx $scheme$host$request_uri),
              header apa pun TIDAK ikut key => unkeyed input.
  2. ORIGIN — halaman artikel yang menaruh nilai X-Forwarded-Host ke dalam
              <link rel=canonical>, <meta og:url>, dan <img src>. Ketiganya
              dibaca browser, jadi payload di situ akan benar-benar dipanggil
              browser korban (bukan cuma teks).
  3. WEBHOOK — endpoint /_hook/<token>. Setiap korban yang memuat halaman
              teracuni akan menembak endpoint ini, meninggalkan jejak
              token + IP + waktu. Inilah bukti "inject banyak".

Endpoint:
  GET /article/<slug>     halaman artikel (di-cache)
  GET /_hook/<token>      1x1 png + catat hit ke log
  GET /_monitor           dashboard live (auto-refresh 1,5 detik)
  GET /_events            JSON semua hit webhook
  GET /_events/clear      kosongkan log webhook
  GET /_cache/clear       kosongkan cache (reset demo)
  GET /                    200 index

Jalankan: python3 lab_cache_origin.py 8899
"""

import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CACHE = {}       # request_uri -> (body, content_type)
HOOKS = []       # daftar hit webhook
LOCK = threading.Lock()
TTL_SECONDS = 180

PNG_1PX = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def render_article(host_value: str) -> bytes:
    """Halaman yang memuat host_value di tiga konteks yang dibaca browser."""
    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Portal Berita — Artikel</title>
<link rel="canonical" href="http://{host_value}/">
<meta property="og:url" content="http://{host_value}/">
<meta property="og:image" content="http://{host_value}/assets/cover.jpg">
</head>
<body>
<h1>Artikel</h1>
<p>Host tercatat: {host_value}</p>
<img src="http://{host_value}/assets/pixel.gif" alt="statistik">
<p>Sumber: <a href="http://{host_value}/sumber">tautan</a></p>
</body>
</html>""".encode("utf-8")


MONITOR_HTML = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Webhook Monitor — live</title>
<style>
:root{--bg:#0b1020;--fg:#e8eefc;--muted:#8b9bb8;--card:#141b2e;--line:#25314d;
--accent:#4f8cff;--ok:#2ecc71;--hot:#ff5c5c}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.big{font-size:56px;font-weight:800;color:var(--accent);line-height:1}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;
background:var(--ok);margin-right:7px;animation:p 1.4s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.25}}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:16px}
th,td{border-bottom:1px solid var(--line);padding:9px 8px;text-align:left;
vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
tr.new{animation:flash 1.6s ease-out}
@keyframes flash{from{background:rgba(79,140,255,.28)}to{background:transparent}}
code{color:#9ff0b0;font-size:12px;word-break:break-all}
.empty{color:var(--muted);padding:28px;text-align:center;border:1px dashed var(--line);
border-radius:10px;margin-top:16px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;
border-radius:999px;background:rgba(46,204,113,.16);color:var(--ok);
border:1px solid var(--ok)}
.bar{margin-top:14px;color:var(--muted);font-size:12px}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px;margin-right:8px}
button:hover{border-color:var(--accent)}
</style>
</head>
<body>
<div class="wrap">
  <h1><span class="dot"></span>Webhook Monitor</h1>
  <div class="sub">Request yang masuk ke endpoint penyerang &mdash; bukti payload
  dieksekusi browser korban. Halaman ini refresh otomatis tiap 1,5 detik.</div>

  <div class="big" id="count">0</div>
  <div class="sub" style="margin-top:6px">request masuk</div>

  <div style="margin-top:14px">
    <button onclick="fetch('/_events/clear',{method:'GET'}).then(()=>location.reload())">
      Kosongkan log</button>
    <button onclick="location.reload()">Refresh</button>
    <button id="toggle" onclick="toggleAuto()">Auto-refresh: ON</button>
    <span class="pill" id="live">LIVE</span>
  </div>

  <div id="table"></div>
  <div class="bar" id="bar">menunggu...</div>
</div>

<script>
let known = new Set();
async function tick() {
  try {
    const r = await fetch('/_events', {cache:'no-store'});
    const d = await r.json();
    document.getElementById('count').textContent = d.count;
    const hits = d.hits || [];
    const t = document.getElementById('table');
    if (!hits.length) {
      t.innerHTML = '<div class="empty">Belum ada request masuk.<br>' +
        'Tanam payload ke cache, lalu buka halaman target di browser.</div>';
      document.getElementById('bar').textContent = 'menunggu...';
      return;
    }
    let rows = '';
    hits.slice().reverse().forEach((h, i) => {
      const key = h.time + '|' + h.token + '|' + (h.query||'');
      const isNew = !known.has(key);
      known.add(key);
      const ua = (h.user_agent||'-');
      rows += '<tr class="' + (isNew && i===0 ? 'new' : '') + '">' +
        '<td>' + (hits.length - i) + '</td>' +
        '<td><code>' + esc(h.token) + '</code></td>' +
        '<td>' + esc(h.client||'-') + '</td>' +
        '<td title="' + esc(ua) + '">' + esc(ua.slice(0,42)) + '</td>' +
        '<td><code>' + esc((h.referer||'-').slice(0,40)) + '</code></td>' +
        '<td>' + esc((h.time||'').replace('T',' ').slice(0,19)) + '</td></tr>';
    });
    t.innerHTML = '<table><thead><tr><th>#</th><th>Token / path</th>' +
      '<th>Klien</th><th>User-Agent</th><th>Referer</th><th>Waktu (UTC)</th>' +
      '</tr></thead><tbody>' + rows + '</tbody></table>';
    document.getElementById('bar').textContent =
      'terakhir dicek ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('bar').textContent = 'gagal konek: ' + e;
  }
}
function esc(s){return String(s).replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
let auto = true, timer = null;
function toggleAuto() {
  auto = !auto;
  document.getElementById('toggle').textContent =
    'Auto-refresh: ' + (auto ? 'ON' : 'OFF');
  document.getElementById('live').style.opacity = auto ? '1' : '.35';
  if (auto) { tick(); timer = setInterval(tick, 1500); }
  else if (timer) { clearInterval(timer); timer = null; }
}
tick();
timer = setInterval(tick, 1500);
</script>
</body>
</html>"""


def render_monitor(hits: list) -> bytes:
    """Render dashboard live. Data diambil via /_events oleh JS, jadi HTML
    ini statis — cukup mengembalikan template."""
    return MONITOR_HTML.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, ctype: str, status: int = 200,
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        """HEAD = intip status cache tanpa mengisi cache.

        Ini penting untuk demo `curl -I`. Kalau HEAD ikut menyimpan response,
        maka `curl -I` pertama akan mengisi cache dengan salinan bersih dan
        injeksi berikutnya selalu kena HIT salinan bersih itu — payload tidak
        pernah masuk. Jadi HEAD hanya MEMBACA cache, tidak menulis.
        """
        parsed = urlparse(self.path)
        path = parsed.path

        if not path.startswith("/article/"):
            self._send(b"", "text/plain", 404)
            return

        key = self.path
        with LOCK:
            cached = CACHE.get(key)
            hit = cached is not None
            if hit:
                body, ctype = cached
            else:
                # Miss: hitung body yang AKAN dihasilkan, tapi jangan simpan.
                shown = (
                    self.headers.get("X-Forwarded-Host")
                    or self.headers.get("X-Host")
                    or self.headers.get("X-HTTP-Host-Override")
                    or "origin.local"
                )
                body = render_article(shown)
                ctype = "text/html; charset=utf-8"

        print(f"[HEAD {'HIT' if hit else 'MISS'}] {key} "
              f"xfh={self.headers.get('X-Forwarded-Host')}", flush=True)

        self._send(body, ctype, extra={
            "X-Cache": "HIT" if hit else "MISS",
            "X-Cache-Hits": "1" if hit else "0",
            "Cache-Control": f"public, max-age={TTL_SECONDS}",
            "Age": "12" if hit else "0",
        })

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---------- webhook receiver ----------
        if path.startswith("/_hook/"):
            token = path[len("/_hook/"):]
            with LOCK:
                HOOKS.append({
                    "token": token,
                    "query": parsed.query,
                    "client": self.client_address[0],
                    "user_agent": self.headers.get("User-Agent", ""),
                    "referer": self.headers.get("Referer", ""),
                    "time": datetime.now(timezone.utc).isoformat(),
                })
                n = len(HOOKS)
            print(f"[WEBHOOK] token={token} dari {self.client_address[0]} "
                  f"(total {n})", flush=True)
            self._send(PNG_1PX, "image/png")
            return

        if path == "/_events":
            with LOCK:
                body = json.dumps({"count": len(HOOKS), "hits": HOOKS},
                                  indent=2).encode()
            self._send(body, "application/json")
            return

        # ---------- dashboard live (auto-refresh) ----------
        if path == "/_monitor":
            with LOCK:
                snapshot = list(HOOKS)
            self._send(render_monitor(snapshot), "text/html; charset=utf-8")
            return

        if path == "/_events/clear":
            with LOCK:
                HOOKS.clear()
            print("[WEBHOOK] log dikosongkan", flush=True)
            self._send(b'{"cleared":true}', "application/json")
            return

        if path == "/_cache/clear":
            with LOCK:
                CACHE.clear()
            print("[CACHE] cache dikosongkan", flush=True)
            self._send(b'{"cleared":true}', "application/json")
            return

        if path == "/":
            self._send(b"<html><body><h1>lab origin</h1>"
                       b"<p>pakai /article/&lt;slug&gt;</p></body></html>",
                       "text/html; charset=utf-8")
            return

        if not path.startswith("/article/"):
            self._send(b"not found", "text/plain", 404)
            return

        # ---------- cache lookup: path + query, TANPA header ----------
        key = self.path
        hop = self.headers

        with LOCK:
            if key in CACHE:
                body, ctype = CACHE[key]
                hit = True
            else:
                # Origin membaca header yang tidak masuk cache key.
                shown = (
                    hop.get("X-Forwarded-Host")
                    or hop.get("X-Host")
                    or hop.get("X-HTTP-Host-Override")
                    or "origin.local"
                )
                body = render_article(shown)
                ctype = "text/html; charset=utf-8"
                CACHE[key] = (body, ctype)
                hit = False

        print(f"[{'HIT' if hit else 'MISS '}] {key} xfh={hop.get('X-Forwarded-Host')}",
              flush=True)

        self._send(body, ctype, extra={
            "X-Cache": "HIT" if hit else "MISS",
            "X-Cache-Hits": "1" if hit else "0",
            "Cache-Control": f"public, max-age={TTL_SECONDS}",
            "Age": "12" if hit else "0",
        })


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    print(f"listening on http://127.0.0.1:{port}", flush=True)
    print(f"  webhook : /_hook/<token>   (log: /_events)", flush=True)
    print(f"  reset   : /_cache/clear dan /_events/clear", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()