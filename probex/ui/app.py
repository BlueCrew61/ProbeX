"""Dashboard web ProbeX (Flask) — Vulnerability Scanner + CachePoisonX GUI.

Satu file untuk menjalankan semuanya:
  - Vulnerability Scanner (OWASP Top 10)
  - Cache Poisoning Detector (read-only)
  - Cache Poisoning Injector (attack mode)
  - Monitor Poisoning (webhook events dari lab_cache_origin.py)

Jalankan:
    python3 probex/ui/app.py

Lalu buka http://127.0.0.1:5000 di browser.
"""

from __future__ import annotations

import os
import sys
import threading
import uuid
from typing import Dict

# Pastikan root repository (dua level di atas probex/ui/) ada di sys.path
_HERE = os.path.dirname(os.path.abspath(__file__))
_UI_DIR = os.path.dirname(_HERE)          # probex/ui -> probex
_ROOT = os.path.dirname(_UI_DIR)          # probex -> root repository
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    jsonify,
    send_file,
    flash,
)
from rich.console import Console

from probex.core.config import Config
from probex.core.request_manager import RequestManager
from probex.core.reporter import Reporter
from probex.core.scanner import Scanner

# --- CachePoisonX modules (deteksi + injeksi) ---
from probex.modules.cachepoisonx_detector import CachePoisoningDetectorModule
from probex.modules.cachepoisonx_injector import CachePoisoningInjectorModule

# --- Lab server (origin + cache + webhook) ---
LAB_SERVER_PATH = os.path.join(
    os.path.dirname(__file__), "..", "tes_lab", "lab_cache_origin.py"
)

APP = Flask(__name__)

HTML_RESULT = """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hasil Scan — ProbeX</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0c10;color:#c5c6c7;margin:0;padding:24px}
 .card{background:#1f2833;border:1px solid #45a29e;border-radius:12px;padding:20px;max-width:1100px;margin:auto}
 h1{color:#66fcf1;margin:0 0 4px}
 .bar{color:#45a29e;font-size:0.95rem;margin:0 0 16px}
 .chip{display:inline-block;background:#45a29e;color:#0b0c10;padding:2px 8px;border-radius:8px;font-size:0.8rem;margin:2px 4px 2px 0}
 .chip.tinggi{background:#ff6b6b}
 .chip.sedang{background:#feca57;color:#0b0c10}
 .chip.bervariasi{background:#a29bfe}
 table{width:100%;border-collapse:collapse;margin-top:14px;font-size:0.85rem}
 th,td{border:1px solid #45a29e;padding:8px;text-align:left;vertical-align:top}
 th{background:#16213e;color:#66fcf1}
 tr:nth-child(even)td{background:#17202a}
 .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:0.75rem;color:#a4b0be}
 .act{margin-top:14px}
 .act a{color:#66fcf1;text-decoration:none;margin-right:16px}
 .act a:hover{text-decoration:underline}
 .back{margin-top:16px;display:inline-block;color:#45a29e;text-decoration:none}
 .back:hover{text-decoration:underline}
 .status-running{color:#feca57} .status-done{color:#45a29e} .status-error{color:#ff6b6b}
 .empty{color:#888;font-style:italic}
</style>
</head>
<body>
<div class="card">
  <h1>Hasil Pemindaian {{ job_id }}</h1>
  <p class="bar">Status: <span class="status-{{ status }}">{{ status }}</span>
     &nbsp;|&nbsp; Temuan: <strong>{{ findings|length }}</strong>
     &nbsp;|&nbsp; Request terpakai: <strong>{{ requests_used }}</strong>
  </p>
  {% if error %}
    <div style="color:#ff6b6b;margin:10px 0">{{ error }}</div>
  {% endif %}
  <div class="act">
    <a href="{{ url_for('export_json', job_id=job_id) }}">Ekspor JSON</a>
    <a href="{{ url_for('export_md', job_id=job_id) }}">Ekspor Markdown</a>
    <a class="back" href="{{ url_for('index') }}">Scan target lain</a>
  </div>
  <form method="get" action="{{ url_for('result', job_id=job_id) }}" style="margin-top:10px">
    <label>Filter jenis: <select name="t"><option value="">semua</option>
      {% for t in types %}<option value="{{ t }}">{{ t }}</option>{% endfor %}</select></label>
    <label>Tingkat: <select name="s"><option value="">semua</option>
      <option value="Tinggi">Tinggi</option><option value="Sedang">Sedang</option><option value="Bervariasi">Bervariasi</option></select></label>
    <button type="submit">Terapkan</button>
    <a href="{{ url_for('result', job_id=job_id) }}">Bersihkan</a>
  </form>
  {% if findings %}
  <table>
    <thead><tr><th>ID</th><th>Jenis</th><th>Tingkat</th><th>Judul</th><th>Lokasi</th><th>Bukti</th><th>Rekomendasi</th></tr></thead>
    <tbody>
    {% for f in findings %}
    <tr>
      <td class="mono">{{ f.id }}</td>
      <td><span class="chip {{ f.type }}">{{ f.type }}</span></td>
      <td><span class="chip {{ 'tinggi' if f.severity=='Tinggi' else ('sedang' if f.severity=='Sedang' else 'bervariasi') }}">{{ f.severity }}</span> <span class="chip" style="background:#393e46">{{ f.confidence }}</span></td>
      <td>{{ f.title|e }}</td>
      <td class="mono">{{ f.location.url }} [{{ f.location.method }}] param={{ f.location.parameter }} ({{ f.location.parameter_in }}) {% if f.location.file %}berkas={{ f.location.file }}:{{ f.location.line }}{% endif %}</td>
      <td class="mono">{{ f.evidence|e }}</td>
      <td>{{ f.recommendation|e }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
    <p class="empty">Belum ada temuan atau pemindaian masih berjalan.</p>
  {% endif %}
</div>
<script>
(function poll(){
  if (document.body.dataset.status === "running") {
    fetch("{{ url_for('status', job_id=job_id) }}").then(r=>r.json()).then(d=>{
      if (d.status === "done") location.reload();
    });
    setTimeout(poll, 2000);
  }
})();
</script>
</body>
</html>"""


APP.secret_key = "probex-dev-key-ubah-di-produksi"

JOBS: Dict[str, dict] = {}
LAB_PROCESS = None  # subprocess lab_cache_origin.py

VULN_MODULES = [
    "Vuln Scan: IDOR / Broken Access Control",
    "Vuln Scan: Injection (SQL / Command / Template)",
    "Vuln Scan: SSRF",
    "Vuln Scan: Authentication / Session",
    "Vuln Scan: XSS",
    "Vuln Scan: Security Misconfiguration",
    "Vuln Scan: Sensitive Data Exposure",
    "Vuln Scan: Business Logic",
]

HTML_FORM = """<!doctype html>
<html lang=\"id\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>ProbeX — Security Platform</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0c10;color:#c5c6c7;margin:0;padding:24px}
 .card{background:#1f2833;border:1px solid #45a29e;border-radius:12px;padding:28px;max-width:820px;margin:auto}
 h1{color:#66fcf1;margin:0 0 8px}
 h2{color:#66fcf1;margin:24px 0 8px;font-size:1.1rem}
 .row{display:flex;gap:12px;margin:10px 0;flex-wrap:wrap}
 input,select{background:#0b0c10;border:1px solid #45a29e;color:#c5c6c7;padding:8px;border-radius:6px;width:100%}
 label{font-size:0.9rem;color:#45a29e}
 button{background:#45a29e;color:#0b0c10;border:none;padding:12px 24px;border-radius:6px;font-weight:bold;cursor:pointer}
 button:hover{background:#66fcf1}
 .consent{color:#ff6b6b;font-size:0.85rem}
 .muted{color:#888;font-size:0.85rem}
 .tab{display:none}
 .tab.active{display:block}
 .tabs button{border:none;background:#16213e;color:#c5c6c7;padding:10px 20px;margin-right:6px;border-bottom:2px solid transparent;cursor:pointer}
 .tabs button.active{background:#45a29e;color:#0b0c10;border-bottom-color:#45a29e}
 .btn-small{padding:6px 12px;font-size:0.85rem}
 .warn{color:#ff6b6b;font-size:0.85rem;margin-top:8px}
 .ok{color:#45a29e;font-size:0.85rem;margin-top:8px}
</style>
</head>
<body>
<div class=\"card\">
  <h1>ProbeX — Security Platform</h1>
  <p class=\"muted\">GUI berbasis browser untuk Vulnerability Scanner dan Cache Poisoning. Semua berjalan di localhost, tidak perlu CLI.</p>

  <div class=\"tabs\">
    <button onclick=\"showTab('scan')\" class=\"active\" id=\"tab-scan\">Vulnerability Scanner</button>
    <button onclick=\"showTab('poison')\" id=\"tab-poison\">Cache Poisoning</button>
    <button onclick=\"showTab('monitor')\" id=\"tab-monitor\">Monitor Poisoning</button>
  </div>

  <!-- Tab: Vulnerability Scanner -->
  <div id=\"scan\" class=\"tab active\">
    <form method=\"post\" action=\"{{ url_for('scan') }}\">
      <div class=\"row\">
        <div style=\"flex:1\">
          <label>Target URL</label>
          <input name=\"target\" value=\"http://127.0.0.1:8080/\" placeholder=\"http://127.0.0.1:8080/\" required>
        </div>
        <div style=\"flex:1\">
          <label>Callback SSRF (opsional, URL milik Anda)</label>
          <input name=\"ssrf_callback\" placeholder=\"https://callback-contoh.com/cb\">
        </div>
      </div>
      <div class=\"row\">
        <label style=\"display:flex;align-items:flex-start;gap:8px\">
          <input type=\"checkbox\" name=\"consent\" value=\"ya\" required>
          <span>Saya memiliki izin untuk menguji target ini (wajib dicentang).</span>
        </label>
      </div>
      <div style=\"margin-top:14px\" class=\"consent\">
        <strong>Peringatan etis:</strong> hanya gunakan pada target yang Anda miliki atau yang telah memberi izin tertulis.
      </div>
      <div style=\"margin-top:16px\">
        <button type=\"submit\">Mulai pemindaian</button>
      </div>
    </form>
    <p class=\"muted\" style=\"margin-top:18px\">CLI: <code>python3 probex.py &lt;target&gt; --vuln-scan</code></p>
  </div>

  <!-- Tab: Cache Poisoning -->
  <div id=\"poison\" class=\"tab\">
    <h2>Cache Poisoning (Deteksi &amp; Injeksi)</h2>
    <div style=\"margin-bottom:16px\">
      <label>Target (contoh: http://127.0.0.1:8899/article/demo)</label><br>
      <input id=\"poison-target\" style=\"width:100%\" value=\"http://127.0.0.1:8899/article/demo\" placeholder=\"http://127.0.0.1:8899/article/demo\">
    </div>
    <div style=\"margin-bottom:16px\">
      <label>Header vektor (boleh lebih dari satu, pisahkan koma)</label><br>
      <input id=\"poison-headers\" style=\"width:100%\" value=\"X-Forwarded-Host\" placeholder=\"X-Forwarded-Host\">
    </div>
    <div style=\"margin-bottom:16px\">
      <label>Payload (profil atau literal, satu baris)</label><br>
      <input id=\"poison-payload\" style=\"width:100%\" value=\"host\" placeholder=\"host | webhook | script | redirect | path | literal\">
      <span class=\"muted\" style=\"margin-left:8px\">Contoh: host, 127.0.0.1:8899/_hook/proof</span>
    </div>
    <div style=\"margin-bottom:16px\">
      <button type=\"button\" class=\"btn-small\" onclick=\"runAction('detect')\">Deteksi (read-only)</button>
      <button type=\"button\" class=\"btn-small\" onclick=\"runAction('inject')\">Injeksi (attack mode)</button>
      <button type=\"button\" class=\"btn-small\" onclick=\"runAction('clear')\">Clear cache lab</button>
      <span id=\"poison-msg\" class=\"muted\" style=\"margin-left:12px\"></span>
    </div>
    <div id=\"poison-log\" style=\"margin-top:12px;background:#0b0c10;border:1px solid #45a29e;border-radius:6px;padding:10px;font-family:ui-monospace,monospace;font-size:0.8rem;max-height:300px;overflow-y:auto\"></div>
  </div>

  <!-- Tab: Monitor Poisoning -->
  <div id=\"monitor\" class=\"tab\">
    <h2>Monitor Poisoning (Webhook Events)</h2>
    <div style=\"margin-bottom:12px\">
      <button type=\"button\" class=\"btn-small\" onclick=\"refreshEvents()\">Refresh</button>
      <button type=\"button\" class=\"btn-small\" onclick=\"clearEvents()\">Clear events</button>
      <span class=\"muted\" style=\"margin-left:12px\">Event datang dari lab_cache_origin.py (port 8899)</span>
    </div>
    <div id=\"events-list\" style=\"background:#0b0c10;border:1px solid #45a29e;border-radius:6px;padding:10px;font-family:ui-monospace,monospace;font-size:0.8rem;max-height:400px;overflow-y:auto\">
      <div class=\"muted\">Belum ada event. Nyalakan lab dan lakukan injeksi cache poisoning, lalu refresh.</div>
    </div>
  </div>

  <p class=\"muted\" style=\"margin-top:24px\">CLI alternatif: <code>python3 probex.py &lt;target&gt; --cache-inject --no-safe</code></p>
</div>

<script>
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
  document.getElementById(name).classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

async function apiPost(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body || {})
  });
  return resp.json();
}

async function runAction(action) {
  const target = document.getElementById('poison-target').value.trim();
  const headers = document.getElementById('poison-headers').value.trim().split(',').map(h => h.trim()).filter(Boolean);
  const payload = document.getElementById('poison-payload').value.trim();
  const log = document.getElementById('poison-log');
  const msg = document.getElementById('poison-msg');

  log.innerHTML = '<div class=\"muted\">Memproses...</div>';
  msg.textContent = '';

  try {
    let data;
    if (action === 'detect') {
      data = await apiPost('/api/detect', { target: target });
    } else if (action === 'inject') {
      data = await apiPost('/api/inject', { target: target, headers: headers, payloads: [payload] });
    } else if (action === 'clear') {
      data = await apiPost('/api/cache/clear', {});
    }
    if (data.ok) {
      log.innerHTML = '<div class=\"ok\">Sukses: ' + JSON.stringify(data, null, 2) + '</div>';
      msg.textContent = '';
    } else {
      log.innerHTML = '<div class=\"warn\">Gagal: ' + (data.error || 'tidak diketahui') + '</div>';
      msg.textContent = '';
    }
  } catch (err) {
    log.innerHTML = '<div class=\"warn\">Error: ' + err.message + '</div>';
  }
}

async function refreshEvents() {
  try {
    const data = await fetch('/api/events').then(r => r.json());
    const list = document.getElementById('events-list');
    const hits = data.hits || [];
    if (hits.length === 0) {
      list.innerHTML = '<div class=\"muted\">Belum ada event webhook.</div>';
      return;
    }
    list.innerHTML = hits.slice().reverse().map(h =>
      '<div style=\"border-bottom:1px solid #16213e;padding:6px 0\">' +
      '<span class=\"muted\">' + (h.time || '').replace(\"T\", \" \").slice(0,19) + '</span> ' +
      '<span style=\"color:#66fcf1\">token=' + (h.token || '-') + '</span> ' +
      '<span>client=' + (h.client || '-') + '</span> ' +
      '<span>UA=' + ((h.user_agent || '-').slice(0,40)) + '</span>' +
      '</div>'
    ).join('');
  } catch (err) {
    document.getElementById('events-list').innerHTML = '<div class=\"warn\">Gagal ambil events: ' + err.message + '</div>';
  }
}

async function clearEvents() {
  try {
    await fetch('/api/events/clear', { method: 'POST' });
    document.getElementById('events-list').innerHTML = '<div class=\"muted\">Events sudah dikosongkan.</div>';
  } catch (err) {
    // ignore
  }
}
</script>
</body>
</html>"""

def _run_scan(job_id: str, target: str, ssrf_callback: str, consent: bool) -> None:
    """Jalankan Scanner di latar belakang dan simpan hasil ke JOBS."""
    job = JOBS[job_id]
    job["status"] = "running"
    try:
        if not consent:
            job["status"] = "error"
            job["error"] = "Scan dibatalkan: izin uji target belum diberikan."
            return
        config = Config(
            base_url_override=target,
            safe_mode=True,
            low_impact=True,
            max_requests=60,
            delay=1.5,
            threads=1,
            timeout=10,
            ssrf_callback=ssrf_callback or None,
            no_banner=True,
        )
        console = Console()
        rm = RequestManager(config)
        reporter = Reporter(console)
        scanner = Scanner(config, console, rm, reporter)
        scanner.run(module_names=VULN_MODULES)
        stats = rm.get_stats()
        status = "COMPLETED"
        job["status"] = "done"
        job["findings"] = reporter.findings
        job["endpoints"] = reporter.endpoints
        job["requests_used"] = stats.get("total_requests", 0)
        job["json_path"] = reporter.save_report(
            target, stats.get("total_requests", 0), status
        )
        job["md_path"] = reporter.save_markdown_report(
            target, stats.get("total_requests", 0), status
        )
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = str(exc)


def _run_detector(target_url: str) -> list:
    """Run cache poisoning detection (read-only), return findings."""
    config = Config(
        base_url_override=target_url,
        safe_mode=True,
        low_impact=True,
        max_requests=30,
        delay=0.0,
        threads=1,
        timeout=10,
        no_banner=True,
    )
    rm = RequestManager(config)
    reporter = Reporter(Console())
    module = CachePoisoningDetectorModule(config, rm, reporter, Console())
    module.run()
    return reporter.findings


def _run_injector(target_url: str, headers: list, payloads: list) -> list:
    """Run cache poisoning injection (attack mode), return findings."""
    config = Config(
        base_url_override=target_url,
        safe_mode=False,
        low_impact=True,
        max_requests=30,
        delay=0.0,
        threads=1,
        timeout=10,
        no_banner=True,
    )
    config._exploit_allowed = True
    config.cache_inject_header = headers or ["X-Forwarded-Host"]
    config.cache_inject_payload = payloads or ["host"]

    rm = RequestManager(config)
    reporter = Reporter(Console())
    module = CachePoisoningInjectorModule(config, rm, reporter, Console())
    module.run()
    return reporter.findings


@APP.get("/")
def index():
    return render_template_string(HTML_FORM)

@APP.get("/gui")
def gui():
    return render_template_string(HTML_FORM)

@APP.post("/scan")
def scan():
    target = (request.form.get("target") or "").strip()
    ssrf_callback = (request.form.get("ssrf_callback") or "").strip()
    consent = request.form.get("consent") == "ya"
    if not target.startswith(("http://", "https://")):
        flash("Target harus URL dengan skema http:// atau https://")
        return redirect(url_for("index"))
    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {"status": "queued", "findings": [], "target": target}
    threading.Thread(
        target=_run_scan, args=(job_id, target, ssrf_callback, consent), daemon=True
    ).start()
    return redirect(url_for("result", job_id=job_id))

@APP.get("/result/<job_id>")
def result(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return "Job tidak ditemukan", 404
    findings = job.get("findings", [])
    t = request.args.get("t", "").strip()
    s = request.args.get("s", "").strip()
    if t:
        findings = [f for f in findings if f.get("type") == t]
    if s:
        findings = [f for f in findings if f.get("severity") == s]
    types = sorted({f.get("type", "") for f in job.get("findings", [])})
    return render_template_string(
        HTML_RESULT,
        job_id=job_id,
        status=job.get("status", "queued"),
        error=job.get("error"),
        findings=findings,
        types=types,
        requests_used=job.get("requests_used", 0),
    )

@APP.get("/api/status/<job_id>")
def status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "tidak ditemukan"}), 404
    return jsonify({"status": job.get("status"), "error": job.get("error")})

@APP.get("/export/<job_id>/json")
def export_json(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("json_path"):
        return "Laporan JSON tidak tersedia", 404
    return send_file(job["json_path"], as_attachment=True)

@APP.get("/export/<job_id>/md")
def export_md(job_id: str):
    job = JOBS.get(job_id)
    if not job or not job.get("md_path"):
        return "Laporan Markdown tidak tersedia", 404
    return send_file(job["md_path"], as_attachment=True)

# ---------- CachePoisonX API ----------

@APP.post("/api/detect")
def api_detect():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target")
    if not target:
        return jsonify({"ok": False, "error": "target required"}), 400
    try:
        findings = _run_detector(target)
        return jsonify({"ok": True, "mode": "detect", "findings": findings, "count": len(findings)})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 500

@APP.post("/api/inject")
def api_inject():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target")
    if not target:
        return jsonify({"ok": False, "error": "target required"}), 400
    try:
        headers = payload.get("headers") or ["X-Forwarded-Host"]
        payloads = payload.get("payloads") or ["host"]
        findings = _run_injector(target, headers, payloads)
        injected = [f for f in findings if f.get("severity") == "high"]
        return jsonify({"ok": True, "mode": "inject", "findings": findings, "injected": len(injected), "count": len(findings)})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 500

@APP.post("/api/cache/clear")
def api_cache_clear():
    import requests as _requests
    try:
        resp = _requests.get("http://127.0.0.1:8899/_cache/clear", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 502

@APP.get("/api/events")
def api_events():
    import requests as _requests
    try:
        resp = _requests.get("http://127.0.0.1:8899/_events", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e), "hits": [], "count": 0}), 502

@APP.post("/api/events/clear")
def api_events_clear():
    import requests as _requests
    try:
        resp = _requests.get("http://127.0.0.1:8899/_events/clear", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 502

# ---------- Lab server management ----------

def _start_lab_server():
    """Nyalakan lab_cache_origin.py di background jika belum ada."""
    global LAB_PROCESS
    if LAB_PROCESS is not None and LAB_PROCESS.poll() is None:
        return
    import subprocess
    LAB_PROCESS = subprocess.Popen(
        [sys.executable, LAB_SERVER_PATH, "8899"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

@APP.get("/api/lab/start")
def api_lab_start():
    _start_lab_server()
    return jsonify({"ok": True, "message": "Lab server dimulai di port 8899"})

@APP.get("/api/lab/stop")
def api_lab_stop():
    global LAB_PROCESS
    if LAB_PROCESS is not None:
        LAB_PROCESS.terminate()
        LAB_PROCESS = None
    return jsonify({"ok": True, "message": "Lab server dihentikan"})

def main():
    # Nyalakan lab server otomatis saat Flask dijalankan
    _start_lab_server()
    APP.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    main()
