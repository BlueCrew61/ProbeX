"""Dashboard web ProbeX (Flask) — Vulnerability Scanner.

Halaman: form target, hasil scan (tabel temuan + filter), progres, ekspor
JSON/Markdown. Semua teks berbahasa Indonesia.
"""

from __future__ import annotations

import threading
import uuid
from typing import Dict

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

APP = Flask(__name__)
APP.secret_key = "probex-dev-key-ubah-di-produksi"

JOBS: Dict[str, dict] = {}

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
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProbeX — Vulnerability Scanner</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0c10;color:#c5c6c7;margin:0;padding:24px}
 .card{background:#1f2833;border:1px solid #45a29e;border-radius:12px;padding:28px;max-width:720px;margin:auto}
 h1{color:#66fcf1;margin:0 0 8px}
 .row{display:flex;gap:12px;margin:10px 0;flex-wrap:wrap}
 input,select{background:#0b0c10;border:1px solid #45a29e;color:#c5c6c7;padding:8px;border-radius:6px;width:100%}
 label{font-size:0.9rem;color:#45a29e}
 button{background:#45a29e;color:#0b0c10;border:none;padding:12px 24px;border-radius:6px;font-weight:bold;cursor:pointer}
 button:hover{background:#66fcf1}
 .consent{color:#ff6b6b;font-size:0.85rem}
 .muted{color:#888;font-size:0.85rem}
</style>
</head>
<body>
<div class="card">
  <h1>ProbeX — Vulnerability Scanner</h1>
  <p class="muted">Dashboard deteksi kerentanan web untuk developer pemula (OWASP Top 10).</p>
  <form method="post" action="{{ url_for('scan') }}">
    <div class="row">
      <div style="flex:1">
        <label>Target URL</label>
        <input name="target" value="http://127.0.0.1:8080/" placeholder="http://127.0.0.1:8080/" required>
      </div>
      <div style="flex:1">
        <label>Callback SSRF (opsional, URL milik Anda)</label>
        <input name="ssrf_callback" placeholder="https://callback-contoh.com/cb">
      </div>
    </div>
    <div class="row">
      <label style="display:flex;align-items:flex-start;gap:8px">
        <input type="checkbox" name="consent" value="ya" required>
        <span>Saya memiliki izin untuk menguji target ini (wajib dicentang).</span>
      </label>
    </div>
    <div style="margin-top:14px" class="consent">
      <strong>Peringatan etis:</strong> hanya gunakan pada target yang Anda miliki atau yang telah memberi izin tertulis.
      Scan tidak merusak dan hanya mengirim payload uji aman.
    </div>
    <div style="margin-top:16px">
      <button type="submit">Mulai pemindaian</button>
    </div>
  </form>
  <p class="muted" style="margin-top:18px">CLI: <code>python3 probex.py &lt;target&gt; --vuln-scan [--ssrf-callback URL]</code></p>
</div>
</body>
</html>"""

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


@APP.get("/")
def index():
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


def main() -> None:
    APP.run(host="127.0.0.1", port=5000, debug=True)


if __name__ == "__main__":
    main()
