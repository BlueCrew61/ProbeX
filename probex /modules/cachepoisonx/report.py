"""modules.report — Tahap 5: Report Generator.

Versi 2. Perbaikan dibanding v1:

1. Import `re` diperbaiki. v1 memakai re.sub di _safe_filename tanpa mengimpor
   `re`, sehingga generate_html_report() CRASH dengan NameError tepat ketika ada
   temuan. Target bersih -> laporan jadi, target rentan -> tool mati.
2. TANPA CDN. v1 menarik Tailwind + Google Fonts dari internet. Lingkungan
   lomba terisolasi, jadi CSS-nya harus inline total.
3. HTML escaping. Marker/URL berasal dari response target; menempelkannya mentah
   ke laporan bisa merusak markup (atau jadi stored-XSS di laporan sendiri).
4. Bukti mentah + curl repro. Tiap temuan membawa potongan response di sekitar
   marker dan satu baris curl yang bisa dicopas juri untuk membuktikan sendiri.
5. Cache key matrix ikut masuk laporan sebagai tabel.
"""

import json
import os
import re
import html
from datetime import datetime, timezone
from typing import List, Dict, Any
import logging

log = logging.getLogger("CachePoisonX.report")

VERSION = "2.0.0"


def _safe_filename(name: str) -> str:
    """Membersihkan string menjadi nama file yang aman."""
    safe = re.sub(r"[^\w\-_.]", "_", name)
    return safe.strip("_") or "unnamed"


def _esc(value: Any) -> str:
    """Escape teks dari response target sebelum masuk HTML."""
    return html.escape(str(value), quote=True)


def _curl_for(finding: Dict[str, Any]) -> str:
    """Bangun baris curl yang mereproduksi injeksi."""
    header = finding.get("vulnerable_header") or finding.get("header", "")
    payload = finding.get("payload") or finding.get("marker", "")
    url = finding.get("target", "")
    if not (header and payload and url):
        return ""
    return f"curl -sv -H '{header}: {payload}' '{url}'"


def _timeline_table(timeline: List[Dict[str, Any]]) -> str:
    """Tabel jejak header cache per langkah injeksi."""
    if not timeline:
        return "<p class=\"muted\">Timeline tidak terekam.</p>"
    rows = []
    for s in timeline:
        state = (s.get("cache_state") or "unknown").upper()
        cls = "ok" if state == "HIT" else ("warn" if state == "MISS" else "muted")
        hdr = s.get("cache") or {}
        hdr_txt = ", ".join(f"{k}: {v}" for k, v in hdr.items())
        present = "ya" if s.get("payload_present") else "tidak"
        rows.append(
            f"<tr><td>{s.get('step', '-')}</td>"
            f"<td>{_esc(s.get('action', '-'))}</td>"
            f"<td><span class=\"badge {cls}\">{state}</span></td>"
            f"<td><code>{_esc(hdr_txt)}</code></td>"
            f"<td>{present}</td></tr>"
        )
    return (
        "<table class=\"matrix\"><thead><tr><th>#</th><th>Langkah</th>"
        "<th>Status cache</th><th>Header cache</th><th>Payload tampil?</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _victim_block(v: Dict[str, Any]) -> str:
    """Ringkasan simulasi korban."""
    if not v:
        return ""
    samples = v.get("samples") or []
    rows = "".join(
        f"<tr><td>{s.get('victim', '-')}</td>"
        f"<td><span class=\"badge {'ok' if s.get('cache') == 'hit' else 'warn'}\">"
        f"{(s.get('cache') or 'unknown').upper()}</span></td>"
        f"<td>{'ya' if s.get('payload_present') else 'tidak'}</td>"
        f"<td>{'ya' if s.get('loads_remote') else 'tidak'}</td></tr>"
        for s in samples
    )
    return f"""
  <h4>Simulasi korban — {v.get('poisoned', 0)}/{v.get('attempted', 0)} menerima payload</h4>
  <table class="matrix"><thead><tr><th>Korban</th><th>Cache</th>
  <th>Payload tampil</th><th>Dimuat browser</th></tr></thead>
  <tbody>{rows}</tbody></table>"""


def generate_json_report(
    findings: List[Dict[str, Any]],
    filepath: str,
    meta: Dict[str, Any] | None = None,
) -> str:
    """Tulis laporan JSON terstruktur (dua mode)."""
    meta = meta or {}
    is_attack = meta.get("mode") == "attack"

    if is_attack:
        summary = {
            "attempts": meta.get("attempts", len(findings)),
            "injected": sum(1 for f in findings if f.get("injected")),
            "loads_remote": sum(1 for f in findings if f.get("loads_remote")),
            "victims_simulated": meta.get("victims_simulated", 0),
            "victims_poisoned": sum(
                (f.get("victims") or {}).get("poisoned", 0) for f in findings
            ),
            "hook_hits": (meta.get("hook_report") or {}).get("count", 0),
        }
    else:
        summary = {
            "total_vulnerabilities": len(findings),
            "confirmed": sum(1 for f in findings if f.get("verified")),
            "unkeyed_headers": sum(
                1 for f in findings if f.get("keyed") is False
            ),
            "targets_scanned": len({f.get("target", "") for f in findings}),
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "CachePoisonX",
        "version": VERSION,
        "mode": meta.get("mode", "detect"),
        "target": meta.get("target", ""),
        "summary": summary,
        "cache_key_matrix": meta.get("cache_key_matrix", []),
        "fingerprint": meta.get("fingerprint", {}),
        "results": findings,
    }

    if is_attack:
        report["headers_tested"] = meta.get("headers_tested", [])
        report["payloads_used"] = meta.get("payloads_used", [])
        report["hook_api"] = meta.get("hook_api")
        report["hook_report"] = meta.get("hook_report")

    os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log.info(f"JSON report disimpan ke: {filepath}")
    return filepath


def _finding_card(f: Dict[str, Any], idx: int) -> str:
    """Kartu satu temuan — mendukung mode deteksi maupun mode injeksi."""
    is_attack = "payload" in f
    sev = f.get("severity") or ("High" if f.get("loads_remote") else "Medium")
    sev_cls = "sev-high" if sev == "High" else "sev-med"

    if is_attack:
        verified = f.get("injected")
        verdict = "INJECTED" if verified else str(f.get("verdict", "REVIEW"))
    else:
        verified = f.get("verified")
        verdict = "TERBUKTI" if verified else "PERLU REVIEW"
    verdict_cls = "ok" if verified else "warn"

    if is_attack:
        steps = " &rarr; ".join(
            f"{(s.get('cache_state') or '?').upper()}"
            for s in (f.get("timeline") or [])
        )
        rows = [
            ("Header vektor", f"<code>{_esc(f.get('header', '-'))}</code>"),
            ("Payload ditanam", f"<code>{_esc(f.get('payload', '-'))}</code>"),
            ("Profil", _esc(f.get("profile", "-"))),
            ("Jejak cache", f"<strong>{steps}</strong>"),
            ("TTL", "lihat Cache-Control di timeline"),
            ("Persist di replay", "ya" if f.get("persists") else "tidak"),
            ("Cache HIT saat replay", "ya" if f.get("cache_hit_on_replay") else "tidak"),
            ("Dimuat browser", "ya" if f.get("loads_remote") else "tidak"),
            ("Konteks HTML", ", ".join(f.get("contexts") or []) or "-"),
            ("Alasan verdict", _esc(f.get("reason", "-"))),
        ]
    else:
        rows = [
            ("Vulnerable header", _esc(f.get("vulnerable_header", "-"))),
            ("Cache key", "UNKEYED (tidak masuk cache key)" if f.get("keyed") is False
             else "keyed / tidak disimpulkan"),
            ("TTL estimasi", f"{_esc(f.get('ttl_estimate', '-'))} detik"),
            ("Marker unik", f"<code>{_esc(f.get('marker', ''))}</code>"),
            ("Status cache saat replay", _esc(f.get("replay_cache_status", "-"))),
            ("Alasan verdict", _esc(f.get("reason", "-"))),
        ]

    rows_html = "".join(
        f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows
    )

    title = f.get("header") or f.get("vulnerable_header", "-")
    evidence = f.get("snippet") or f.get("evidence", "")
    evidence_html = (
        f"<pre class=\"evidence\">{_esc(evidence)}</pre>" if evidence else
        "<p class=\"muted\">Tidak ada potongan response tersimpan.</p>"
    )
    curl = _curl_for(f)
    curl_html = f"<pre class=\"evidence\">{_esc(curl)}</pre>" if curl else ""
    timeline_html = _timeline_table(f.get("timeline") or []) if is_attack else ""
    victim_html = _victim_block(f.get("victims") or {}) if is_attack else ""

    return f"""
<section class="card">
  <header class="card-head">
    <h3>#{idx} {_esc(title)} <span class="url">{_esc(f.get('target', ''))}</span></h3>
    <span class="badge {sev_cls}">{_esc(sev)}</span>
    <span class="badge {verdict_cls}">{verdict}</span>
  </header>
  <table class="kv">{rows_html}</table>
  {timeline_html}
  <h4>Potongan response (di sekitar payload)</h4>
  {evidence_html}
  <h4>Reproduksi manual</h4>
  {curl_html}
  {victim_html}
</section>"""


def _matrix_table(matrix: List[Dict[str, Any]]) -> str:
    if not matrix:
        return "<p class=\"muted\">Cache key matrix tidak dijalankan.</p>"
    rows = []
    for m in matrix:
        keyed = m.get("keyed")
        if keyed is False:
            status, cls = "UNKEYED &rarr; rentan", "warn"
        elif keyed is True:
            status, cls = "keyed &rarr; aman", "ok"
        else:
            status, cls = "tidak disimpulkan", "muted"
        rows.append(
            f"<tr><td><code>{_esc(m.get('header', ''))}</code></td>"
            f"<td><span class=\"badge {cls}\">{status}</span></td>"
            f"<td>{_esc(m.get('note', ''))}</td></tr>"
        )
    return (
        "<table class=\"matrix\"><thead><tr><th>Header</th><th>Masuk cache key?</th>"
        "<th>Catatan</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


CSS = """
:root{--bg:#0b1020;--fg:#e8eefc;--muted:#8b9bb8;--card:#141b2e;--line:#25314d;
--accent:#4f8cff;--high:#ff5c5c;--med:#ffb020;--ok:#2ecc71}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
line-height:1.55}
.wrap{max-width:1040px;margin:0 auto}
.hero{background:linear-gradient(135deg,#16203a,#0b1020);border:1px solid var(--line);
border-radius:14px;padding:26px;margin-bottom:22px}
.hero h1{margin:0 0 6px;font-size:26px}
.hero p{margin:0;color:var(--muted);font-size:14px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.stat{flex:1 1 150px;background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:14px;text-align:center}
.stat .n{font-size:28px;font-weight:700;color:var(--accent)}
.stat .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
h2{font-size:19px;margin:26px 0 12px}
h4{margin:16px 0 6px;font-size:13px;color:var(--muted);text-transform:uppercase;
letter-spacing:.05em}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px;margin-bottom:14px}
.card-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;
border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:12px}
.card-head h3{margin:0;font-size:15px;flex:1 1 auto}
.card-head .url{color:var(--muted);font-weight:400;font-size:12px;word-break:break-all}
.badge{font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;
text-transform:uppercase;letter-spacing:.03em}
.sev-high{background:rgba(255,92,92,.16);color:var(--high);border:1px solid var(--high)}
.sev-med{background:rgba(255,176,32,.14);color:var(--med);border:1px solid var(--med)}
.ok{background:rgba(46,204,113,.14);color:var(--ok);border:1px solid var(--ok)}
.warn{background:rgba(255,176,32,.14);color:var(--med);border:1px solid var(--med)}
.muted{color:var(--muted)}
table.kv{width:100%;border-collapse:collapse;font-size:14px}
table.kv th{text-align:left;width:210px;color:var(--muted);font-weight:500;
padding:6px 10px 6px 0;vertical-align:top}
table.kv td{padding:6px 0;word-break:break-all}
table.matrix{width:100%;border-collapse:collapse;font-size:13px}
table.matrix th,table.matrix td{border-bottom:1px solid var(--line);
padding:8px;text-align:left;vertical-align:top}
table.matrix th{color:var(--muted);font-weight:500}
pre.evidence{background:#0a0f1c;border:1px solid var(--line);border-radius:6px;
padding:10px;overflow-x:auto;color:#9ff0b0;font-size:12.5px;white-space:pre-wrap;
word-break:break-all;margin:0}
footer{margin-top:32px;padding-top:16px;border-top:1px solid var(--line);
color:var(--muted);font-size:12px}
"""


def generate_html_report(
    findings: List[Dict[str, Any]],
    filepath: str,
    meta: Dict[str, Any] | None = None,
) -> str:
    """Tulis laporan HTML mandiri (offline, tanpa CDN)."""
    meta = meta or {}
    is_attack = meta.get("mode") == "attack"

    if is_attack:
        total = len(findings)
        confirmed = sum(1 for f in findings if f.get("injected"))
        remote = sum(1 for f in findings if f.get("loads_remote"))
        attempts = meta.get("attempts", total)
        cards = "".join(_finding_card(f, i + 1) for i, f in enumerate(findings))
        if not cards:
            cards = (
                "<p class=\"muted\">Tidak ada injeksi yang berhasil. Periksa "
                "apakah target punya cache layer, apakah cache sudah hangat "
                "(pakai --buster), dan apakah header tersebut masuk cache key.</p>"
            )
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Blok bukti callback webhook
        hook = meta.get("hook_report") or {}
        hook_block = ""
        if hook and not hook.get("error"):
            hits = hook.get("hits") or []
            if hits:
                rows_h = "".join(
                    f"<tr><td><code>{_esc(h.get('token', '-'))}</code></td>"
                    f"<td>{_esc(h.get('query', '-') or '-')}</td>"
                    f"<td>{_esc(h.get('client', '-'))}</td>"
                    f"<td>{_esc(h.get('time', '-'))}</td></tr>"
                    for h in hits
                )
                hook_block = f"""
  <h2>Bukti callback webhook &mdash; {hook.get('count', 0)} request masuk</h2>
  <section class="card">
    <p class="muted">Bukan sekadar "payload ada di HTML". Ini request yang
    benar-benar diterima endpoint penyerang, artinya payload dieksekusi.</p>
    <table class="matrix"><thead><tr><th>Token</th><th>Query</th>
    <th>Klien</th><th>Waktu</th></tr></thead><tbody>{rows_h}</tbody></table>
  </section>"""
            else:
                hook_block = """
  <h2>Callback webhook</h2>
  <section class="card">
    <p class="muted">Belum ada callback tercatat. Payload sudah tertanam di
    cache, tapi belum ada klien yang memuatnya. Buka URL target di browser
    untuk memicu callback, lalu jalankan ulang dengan <code>--hook-api</code>.</p>
  </section>"""
        doc = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CachePoisonX &mdash; Laporan Injeksi Cache</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>CachePoisonX &mdash; Laporan Injeksi Cache</h1>
    <p>Target: <strong>{_esc(meta.get('target', '-'))}</strong> &middot;
       dibuat {generated} &middot; v{VERSION} &middot; mode ATTACK</p>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{attempts}</div><div class="l">Percobaan</div></div>
    <div class="stat"><div class="n">{confirmed}</div><div class="l">Injected</div></div>
    <div class="stat"><div class="n">{remote}</div><div class="l">Dimuat browser</div></div>
    <div class="stat"><div class="n">{meta.get('victims_simulated', 0)}</div>
      <div class="l">Korban disimulasi</div></div>
  </div>

  <h2>Payload yang dicoba</h2>
  <section class="card">
    <p class="muted">Header: {_esc(', '.join(meta.get('headers_tested', [])))}</p>
    <p class="muted">Payload: {_esc(', '.join(meta.get('payloads_used', [])))}</p>
  </section>
  {hook_block}

  <h2>Hasil injeksi</h2>
  {cards}

  <footer>
    CachePoisonX v{VERSION} &middot; {confirmed} dari {attempts} percobaan berhasil
    menanam payload ke cache. Jejak header (MISS &rarr; HIT) adalah bukti bahwa
    response yang disajikan berasal dari cache, bukan dari origin.
    Laporan mandiri, tanpa CDN.
  </footer>
</div>
</body>
</html>"""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(doc)
        log.info(f"HTML report disimpan ke: {filepath}")
        return filepath

    total = len(findings)
    confirmed = sum(1 for f in findings if f.get("verified"))
    unkeyed = sum(1 for f in findings if f.get("keyed") is False)
    high = sum(1 for f in findings if f.get("severity") == "High")

    cards = "".join(_finding_card(f, i + 1) for i, f in enumerate(findings))
    if not cards:
        cards = (
            "<p class=\"muted\">Tidak ada temuan. Catatan: tidak ada temuan BUKAN "
            "berarti target aman &mdash; lihat tabel cache key di atas untuk melihat "
            "header yang tidak dapat disimpulkan.</p>"
        )

    fp = meta.get("fingerprint") or {}
    fp_text = ", ".join(f"{k}: {v}" for k, v in (fp.get("headers") or {}).items())
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    doc = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CachePoisonX &mdash; Laporan Cache Poisoning</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>CachePoisonX &mdash; Laporan Hasil Uji</h1>
    <p>Target: <strong>{_esc(meta.get('target', '-'))}</strong> &middot;
       dibuat {generated} &middot; v{VERSION}</p>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{total}</div><div class="l">Temuan</div></div>
    <div class="stat"><div class="n">{confirmed}</div><div class="l">Terbukti</div></div>
    <div class="stat"><div class="n">{unkeyed}</div><div class="l">Unkeyed</div></div>
    <div class="stat"><div class="n">{high}</div><div class="l">High severity</div></div>
  </div>

  <h2>Fingerprint cache</h2>
  <section class="card">
    <p class="muted">{_esc(fp_text) or 'Tidak ada header cache terdeteksi pada target.'}</p>
  </section>

  <h2>Cache key differential matrix</h2>
  <section class="card">{_matrix_table(meta.get('cache_key_matrix', []))}</section>

  <h2>Temuan</h2>
  {cards}

  <footer>
    CachePoisonX v{VERSION} &middot; {total} temuan, {confirmed} terverifikasi.
    Laporan ini mandiri (tanpa CDN) sehingga dapat dibuka di lingkungan terisolasi.
  </footer>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(doc)

    log.info(f"HTML report disimpan ke: {filepath}")
    return filepath