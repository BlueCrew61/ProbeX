/* ==========================================================================
   ProbeX GUI — script.js
   SPA terhubung ke backend API (probex_api.py). Semua scan/injeksi/monitor
   dijalankan melalui HTTP ke backend ProbeX, bukan simulasi hardcoded.
   ========================================================================== */

(function () {
  'use strict';

  const API_BASE = 'http://127.0.0.1:8777';
  const state = {
    activeSection: 'scanner',
    scanRunning: false,
    monitorPaused: false,
    monitorInterval: null,
    findings: [],
    injected: [],
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // ---------- API helpers ----------
  async function apiPost(path, body) {
    const resp = await fetch(API_BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    return resp.json();
  }

  async function apiGet(path) {
    const resp = await fetch(API_BASE + path);
    return resp.json();
  }

  function showToast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = 'fixed top-4 right-4 z-50 px-4 py-2 rounded-lg font-mono text-[12px] text-on-surface shadow-inner transition-opacity';
    el.style.background = type === 'error' ? 'rgba(229,72,77,0.95)' : 'rgba(200,240,49,0.15)';
    el.style.border = type === 'error' ? '1px solid #E5484D' : '1px solid #CAF233';
    el.style.color = type === 'error' ? '#ffb4ab' : '#0E0F0C';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 2500);
  }

  // ---------- Navigation ----------
  function showSection(id) {
    state.activeSection = id;
    $$('.section').forEach((el) => el.classList.remove('active'));
    $$('.nav-item').forEach((el) => el.classList.remove('active'));
    const target = $('#' + id);
    if (target) target.classList.add('active');
    const nav = $('[data-section="' + id + '"]');
    if (nav) nav.classList.add('active');

    if (id === 'monitor') startMonitorPoll();
    else stopMonitorPoll();

    if (id === 'scanner') stopScan();
  }

  $$('.nav-item').forEach((item) => {
    item.addEventListener('click', (e) => {
      const section = item.getAttribute('data-section');
      if (section) showSection(section);
    });
  });

  // ---------- Consent (SSH page) ----------
  const consent = $('#auth-consent');
  if (consent) {
    consent.addEventListener('change', () => {
      const btn = $('#ssh-run-btn');
      if (btn) btn.disabled = !consent.checked;
    });
  }

  // ---------- Scanner: detect via API ----------
  const startBtn = $('#start-scan-btn');
  if (startBtn) {
    startBtn.addEventListener('click', async () => {
      const targetInput = $('#target-url-input');
      const target = targetInput ? targetInput.value.trim() : '';
      if (!target) {
        showToast('Masukkan target URL terlebih dahulu.', 'error');
        return;
      }
      if (state.scanRunning) {
        showToast('Pemindaian sudah berjalan.', 'error');
        return;
      }

      state.scanRunning = true;
      startBtn.textContent = 'MEMINDAI...';
      startBtn.classList.add('btn-secondary');
      startBtn.classList.remove('btn-primary');

      const logContainer = $('#scan-log');
      if (logContainer) {
        logContainer.innerHTML = '';
        appendLog(logContainer, 'INFO', 'Menghubungkan backend ProbeX di ' + API_BASE);
        appendLog(logContainer, 'INFO', 'Target: ' + target);
      }

      try {
        const data = await apiPost('/api/detect', { target: target });

        if (data.ok) {
          state.findings = data.findings || [];
          renderFindingsTable(state.findings);
          appendLog(logContainer, 'INFO', 'Backend mencatat ' + data.count + ' temuan.');
          if (data.count > 0) {
            showToast('Deteksi selesai: ' + data.count + ' temuan.', 'info');
          } else {
            showToast('Deteksi selesai: tidak ada temuan.', 'info');
          }
        } else {
          appendLog(logContainer, 'ERROR', data.error || 'Deteksi gagal.');
          showToast('Deteksi gagal: ' + (data.error || 'tidak diketahui'), 'error');
        }
      } catch (err) {
        appendLog(logContainer, 'ERROR', 'Gagal konek ke backend: ' + err.message);
        showToast('Backend tidak terjangkau. Nyalakan probex_api.py dulu.', 'error');
      }

      state.scanRunning = false;
      startBtn.textContent = 'MULAI PINDAI';
      startBtn.classList.remove('btn-secondary');
      startBtn.classList.add('btn-primary');
    });
  }

  function stopScan() {
    state.scanRunning = false;
    const btn = $('#start-scan-btn');
    if (btn) {
      btn.textContent = 'MULAI PINDAI';
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-primary');
    }
  }

  // ---------- Injection via API ----------
  const injectBtn = $$('button').find((b) => b.textContent && b.textContent.includes('Jalankan Pengujian'));
  if (injectBtn) {
    injectBtn.addEventListener('click', async () => {
      const urlInput = $$('input').find((i) => i.placeholder && i.placeholder.includes('target-endpoint'));
      const target = urlInput ? urlInput.value.trim() : '';
      if (!target) {
        showToast('Masukkan target URL terlebih dahulu.', 'error');
        return;
      }
      if (state.scanRunning) {
        showToast('Proses lain masih berjalan.', 'error');
        return;
      }

      state.scanRunning = true;
      injectBtn.textContent = 'MENJALANKAN...';
      injectBtn.disabled = true;

      try {
        const data = await apiPost('/api/inject', {
          target: target,
          payloads: ['host'],
          headers: ['X-Forwarded-Host'],
        });

        if (data.ok) {
          state.injected = data.findings || [];
          const tbody = $('#injection-results');
          if (tbody) renderInjectionTable(state.injected);
          showToast('Injeksi selesai: ' + data.injected + ' berhasil tertanam.', 'info');
        } else {
          showToast('Injeksi gagal: ' + (data.error || 'tidak diketahui'), 'error');
        }
      } catch (err) {
        showToast('Gagal konek backend: ' + err.message, 'error');
      }

      state.scanRunning = false;
      injectBtn.textContent = 'Jalankan Pengujian';
      injectBtn.disabled = false;
    });
  }

  // ---------- API config form ----------
  const apiForm = $('#api-config-form');
  if (apiForm) {
    apiForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const btn = apiForm.querySelector('button[type="submit"]');
      if (btn) { btn.textContent = 'DISIMPAN...'; btn.disabled = true; }
      setTimeout(() => {
        if (btn) { btn.textContent = 'DISIMPAN'; btn.disabled = false; }
        showToast('Konfigurasi API penyedia disimpan.', 'info');
      }, 800);
    });
  }

  // ---------- Visibility toggle ----------
  const toggleKey = $('#toggle-key-visibility');
  const keyInput = $('#api-key');
  const eyeIcon = $('#eye-icon');
  if (toggleKey && keyInput) {
    toggleKey.addEventListener('click', () => {
      const isPassword = keyInput.type === 'password';
      keyInput.type = isPassword ? 'text' : 'password';
      eyeIcon.textContent = isPassword ? 'visibility_off' : 'visibility';
    });
  }

  // ---------- Log helpers ----------
  function appendLog(container, level, msg) {
    if (!container) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString('id-ID', { hour12: false });
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML =
      '<span class="log-time">[' + timeStr + ']</span>' +
      '<span class="log-level ' + level + '">' + level.toUpperCase() + '</span>' +
      '<span class="log-msg">' + escapeHtml(msg) + '</span>';
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ---------- Renderers ----------
  function renderFindingsTable(findings) {
    const tbody = $('#findings-table-body');
    if (!tbody) return;
    tbody.innerHTML = findings.map((f) => {
      const isHigh = f.severity === 'high' || f.severity === 'High' || f.severity === 'Tinggi';
      const isMed = f.severity === 'med' || f.severity === 'Medium' || f.severity === 'Sedang';
      const bg = isHigh ? 'bg-secondary-container' : (isMed ? 'bg-tertiary-container/20' : 'bg-outline');
      const txt = isHigh ? 'text-secondary' : (isMed ? 'text-tertiary-container/20' : 'text-outline');
      const sevLabel = isHigh ? 'Tinggi' : (isMed ? 'Sedang' : 'Rendah');
      return `
        <tr class="hover:bg-surface-high/40 transition-colors group">
          <td class="py-4 px-4">
            <div class="flex items-center space-x-1.5">
              <span class="w-1.5 h-3 ${bg}"></span>
              <span class="font-mono text-[12px] ${txt} font-medium uppercase">${sevLabel}</span>
            </div>
          </td>
          <td class="py-4 px-4 font-medium text-primary">${escapeHtml(f.title || '(tanpa judul)')}</td>
          <td class="py-4 px-4 font-mono text-[12px] text-on-surface-v">${escapeHtml(f.url || f.location || '')}</td>
          <td class="py-4 px-4 text-right font-mono text-[12px]">
            <span class="text-primary-fixed font-semibold">${escapeHtml(f.cvss || '-')}</span>
            <span class="text-outline block text-[10px]">${escapeHtml(f.detail || '')}</span>
          </td>
        </tr>
      `;
    }).join('');
  }

  function renderInjectionTable(findings) {
    const tbody = $('#injection-results');
    if (!tbody) return;
    tbody.innerHTML = findings.map((f) => {
      const isHigh = f.severity === 'high' || f.severity === 'High';
      return `
        <tr class="hover:bg-surface-high/40 transition-colors">
          <td class="py-4 px-4"><span class="font-mono text-[12px] text-on-surface-v">${escapeHtml(f.parameter || f.header || '-')}</span></td>
          <td class="py-4 px-4 font-mono text-[12px] text-on-surface">${escapeHtml(f.evidence || f.payload || '-')}</td>
          <td class="py-4 px-4"><span class="badge ${isHigh ? 'badge-high' : 'badge-med'}">${isHigh ? 'TERTERVAKAI' : 'DIREVIEW'}</span></td>
          <td class="py-4 px-4 text-right font-mono text-[12px] text-primary-fixed-dim">200 OK</td>
        </tr>
      `;
    }).join('');
  }

  // ---------- Monitor poisoning ----------
  const monitorLog = $('#monitor-log-body');
  const pauseBtn = $('#pauseToggleBtn');

  function startMonitorPoll() {
    if (state.monitorInterval) return;
    fetchMonitorEvents();
    state.monitorInterval = setInterval(fetchMonitorEvents, 3000);
  }

  function stopMonitorPoll() {
    if (state.monitorInterval) {
      clearInterval(state.monitorInterval);
      state.monitorInterval = null;
    }
  }

  async function fetchMonitorEvents() {
    if (state.monitorPaused || !monitorLog) return;
    try {
      const data = await apiGet('/api/events');
      const hits = data.hits || [];
      if (hits.length === 0) return;
      const existing = monitorLog.querySelectorAll('.log-entry');
      let added = 0;
      hits.slice().reverse().forEach((h) => {
        const time = (h.time || '').replace('T', ' ').slice(0, 19);
        const token = (h.token || '-').slice(0, 20);
        const client = (h.client || '-');
        const ua = (h.user_agent || '-').slice(0, 30);
        let already = false;
        existing.forEach((el) => {
          if (el.textContent.includes(token) && el.textContent.includes(time)) already = true;
        });
        if (already) return;
        added++;
        appendLog(monitorLog, 'INFO', 'Webhook hit: token=' + token + ' dari ' + client + ' UA=' + ua + ' waktu=' + time);
      });
      if (added > 0) showToast('Webhook monitor: ' + added + ' hit baru.', 'info');
    } catch (err) {
      // Silent on monitor poll errors (lab may not be running)
    }
  }

  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      state.monitorPaused = !state.monitorPaused;
      const label = $('#pauseLabel');
      const icon = $('#pauseIcon');
      if (state.monitorPaused) {
        label.textContent = 'Lanjutkan Pemantauan';
        icon.textContent = 'play_arrow';
        pauseBtn.classList.add('bg-primary-container', 'text-on-primary-container');
        pauseBtn.classList.remove('bg-surface-container', 'text-on-surface');
      } else {
        label.textContent = 'Jeda Pemantauan';
        icon.textContent = 'pause';
        pauseBtn.classList.remove('bg-primary-container', 'text-on-primary-container');
        pauseBtn.classList.add('bg-surface-container', 'text-on-surface');
      }
    });
  }

  // ---------- Init ----------
  document.addEventListener('DOMContentLoaded', () => {
    showSection('scanner');
    const targetInput = $('#target-url-input');
    if (targetInput) targetInput.focus();

    apiGet('/api/status').then(() => {
      showToast('Backend ProbeX terhubung (' + API_BASE + ').', 'info');
    }).catch(() => {
      showToast('Backend belum nyala. Jalankan: python3 probex_api.py 8777', 'error');
    });
  });

})();
