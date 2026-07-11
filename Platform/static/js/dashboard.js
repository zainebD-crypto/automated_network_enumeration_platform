/* dashboard.js — "My Scans" history list + New Scan modal. */

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_COLORS = {
  Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)',
  Low: 'var(--low)', Info: 'var(--info)'
};

let scansPolling = null;

function formatDuration(seconds) {
  seconds = Math.floor(seconds || 0);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso + 'Z');
  return d.toLocaleString();
}

function severityMiniBar(counts) {
  const total = SEV_ORDER.reduce((s, k) => s + counts[k], 0);
  if (total === 0) return '<span class="dim" style="font-size:11.5px;color:var(--text-dim);">No findings</span>';
  const segs = SEV_ORDER.filter(s => counts[s] > 0).map(s =>
    `<div class="mini-sev-seg" style="width:${(counts[s] / total) * 100}%; background:${SEV_COLORS[s]};" title="${s}: ${counts[s]}"></div>`
  ).join('');
  return `<div class="mini-sev-bar">${segs}</div>`;
}

async function loadScans() {
  let scans;
  try {
    const res = await fetch('/api/scans');
    scans = await res.json();
  } catch (err) {
    console.error('Failed to load scans:', err);
    return;
  }

  const tbody = document.getElementById('scansTableBody');
  if (scans.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans yet — click "+ New Scan" to get started.</td></tr>';
  } else {
    tbody.innerHTML = scans.map(s => `
      <tr>
        <td><a class="scan-name-link" href="/scans/${s.id}">${s.name}</a></td>
        <td><span class="badge ${s.status}">${s.status.toUpperCase()}</span></td>
        <td>${s.host_count}</td>
        <td>${severityMiniBar(s.severity_counts)}</td>
        <td>${formatDate(s.started_at)}</td>
        <td>${formatDuration(s.duration_seconds)}</td>
        <td><a href="/scans/${s.id}" class="btn-secondary" style="text-decoration:none;display:inline-block;">View</a></td>
      </tr>
    `).join('');
  }

  const anyRunning = scans.some(s => s.status === 'running');
  if (!anyRunning && scansPolling) {
    clearInterval(scansPolling);
    scansPolling = setInterval(loadScans, 15000); // slow poll once nothing's running
  }
}

/* ---------- New Scan modal ---------- */
function openNewScanModal() {
  document.getElementById('newScanModal').classList.add('open');
  document.getElementById('modalError').style.display = 'none';
}
function closeNewScanModal() {
  document.getElementById('newScanModal').classList.remove('open');
}

function addTargetRow() {
  const list = document.getElementById('targetsList');
  const row = document.createElement('div');
  row.className = 'target-row';
  row.innerHTML = `
    <input class="target-input" placeholder="Target IP">
    <button type="button" class="target-remove-btn" onclick="removeTargetRow(this)">✕</button>
  `;
  list.appendChild(row);
  updateRemoveButtonsState();
  row.querySelector('input').focus();
}
function removeTargetRow(btn) {
  const list = document.getElementById('targetsList');
  if (list.children.length <= 1) return;
  btn.closest('.target-row').remove();
  updateRemoveButtonsState();
}
function updateRemoveButtonsState() {
  const rows = document.querySelectorAll('#targetsList .target-row');
  rows.forEach(row => { row.querySelector('.target-remove-btn').disabled = rows.length <= 1; });
}
function getTargetsFromRows() {
  return Array.from(document.querySelectorAll('.target-input')).map(i => i.value.trim()).filter(Boolean);
}
function toggleAdFields() {
  const enabled = document.getElementById('adToggle').checked;
  document.getElementById('adFields').classList.toggle('disabled', !enabled);
}

function showModalError(msg) {
  const el = document.getElementById('modalError');
  el.textContent = msg;
  el.style.display = 'block';
}

async function launchScan() {
  const name = document.getElementById('scanName').value.trim();
  const targets = getTargetsFromRows();
  const adEnabled = document.getElementById('adToggle').checked;
  const domain = adEnabled ? document.getElementById('domain').value.trim() : '';
  const dc_ip = adEnabled ? document.getElementById('dcIp').value.trim() : '';
  const username = adEnabled ? document.getElementById('adUsername').value : '';
  const password = adEnabled ? document.getElementById('adPassword').value : '';

  if (targets.length === 0) {
    showModalError('Enter at least one target IP.');
    return;
  }
  if (adEnabled && !domain) {
    showModalError('AD target is enabled — enter a domain, or turn the AD toggle off.');
    return;
  }

  const btn = document.getElementById('launchScanBtn');
  btn.disabled = true;
  btn.textContent = 'Launching...';

  let res;
  try {
    res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, targets, ad_enabled: adEnabled, domain, dc_ip, username, password })
    });
  } catch (err) {
    showModalError('Could not reach the server.');
    btn.disabled = false;
    btn.textContent = 'Launch Scan';
    return;
  }

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    showModalError(body.error || `Request failed (HTTP ${res.status}).`);
    btn.disabled = false;
    btn.textContent = 'Launch Scan';
    return;
  }

  // Reset the form so the previous target(s) don't linger — the scan we
  // just launched is already saved and will show up in the table below.
  document.getElementById('scanName').value = '';
  document.getElementById('targetsList').innerHTML = `
    <div class="target-row">
      <input class="target-input" placeholder="Target IP">
      <button type="button" class="target-remove-btn" onclick="removeTargetRow(this)" disabled>✕</button>
    </div>`;
  document.getElementById('adToggle').checked = false;
  toggleAdFields();
  ['domain', 'dcIp', 'adUsername', 'adPassword'].forEach(id => document.getElementById(id).value = '');

  btn.disabled = false;
  btn.textContent = 'Launch Scan';
  closeNewScanModal();

  loadScans();
  if (!scansPolling) scansPolling = setInterval(loadScans, 2000);

  // Jump straight to the new scan's detail page, like Nessus does after launch.
  window.location.href = `/scans/${body.scan_id}`;
}

updateRemoveButtonsState();
loadScans();
scansPolling = setInterval(loadScans, 3000);
