/* scan_detail.js — single scan view: Hosts / Findings tabs, console, sidebar. */

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_COLORS = {
  Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)',
  Low: 'var(--low)', Info: 'var(--info)'
};

let polling = null;
let openHost = null;
let lastState = null;

/* ---------- tabs ---------- */
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

/* ---------- helpers ---------- */
function formatDuration(seconds) {
  seconds = Math.floor(seconds || 0);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso + 'Z').toLocaleString();
}
function cssSafe(ip) { return ip.replace(/[^a-zA-Z0-9]/g, '_'); }

/* ---------- console ---------- */
function renderConsole(log) {
  const el = document.getElementById('console');
  el.innerHTML = (log || []).map(l => `<div>${l}</div>`).join('') || '<div>Waiting for the scan to start logging...</div>';
  el.scrollTop = el.scrollHeight;
}

/* ---------- severity aggregation + sidebar donut ---------- */
function countAllFindings(targets) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  Object.values(targets).forEach(t => {
    (t.security_findings || []).forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  });
  return counts;
}

function renderSevDonut(counts) {
  const wrap = document.getElementById('sevDonutWrap');
  const entries = SEV_ORDER.map(s => [s, counts[s]]).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0);

  if (total === 0) {
    wrap.innerHTML = '<div class="donut-empty">No data yet.</div>';
    return;
  }

  let acc = 0;
  const stops = entries.map(([label, val]) => {
    const start = (acc / total) * 360;
    acc += val;
    const end = (acc / total) * 360;
    return `${SEV_COLORS[label]} ${start}deg ${end}deg`;
  }).join(', ');

  const legendRows = entries.map(([label, val]) => `
    <div class="legend-row">
      <div class="legend-left"><span class="dot" style="background:${SEV_COLORS[label]}"></span>${label}</div>
      <div class="legend-val">${val}</div>
    </div>`).join('');

  wrap.innerHTML = `
    <div class="donut" style="background: conic-gradient(${stops});"></div>
    <div class="legend-list">${legendRows}</div>
  `;
}

/* ---------- sidebar: Scan Details ---------- */
function renderScanDetails(state) {
  document.getElementById('detailStatus').innerHTML = `<span class="badge ${state.status}">${state.status.toUpperCase()}</span>`;
  document.getElementById('detailHosts').textContent = Object.keys(state.targets).length;
  document.getElementById('detailStarted').textContent = formatDate(state.started_at);
  document.getElementById('detailDuration').textContent = formatDuration(state.duration_seconds);
}

/* ---------- Hosts tab ---------- */
function renderHostList(targets) {
  const ips = Object.keys(targets);
  document.getElementById('hostsCount').textContent = ips.length;
  const listEl = document.getElementById('hostList');

  if (ips.length === 0) {
    listEl.innerHTML = '<div class="empty-state">No targets in this scan.</div>';
    return;
  }

  listEl.innerHTML = ips.map(ip => {
    const t = targets[ip];
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (t.security_findings || []).forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
    const total = SEV_ORDER.reduce((s, k) => s + counts[k], 0);

    const recon = t.modules.recon && t.modules.recon.result;
    const hostRecon = recon ? recon[ip] : null;
    const osName = (hostRecon && hostRecon.os && hostRecon.os[0]) ? hostRecon.os[0].name : 'Unknown';

    const statusMap = { queued: 'queued', running: 'running', completed: 'completed', failed: 'failed' };
    const overallStatus = statusMap[t.status] || 'queued';

    const bar = total === 0
      ? `<div class="host-bar-empty">${overallStatus === 'running' ? 'Scanning...' : 'No findings'}</div>`
      : SEV_ORDER.filter(s => counts[s] > 0).map(s => `
          <div class="host-bar-seg" style="width:${(counts[s] / total) * 100}%; background:${SEV_COLORS[s]}; ${s === 'Medium' ? 'color:#4a3b00;' : ''}">${counts[s]}</div>
        `).join('');

    return `
      <div class="host-row" onclick="toggleHost('${ip}')">
        <div class="host-id">
          <div class="host-ip">${ip}</div>
          <div class="host-os">${osName}</div>
        </div>
        <div class="host-bar">${bar}</div>
        <div class="host-status"><span class="badge ${overallStatus}">${overallStatus.toUpperCase()}</span></div>
      </div>
      <div class="host-detail ${openHost === ip ? 'open' : ''}" id="detail-${cssSafe(ip)}"></div>
    `;
  }).join('');

  if (openHost && targets[openHost]) renderHostDetail(openHost, targets[openHost]);
}

function toggleHost(ip) {
  openHost = (openHost === ip) ? null : ip;
  if (lastState) renderHostList(lastState.targets);
}

function renderHostDetail(ip, t) {
  const el = document.getElementById('detail-' + cssSafe(ip));
  if (!el) return;
  el.classList.add('open');

  const recon = t.modules.recon && t.modules.recon.result;
  const host = recon ? recon[ip] : null;
  const smb = t.modules.smb && t.modules.smb.result;
  const ad = t.modules.ad && t.modules.ad.result;
  const adStatus = t.modules.ad && t.modules.ad.status;

  let portRows = '<tr><td colspan="4">No open ports found</td></tr>';
  if (host && host.ports) {
    portRows = Object.entries(host.ports).map(([port, info]) =>
      `<tr><td>${port}</td><td>${info.state}</td><td>${info.service}</td><td>${info.version || '-'}</td></tr>`
    ).join('') || portRows;
  }

  const shares = smb ? Object.keys(smb.shares || {}) : [];

  el.innerHTML = `
    <div class="two-col">
      <div>
        <h2 style="font-size:12px;">Network Enumeration</h2>
        <table class="mini-table"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>${portRows}</tbody></table>
      </div>
      <div>
        <h2 style="font-size:12px;">SMB Enumeration</h2>
        ${smb ? `
          <p style="font-size:13px;">Anonymous Access:
            <strong style="color:${smb.anonymous_access ? 'var(--critical)' : 'var(--low)'}">
              ${smb.anonymous_access ? 'ALLOWED' : 'Denied'}
            </strong>
          </p>
          <table class="mini-table"><thead><tr><th>Share</th><th>Items</th></tr></thead><tbody>
            ${shares.map(s => `<tr><td>${s}</td><td>${(smb.shares[s] || []).length}</td></tr>`).join('') || '<tr><td colspan=2>None</td></tr>'}
          </tbody></table>
        ` : '<div class="empty-state">No data yet.</div>'}
      </div>
    </div>
    <div style="margin-top:16px;">
      <h2 style="font-size:12px;">Active Directory Enumeration</h2>
      ${ad ? `
        <div class="two-col">
          <div>
            <p style="font-size:13px; color:var(--text-dim)">Users enumerated: ${(ad.users || []).length}</p>
            <p style="font-size:13px; color:var(--text-dim)">Domain Admins: ${(ad.domain_admins || []).length}</p>
          </div>
          <div>
            <p style="font-size:13px;">Kerberoastable: <strong style="color:var(--high)">${(ad.kerberoastable || []).join(', ') || 'None'}</strong></p>
            <p style="font-size:13px;">AS-REP Roastable: <strong style="color:var(--high)">${(ad.asrep_roastable || []).join(', ') || 'None'}</strong></p>
          </div>
        </div>
      ` : `<div class="empty-state">${adStatus === 'skipped' ? 'AD enumeration was skipped for this target (no domain supplied).' : 'No data yet.'}</div>`}
    </div>
  `;
}

/* ---------- Findings tab ---------- */
function renderFindings() {
  if (!lastState) return;
  const targets = lastState.targets;
  const filterEl = document.getElementById('findingsHostFilter');

  const currentIps = Object.keys(targets);
  const existingOptions = Array.from(filterEl.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(existingOptions) !== JSON.stringify(currentIps)) {
    filterEl.innerHTML = '<option value="">All hosts</option>' + currentIps.map(ip => `<option value="${ip}">${ip}</option>`).join('');
  }
  const selectedHost = filterEl.value;

  let rows = [];
  Object.entries(targets).forEach(([ip, t]) => {
    if (selectedHost && selectedHost !== ip) return;
    (t.security_findings || []).forEach(f => rows.push({ ...f, host: ip }));
  });

  document.getElementById('findingsCount').textContent = rows.length;
  const el = document.getElementById('findingsResults');

  if (rows.length === 0) {
    el.innerHTML = '<div class="empty-state">No findings yet.</div>';
    return;
  }

  const sevRank = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  rows.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  el.innerHTML = `
    <table class="mini-table"><thead><tr><th>Severity</th><th>Host</th><th>Category</th><th>Title</th><th>Detail</th><th>Recommendation</th></tr></thead>
    <tbody>
      ${rows.map(f => `
        <tr>
          <td><span class="sev ${f.severity}">${f.severity}</span></td>
          <td style="font-family:'Courier New',monospace;">${f.host}</td>
          <td>${f.category}</td>
          <td>${f.title}</td>
          <td style="color:var(--text-dim)">${f.detail}</td>
          <td style="color:var(--text-dim)">${f.recommendation}</td>
        </tr>
      `).join('')}
    </tbody></table>
  `;
}

/* ---------- master poll ---------- */
async function pollStatus() {
  let state;
  try {
    const res = await fetch(`/api/scans/${SCAN_ID}`);
    state = await res.json();
  } catch (err) {
    console.error('Failed to reach /api/scans/' + SCAN_ID, err);
    return;
  }
  lastState = state;

  const counts = countAllFindings(state.targets);
  renderScanDetails(state);
  renderSevDonut(counts);
  renderConsole(state.log);
  renderHostList(state.targets);
  renderFindings();

  document.getElementById('reportBtn').disabled = state.running;

  if (!state.running && polling) {
    clearInterval(polling);
    polling = setInterval(pollStatus, 10000); // slow poll once finished, in case a re-run happens
  }
}

/* ---------- Export Report modal ---------- */
function openReportModal() {
  document.getElementById('reportModal').classList.add('open');
  document.getElementById('reportModalError').style.display = 'none';
}

function closeReportModal() {
  document.getElementById('reportModal').classList.remove('open');
}

function downloadReport() {
  const name = document.getElementById('reportName').value.trim();
  const client = document.getElementById('reportClient').value.trim();
  const author = document.getElementById('reportAuthor').value.trim();

  if (!name) {
    const err = document.getElementById('reportModalError');
    err.textContent = 'Report name is required.';
    err.style.display = 'block';
    return;
  }

  const params = new URLSearchParams();
  if (name) params.set('name', name);
  if (client) params.set('client', client);
  if (author) params.set('author', author);

  window.location.href = `/api/scans/${SCAN_ID}/report?${params.toString()}`;
  closeReportModal();
}

/* ---------- Ask ANCScan (AI advisory chat) ---------- */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderChatMessages(messages) {
  const el = document.getElementById('chatMessages');
  if (messages.length === 0) {
    el.innerHTML = '<div class="empty-state">Ask about this scan\'s findings, priorities, or remediation wording.</div>';
    return;
  }
  el.innerHTML = messages.map(m => `
    <div class="chat-msg chat-msg-${m.role}">
      <div class="chat-msg-role">${m.role === 'user' ? 'You' : 'ANCScan Assistant'}</div>
      <div class="chat-msg-content">${escapeHtml(m.content).replace(/\n/g, '<br>')}</div>
    </div>
  `).join('');
  el.scrollTop = el.scrollHeight;
}

async function loadChatHistory() {
  try {
    const res = await fetch(`/api/scans/${SCAN_ID}/chat`);
    const messages = await res.json();
    renderChatMessages(messages);
  } catch (err) {
    console.error('Failed to load chat history:', err);
  }
}

async function sendChatMessage() {
  const input = document.getElementById('chatInput');
  const text = input.value.trim();
  if (!text) return;

  const sendBtn = document.getElementById('chatSendBtn');
  input.disabled = true;
  sendBtn.disabled = true;
  sendBtn.textContent = '...';

  // Optimistically show the user's message immediately.
  const el = document.getElementById('chatMessages');
  if (el.querySelector('.empty-state')) el.innerHTML = '';
  el.insertAdjacentHTML('beforeend', `
    <div class="chat-msg chat-msg-user">
      <div class="chat-msg-role">You</div>
      <div class="chat-msg-content">${escapeHtml(text)}</div>
    </div>
  `);
  el.scrollTop = el.scrollHeight;
  input.value = '';

  try {
    const res = await fetch(`/api/scans/${SCAN_ID}/ask`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text })
    });
    const body = await res.json();
    if (body.message) {
      el.insertAdjacentHTML('beforeend', `
        <div class="chat-msg chat-msg-assistant">
          <div class="chat-msg-role">ANCScan Assistant</div>
          <div class="chat-msg-content">${escapeHtml(body.message.content).replace(/\n/g, '<br>')}</div>
        </div>
      `);
    }
  } catch (err) {
    el.insertAdjacentHTML('beforeend', `
      <div class="chat-msg chat-msg-assistant">
        <div class="chat-msg-role">ANCScan Assistant</div>
        <div class="chat-msg-content">[Could not reach the assistant. Check the server console.]</div>
      </div>
    `);
  }

  el.scrollTop = el.scrollHeight;
  input.disabled = false;
  sendBtn.disabled = false;
  sendBtn.textContent = 'Send';
  input.focus();
}

pollStatus();
polling = setInterval(pollStatus, 1200);
loadChatHistory();
