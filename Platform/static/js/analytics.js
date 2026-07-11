/* analytics.js — cross-scan BI-style dashboard. Pure SVG/CSS, no external
   charting library, so it works even with no internet access in the lab. */

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const SEV_COLORS_HEX = {
  Critical: '#d0374e', High: '#e8813d', Medium: '#f1c22e', Low: '#4b9b5f', Info: '#2f6fb3'
};
const SEV_COLORS_VAR = {
  Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)',
  Low: 'var(--low)', Info: 'var(--info)'
};

function formatDuration(seconds) {
  seconds = Math.floor(seconds || 0);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function shortDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso + 'Z');
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/* ---------- KPI cards ---------- */
function renderKpis(kpis) {
  document.getElementById('kpiScans').textContent = kpis.total_scans;
  document.getElementById('kpiHosts').textContent = kpis.total_hosts;
  document.getElementById('kpiFindings').textContent = kpis.total_findings;
  document.getElementById('kpiDuration').textContent = formatDuration(kpis.avg_duration_seconds);
}

/* ---------- Severity trend: SVG stacked bar chart over scans ---------- */
function renderTrendChart(trend) {
  const container = document.getElementById('trendChart');

  if (trend.length === 0) {
    container.innerHTML = '<div class="empty-state">No scans yet — run a scan to populate this chart.</div>';
    return;
  }

  const width = 900, height = 260;
  const padLeft = 40, padBottom = 30, padTop = 10, padRight = 10;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const totals = trend.map(t => SEV_ORDER.reduce((s, k) => s + t.counts[k], 0));
  const maxTotal = Math.max(1, ...totals);

  const barSlot = chartW / trend.length;
  const barWidth = Math.min(48, barSlot * 0.6);

  // Y-axis gridlines (4 steps)
  const steps = 4;
  let gridLines = '';
  let gridLabels = '';
  for (let i = 0; i <= steps; i++) {
    const val = Math.round((maxTotal / steps) * i);
    const y = padTop + chartH - (chartH * i / steps);
    gridLines += `<line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="#eef0f3" stroke-width="1"/>`;
    gridLabels += `<text x="${padLeft - 8}" y="${y + 4}" font-size="10" fill="#8a929c" text-anchor="end">${val}</text>`;
  }

  let bars = '';
  let labels = '';
  trend.forEach((t, i) => {
    const x = padLeft + barSlot * i + (barSlot - barWidth) / 2;
    let yCursor = padTop + chartH;
    SEV_ORDER.forEach(sev => {
      const val = t.counts[sev];
      if (val === 0) return;
      const segH = (val / maxTotal) * chartH;
      yCursor -= segH;
      bars += `<rect x="${x}" y="${yCursor}" width="${barWidth}" height="${segH}" fill="${SEV_COLORS_HEX[sev]}">
                 <title>${t.scan_name} — ${sev}: ${val}</title>
               </rect>`;
    });
    labels += `<text x="${x + barWidth / 2}" y="${height - 10}" font-size="10" fill="#8a929c" text-anchor="middle">${shortDate(t.started_at)}</text>`;
  });

  const legend = SEV_ORDER.map(sev => `
    <div class="legend-row" style="justify-content:flex-start;gap:8px;">
      <span class="dot" style="background:${SEV_COLORS_VAR[sev]}"></span>
      <span style="color:var(--text-dim);">${sev}</span>
    </div>`).join('');

  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" style="width:100%;height:auto;">
      ${gridLines}
      ${gridLabels}
      ${bars}
      ${labels}
      <line x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${padTop + chartH}" stroke="#c7cbd1" stroke-width="1"/>
      <line x1="${padLeft}" y1="${padTop + chartH}" x2="${width - padRight}" y2="${padTop + chartH}" stroke="#c7cbd1" stroke-width="1"/>
    </svg>
    <div class="trend-legend">${legend}</div>
  `;
}

/* ---------- Findings by category donut ---------- */
function renderCategoryDonut(categoryCounts) {
  const wrap = document.getElementById('categoryDonutWrap');
  const entries = Object.entries(categoryCounts).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0);

  if (total === 0) {
    wrap.innerHTML = '<div class="donut-empty">No findings yet.</div>';
    return;
  }

  const palette = ['var(--critical)', 'var(--high)', 'var(--accent)', 'var(--low)', 'var(--info)', '#8b5cf6', '#c026d3'];
  const colorMap = {};
  entries.forEach(([k], i) => colorMap[k] = palette[i % palette.length]);

  let acc = 0;
  const stops = entries.map(([label, val]) => {
    const start = (acc / total) * 360;
    acc += val;
    const end = (acc / total) * 360;
    return `${colorMap[label]} ${start}deg ${end}deg`;
  }).join(', ');

  const legendRows = entries
    .sort((a, b) => b[1] - a[1])
    .map(([label, val]) => `
      <div class="legend-row">
        <div class="legend-left"><span class="dot" style="background:${colorMap[label]}"></span>${label}</div>
        <div class="legend-val">${val}</div>
      </div>`).join('');

  wrap.innerHTML = `
    <div class="donut" style="background: conic-gradient(${stops});"></div>
    <div class="legend-list">${legendRows}</div>
  `;
}

/* ---------- Riskiest hosts ---------- */
function renderRiskiestHosts(hosts) {
  const el = document.getElementById('riskiestHosts');
  if (hosts.length === 0) {
    el.innerHTML = '<div class="empty-state">No findings yet.</div>';
    return;
  }

  const maxScore = Math.max(1, ...hosts.map(h => h.counts.Critical * 3 + h.counts.High));

  el.innerHTML = hosts.map(h => {
    const score = h.counts.Critical * 3 + h.counts.High;
    const pct = Math.max(4, (score / maxScore) * 100);
    return `
      <div class="risk-host-row">
        <div class="risk-host-ip">${h.ip}</div>
        <div class="risk-host-bar-wrap">
          <div class="risk-host-bar" style="width:${pct}%;"></div>
        </div>
        <div class="risk-host-counts">
          ${h.counts.Critical > 0 ? `<span style="color:var(--critical);font-weight:700;">${h.counts.Critical}C</span>` : ''}
          ${h.counts.High > 0 ? `<span style="color:var(--high);font-weight:700;">${h.counts.High}H</span>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

/* ---------- Recurring findings table ---------- */
function renderRecurring(rows) {
  const el = document.getElementById('recurringTable');
  if (rows.length === 0) {
    el.innerHTML = '<div class="empty-state">No recurring findings yet — each finding so far has only appeared once.</div>';
    return;
  }

  el.innerHTML = `
    <table class="mini-table">
      <thead><tr><th>Finding</th><th>Severity</th><th>Occurrences</th></tr></thead>
      <tbody>
        ${rows.map(r => `
          <tr>
            <td>${r.title}</td>
            <td><span class="sev ${r.severity}">${r.severity}</span></td>
            <td>${r.count}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

/* ---------- master load ---------- */
async function loadAnalytics() {
  let data;
  try {
    const res = await fetch('/api/analytics');
    data = await res.json();
  } catch (err) {
    console.error('Failed to load analytics:', err);
    return;
  }

  renderKpis(data.kpis);
  renderTrendChart(data.trend);
  renderCategoryDonut(data.category_counts);
  renderRiskiestHosts(data.riskiest_hosts);
  renderRecurring(data.recurring_findings);
}

loadAnalytics();
setInterval(loadAnalytics, 20000);
