/* vulnerabilities.js — cross-scan findings library, with severity/category/search filters. */

let allVulns = [];
let activeSevs = new Set(['Critical', 'High', 'Medium', 'Low', 'Info']);

function toggleSevFilter(btn) {
  const sev = btn.dataset.sev;
  if (activeSevs.has(sev)) {
    activeSevs.delete(sev);
    btn.classList.remove('active');
  } else {
    activeSevs.add(sev);
    btn.classList.add('active');
  }
  renderVulnTable();
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso + 'Z').toLocaleDateString();
}

function populateCategoryFilter(vulns) {
  const select = document.getElementById('vulnCategoryFilter');
  const current = select.value;
  const categories = [...new Set(vulns.map(v => v.category).filter(Boolean))].sort();
  select.innerHTML = '<option value="">All categories</option>' +
    categories.map(c => `<option value="${c}">${c}</option>`).join('');
  if (categories.includes(current)) select.value = current;
}

function renderVulnTable() {
  const search = document.getElementById('vulnSearch').value.trim().toLowerCase();
  const categoryFilter = document.getElementById('vulnCategoryFilter').value;

  const filtered = allVulns.filter(v => {
    if (!activeSevs.has(v.severity)) return false;
    if (categoryFilter && v.category !== categoryFilter) return false;
    if (search) {
      const haystack = `${v.title} ${v.host} ${v.detail} ${v.scan_name}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  document.getElementById('vulnCount').textContent = `${filtered.length} of ${allVulns.length} finding(s)`;

  const wrap = document.getElementById('vulnTableWrap');
  if (filtered.length === 0) {
    wrap.innerHTML = '<div class="empty-state">No findings match the current filters.</div>';
    return;
  }

  wrap.innerHTML = `
    <table class="mini-table">
      <thead>
        <tr>
          <th>Severity</th><th>Host</th><th>Category</th><th>Title</th>
          <th>Detail</th><th>Scan</th><th>Found</th>
        </tr>
      </thead>
      <tbody>
        ${filtered.map(v => `
          <tr>
            <td><span class="sev ${v.severity}">${v.severity}</span></td>
            <td style="font-family:'Courier New',monospace;">${v.host}</td>
            <td>${v.category || '—'}</td>
            <td>${v.title}</td>
            <td style="color:var(--text-dim);max-width:280px;">${v.detail || ''}</td>
            <td><a href="/scans/${v.scan_id}" style="color:var(--accent);text-decoration:none;">${v.scan_name}</a></td>
            <td style="color:var(--text-dim);white-space:nowrap;">${formatDate(v.found_at)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function loadVulnerabilities() {
  try {
    const res = await fetch('/api/vulnerabilities');
    allVulns = await res.json();
  } catch (err) {
    console.error('Failed to load vulnerabilities:', err);
    document.getElementById('vulnTableWrap').innerHTML =
      '<div class="empty-state">Failed to load vulnerabilities.</div>';
    return;
  }
  populateCategoryFilter(allVulns);
  renderVulnTable();
}

loadVulnerabilities();
