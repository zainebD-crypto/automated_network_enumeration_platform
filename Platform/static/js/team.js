/* team.js — admin-only team management page. */

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso + 'Z').toLocaleDateString();
}

async function loadTeam() {
  let users;
  try {
    const res = await fetch('/api/team');
    if (res.status === 403) {
      document.getElementById('teamTableBody').innerHTML =
        '<tr><td colspan="5" class="empty-state">Admin access required.</td></tr>';
      return;
    }
    users = await res.json();
  } catch (err) {
    console.error('Failed to load team:', err);
    return;
  }

  const tbody = document.getElementById('teamTableBody');
  if (users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No team members yet.</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${u.username}</td>
      <td>${u.email || '—'}</td>
      <td>${u.is_admin ? '<span class="badge completed">ADMIN</span>' : '<span class="badge queued">ANALYST</span>'}</td>
      <td>${formatDate(u.created_at)}</td>
      <td style="text-align:right;">
        <button class="btn-secondary" style="padding:6px 12px;font-size:12px;" onclick="removeMember(${u.id}, '${u.username}')">Remove</button>
      </td>
    </tr>
  `).join('');
}

function openAddMemberModal() {
  document.getElementById('addMemberModal').classList.add('open');
  document.getElementById('addMemberError').style.display = 'none';
  document.getElementById('devSetupLink').style.display = 'none';
  document.getElementById('memberUsername').value = '';
  document.getElementById('memberEmail').value = '';
  document.getElementById('memberIsAdmin').checked = false;
}

function closeAddMemberModal() {
  document.getElementById('addMemberModal').classList.remove('open');
}

async function addTeamMember() {
  const username = document.getElementById('memberUsername').value.trim();
  const email = document.getElementById('memberEmail').value.trim();
  const is_admin = document.getElementById('memberIsAdmin').checked;

  const errEl = document.getElementById('addMemberError');
  const linkEl = document.getElementById('devSetupLink');
  errEl.style.display = 'none';
  linkEl.style.display = 'none';

  if (!username || !email) {
    errEl.textContent = 'Username and email are required.';
    errEl.style.display = 'block';
    return;
  }

  const btn = document.getElementById('addMemberBtn');
  btn.disabled = true;
  btn.textContent = 'Adding...';

  let body;
  try {
    const res = await fetch('/api/team', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, is_admin })
    });
    body = await res.json();
    if (!res.ok) {
      errEl.textContent = body.error || 'Failed to add team member.';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Add Member';
      return;
    }
  } catch (err) {
    errEl.textContent = 'Could not reach the server.';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Add Member';
    return;
  }

  btn.disabled = false;
  btn.textContent = 'Add Member';

  if (body.dev_setup_link) {
    // No SMTP configured -- show the setup link so the admin can share it manually.
    linkEl.innerHTML = `<strong>No email server configured.</strong> Share this setup link with ${username}:<br>
      <code style="word-break:break-all;">${body.dev_setup_link}</code>`;
    linkEl.style.display = 'block';
  } else {
    closeAddMemberModal();
  }

  loadTeam();
}

async function removeMember(id, username) {
  if (!confirm(`Remove ${username} from the team? This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/team/${id}`, { method: 'DELETE' });
    const body = await res.json();
    if (!res.ok) {
      alert(body.error || 'Failed to remove team member.');
      return;
    }
  } catch (err) {
    alert('Could not reach the server.');
    return;
  }
  loadTeam();
}

loadTeam();
