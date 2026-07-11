/* notifications.js — bell icon dropdown, shared across every page. */

let notifDropdownOpen = false;

function toggleNotifDropdown() {
  notifDropdownOpen = !notifDropdownOpen;
  document.getElementById('notifDropdown').classList.toggle('open', notifDropdownOpen);
  if (notifDropdownOpen) loadNotifications();
}

document.addEventListener('click', (e) => {
  const wrap = document.querySelector('.notif-wrap');
  if (wrap && !wrap.contains(e.target) && notifDropdownOpen) {
    notifDropdownOpen = false;
    document.getElementById('notifDropdown').classList.remove('open');
  }
});

function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso + 'Z')) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

async function loadNotifications() {
  let notes;
  try {
    const res = await fetch('/api/notifications');
    notes = await res.json();
  } catch (err) {
    return;
  }

  const unread = notes.filter(n => !n.read).length;
  const badge = document.getElementById('notifBadge');
  if (unread > 0) {
    badge.style.display = 'block';
    badge.textContent = unread > 9 ? '9+' : unread;
  } else {
    badge.style.display = 'none';
  }

  const dropdown = document.getElementById('notifDropdown');
  if (notes.length === 0) {
    dropdown.innerHTML = `
      <div class="notif-dropdown-header"><span>Notifications</span></div>
      <div class="notif-empty">No notifications yet.</div>
    `;
    return;
  }

  dropdown.innerHTML = `
    <div class="notif-dropdown-header">
      <span>Notifications</span>
      <button onclick="markAllRead(event)">Mark all read</button>
    </div>
    ${notes.map(n => `
      <div class="notif-item ${n.read ? '' : 'unread'}" onclick="onNotifClick(event, ${n.id}, ${n.scan_id ?? 'null'})">
        <div class="notif-msg">${n.message}</div>
        <div class="notif-time">${timeAgo(n.created_at)}</div>
      </div>
    `).join('')}
  `;
}

async function onNotifClick(e, noteId, scanId) {
  e.stopPropagation();
  try {
    await fetch(`/api/notifications/${noteId}/read`, { method: 'POST' });
  } catch (err) { /* non-fatal */ }
  if (scanId) window.location.href = `/scans/${scanId}`;
  else loadNotifications();
}

async function markAllRead(e) {
  e.stopPropagation();
  try {
    await fetch('/api/notifications/read_all', { method: 'POST' });
  } catch (err) { /* non-fatal */ }
  loadNotifications();
}

loadNotifications();
setInterval(loadNotifications, 8000);
