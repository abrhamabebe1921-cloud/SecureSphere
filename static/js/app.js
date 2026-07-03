// ═══════════════════════════════════════════════════════════
// SecureSphere v2.0 — Main Application JavaScript
// ═══════════════════════════════════════════════════════════

const socket = io();
let currentFindings = [];
let scanRunning = false;

// ── Init ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadActivity();
});

// ── Stats ──────────────────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        animateNumber('statScans', stats.total_scans);
        animateNumber('statCritical', stats.severity.critical);
        animateNumber('statHigh', stats.severity.high);
        animateNumber('statMedium', stats.severity.medium);
        animateNumber('statUsers', stats.total_users);
    } catch (e) {
        console.error('Failed to load stats:', e);
    }
}

function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    let current = 0;
    const step = Math.ceil(target / 30);
    const interval = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(interval);
        }
        el.textContent = current;
    }, 30);
}

// ── Scan Panel ─────────────────────────────────────────────
function toggleScanPanel() {
    const panel = document.getElementById('scanPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    if (panel.style.display === 'block') {
        panel.scrollIntoView({ behavior: 'smooth' });
    }
}

/* Active scan tab: 'domain', 'file', or 'source' */
let activeScanTab = 'file';

function setScanTab(mode) {
    activeScanTab = mode;

    const tabDomain = document.getElementById('tabDomain');
    const tabFile = document.getElementById('tabFile');
    const tabSource = document.getElementById('tabSource');
    const modeDomain = document.getElementById('modeDomain');
    const modeFile = document.getElementById('modeFile');
    const modeSource = document.getElementById('modeSource');

    // Reset all tabs to inactive
    [tabDomain, tabFile, tabSource].forEach(t => {
        if (!t) return;
        t.style.background = 'rgba(255,255,255,0.04)';
        t.style.color = '#888';
        t.style.border = '1px solid rgba(255,255,255,0.1)';
    });
    // Hide all panels
    if (modeDomain) modeDomain.style.display = 'none';
    if (modeFile) modeFile.style.display = 'none';
    if (modeSource) modeSource.style.display = 'none';

    // Activate selected tab
    const activeStyle = { background: 'rgba(0,255,200,0.12)', color: '#00ffcc', border: '1px solid rgba(0,255,200,0.45)' };
    if (mode === 'domain' && tabDomain) {
        Object.assign(tabDomain.style, activeStyle);
        if (modeDomain) modeDomain.style.display = 'block';
    } else if (mode === 'file' && tabFile) {
        Object.assign(tabFile.style, activeStyle);
        if (modeFile) modeFile.style.display = 'block';
    } else if (mode === 'source' && tabSource) {
        Object.assign(tabSource.style, activeStyle);
        if (modeSource) modeSource.style.display = 'block';
    }
}

/* Preview how many subdomains are loaded from the .txt file */
function previewSubdomainFile(input) {
    const preview = document.getElementById('subdomainFilePreview');
    if (!input.files || !input.files[0]) { preview.textContent = ''; return; }
    const reader = new FileReader();
    reader.onload = function (e) {
        const lines = e.target.result.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        preview.innerHTML = `<span style="color:#00ffcc;">✔ ${lines.length} subdomain${lines.length !== 1 ? 's' : ''} loaded</span>`
            + ` &mdash; first: <code style="color:#aaa;">${lines[0] || ''}</code>`;
        input._parsedLines = lines;   // store for startScan
    };
    reader.readAsText(input.files[0]);
}

function startScan() {
    if (scanRunning) return;

    /* ── Resolve target based on active tab ── */
    let target = '';
    let subdomains = [];
    let sourceCode = null;

    if (activeScanTab === 'domain') {
        target = (document.getElementById('scanTarget').value || '').trim();
        if (!target) {
            showToast('Enter a domain or wildcard (e.g. *.example.com)', 'error');
            return;
        }
    } else if (activeScanTab === 'file') {
        const fileInput = document.getElementById('subdomainFile');
        if (!fileInput._parsedLines || !fileInput._parsedLines.length) {
            showToast('Upload a .txt file with subdomains first', 'error');
            return;
        }
        subdomains = fileInput._parsedLines;
        target = subdomains[0];
    } else if (activeScanTab === 'source') {
        sourceCode = (document.getElementById('sourceCodeInput').value || '').trim();
        if (!sourceCode) {
            showToast('Paste source code before running SAST scan', 'error');
            return;
        }
        target = 'SAST_Code';
    }

    scanRunning = true;

    const scanType = document.getElementById('scanType').value;
    const output = document.getElementById('scanOutput');
    const btn = document.getElementById('scanBtn');
    const progress = document.getElementById('scanProgress');
    const progressCircle = document.getElementById('scanProgressCircle');
    const pctLabel = document.getElementById('scanPctLabel');

    output.innerHTML = '';
    btn.innerHTML = '<span class="spinner"></span> Scanning...';
    btn.disabled = true;
    progress.style.display = 'block';
    progressCircle.style.strokeDashoffset = '263.89';
    pctLabel.innerText = '0%';

    const maxDash = 263.89;

    socket.off('scan_progress');
    socket.on('scan_progress', (data) => {
        const truePct = data.pct || 0;
        const offset = maxDash - (truePct / 100) * maxDash;
        progressCircle.style.strokeDashoffset = offset;
        pctLabel.innerText = Math.floor(truePct) + '%';
    });

    const speed = document.getElementById('scanSpeed').value;

    /* Emit to backend — pass source_code when in SAST mode */
    socket.emit('start_scan', {
        target,
        subdomains: subdomains.length ? subdomains : null,
        source_code: sourceCode,
        type: scanType,
        speed
    });

    socket.off('scan_output');
    socket.on('scan_output', (data) => {
        const line = data.data;
        output.innerHTML += colorizeLine(line);
        const terminalWrapper = output.closest('.terminal');
        if (terminalWrapper) terminalWrapper.scrollTop = terminalWrapper.scrollHeight;
    });

    socket.off('scan_complete');
    socket.on('scan_complete', (result) => {
        progressCircle.style.strokeDashoffset = '0';
        pctLabel.innerText = '100%';
        scanRunning = false;
        btn.innerHTML = '⚡ Start Scan';
        btn.disabled = false;

        currentFindings = result.findings || [];
        renderFindingsTable(currentFindings);
        document.getElementById('findingsSection').style.display = 'grid';
        document.getElementById('findingsSection').scrollIntoView({ behavior: 'smooth' });

        loadStats();
        loadActivity();
        showToast(`Scan complete — ${currentFindings.length} findings`, 'success');
    });
}

function colorizeLine(text) {
    if (text.includes('[FOUND]') || text.includes('[CRITICAL]')) {
        return `<span style="color:var(--accent-orange);">${escapeHtml(text)}</span>`;
    }
    if (text.includes('[OK]') || text.includes('100%')) {
        return `<span style="color:var(--accent-green);font-weight:700;">${escapeHtml(text)}</span>`;
    }
    if (text.includes('[WARN]')) {
        return `<span style="color:var(--accent-yellow);">${escapeHtml(text)}</span>`;
    }
    if (text.includes('[INIT]')) {
        return `<span style="color:var(--accent-cyan);">${escapeHtml(text)}</span>`;
    }
    if (text.includes('===')) {
        return `<span style="color:var(--text-muted);opacity:0.5;">${escapeHtml(text)}</span>`;
    }
    if (text.includes('[SUMMARY]')) {
        return `<span style="color:var(--accent-green);font-weight:600;">${escapeHtml(text)}</span>`;
    }
    return `<span style="color:var(--text-secondary);">${escapeHtml(text)}</span>`;
}

// ── Findings Table ─────────────────────────────────────────
function renderFindingsTable(findings) {
    const tbody = document.getElementById('findingsBody');
    if (!findings.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">No findings</td></tr>';
        return;
    }

    // Sort: Critical first
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    findings.sort((a, b) => (order[a.severity] || 5) - (order[b.severity] || 5));

    tbody.innerHTML = findings.map(f => `
    <tr class="finding-row" onclick="explainFinding('${escapeHtml(f.issue)}', '${escapeHtml(f.path || '')}')" style="cursor:pointer; transition:background 0.2s;" onmouseover="this.style.background='rgba(0,255,136,0.1)'" onmouseout="this.style.background='transparent'">
      <td style="font-family:var(--font-mono);font-size:12px;">
        ${escapeHtml(f.host)}<br>
        <span style="font-size:10px;color:var(--text-secondary);">${escapeHtml(f.path || '')}</span>
      </td>
      <td>${escapeHtml(f.issue)}</td>
      <td><span class="severity-badge severity-${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td style="font-family:var(--font-mono);">${f.cvss || '—'}</td>
      <td style="font-size:11px;color:var(--text-secondary);">${escapeHtml(f.owasp || '—')}</td>
    </tr>
  `).join('');
}

function explainFinding(issue, path) {
    const q = `Explain ${issue} and how to fix it. Attack Path was: ${path}`;
    document.getElementById('aiInput').value = q;
    askAI();
}

// ── AI Chat ────────────────────────────────────────────────
async function askAI() {
    const input = document.getElementById('aiInput');
    const q = input.value.trim();
    if (!q) return;

    const messages = document.getElementById('aiMessages');
    messages.innerHTML += `<div class="ai-message user">🧑 ${escapeHtml(q)}</div>`;
    input.value = '';
    messages.scrollTop = messages.scrollHeight;

    // Show typing indicator
    const typingId = 'typing-' + Date.now();
    messages.innerHTML += `<div class="ai-message assistant" id="${typingId}"><span class="spinner"></span> Thinking...</div>`;
    messages.scrollTop = messages.scrollHeight;

    try {
        const res = await fetch('/api/ai', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: q })
        });
        const data = await res.json();
        document.getElementById(typingId).innerHTML = '🤖 ' + escapeHtml(data.answer);
    } catch (e) {
        document.getElementById(typingId).innerHTML = '❌ Error getting response';
    }
    messages.scrollTop = messages.scrollHeight;
}

// ── PDF Export ─────────────────────────────────────────────
async function exportPDF() {
    if (!currentFindings.length) {
        showToast('No findings to export. Run a scan first.', 'error');
        return;
    }
    try {
        const res = await fetch('/api/export-pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings: currentFindings })
        });
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'SecureSphere_Report.pdf';
            a.click();
            URL.revokeObjectURL(url);
            showToast('PDF report downloaded!', 'success');
        }
    } catch (e) {
        showToast('Failed to generate PDF', 'error');
    }
}

// ── User Management ────────────────────────────────────────
function toggleUsersPanel() {
    const panel = document.getElementById('usersPanel');
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    if (panel.style.display === 'block') {
        loadUsers();
        panel.scrollIntoView({ behavior: 'smooth' });
    }
}

async function loadUsers() {
    try {
        const res = await fetch('/api/users');
        const users = await res.json();
        const tbody = document.getElementById('usersBody');
        tbody.innerHTML = users.map(u => `
      <tr>
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td style="font-family:var(--font-mono);font-size:12px;">${escapeHtml(u.email)}</td>
        <td><span class="role-badge role-${u.role}">${u.role}</span></td>
        <td style="font-size:12px;color:var(--text-muted);">${u.created_at || '—'}</td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id})">🗑 Delete</button>
        </td>
      </tr>
    `).join('');
    } catch (e) {
        console.error('Failed to load users:', e);
    }
}

function showAddUserModal() {
    document.getElementById('addUserModal').style.display = 'flex';
}

async function addUser() {
    const data = {
        username: document.getElementById('newUsername').value,
        email: document.getElementById('newEmail').value,
        password: document.getElementById('newPassword').value,
        role: document.getElementById('newRole').value,
    };
    if (!data.username || !data.email || !data.password) {
        showToast('Fill all fields', 'error');
        return;
    }
    try {
        const res = await fetch('/api/users/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const result = await res.json();
        if (result.success) {
            document.getElementById('addUserModal').style.display = 'none';
            loadUsers();
            loadStats();
            showToast(`User ${data.username} added!`, 'success');
        } else {
            showToast(result.error || 'Failed to add user', 'error');
        }
    } catch (e) {
        showToast('Error adding user', 'error');
    }
}

async function deleteUser(id) {
    if (!confirm('Delete this user?')) return;
    try {
        const res = await fetch('/api/users/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        const result = await res.json();
        if (result.success) {
            loadUsers();
            loadStats();
            showToast('User deleted', 'success');
        } else {
            showToast(result.error || 'Failed', 'error');
        }
    } catch (e) {
        showToast('Error deleting user', 'error');
    }
}

// ── Activity Log ───────────────────────────────────────────
async function loadActivity() {
    try {
        const res = await fetch('/api/activity');
        const items = await res.json();
        const list = document.getElementById('activityList');
        if (!items.length) return;

        const iconMap = {
            login: '🔑', logout: '🚪', scan: '🔍',
            ai_query: '🤖', export_pdf: '📄',
            user_add: '👤', user_delete: '🗑'
        };

        list.innerHTML = items.slice(0, 20).map(a => `
      <div class="activity-item">
        <div class="activity-icon">${iconMap[a.action] || '📌'}</div>
        <div class="activity-text">
          <strong>${escapeHtml(a.username || 'System')}</strong> — ${escapeHtml(a.action)}
          ${a.detail ? '<br><span style="font-size:11px;color:var(--text-muted);">' + escapeHtml(a.detail) + '</span>' : ''}
        </div>
        <div class="activity-time">${a.created_at || ''}</div>
      </div>
    `).join('');
    } catch (e) {
        console.error('Failed to load activity:', e);
    }
}

// ── Utilities ──────────────────────────────────────────────
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function showToast(message, type = 'success') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `${type === 'success' ? '✅' : '❌'} ${escapeHtml(message)}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// ── Custom UI Card Deck ────────────────────────────────ــــــ
function addVulnCard() {
    const nameInput = document.getElementById('vulnNameUI');
    const descInput = document.getElementById('vulnDescUI');
    const name = nameInput.value.trim() || 'Custom Threat';
    const desc = descInput.value.trim() || 'No description provided.';

    const stack = document.getElementById('vulnStackWrapper');
    const newCard = document.createElement('div');
    newCard.className = 'card';
    newCard.innerHTML = `<h4>${escapeHtml(name)}</h4><p>${escapeHtml(desc)}</p>`;

    // Add to top (so it gets nth-child styles correctly if prepended, or appended)
    stack.appendChild(newCard);

    // Auto-update height of stack based on children + padding
    const count = stack.children.length;
    stack.style.minHeight = (count * 45 + 100) + 'px';

    // Clear inputs
    nameInput.value = '';
    descInput.value = '';

    showToast('Vulnerability Card Added', 'success');
}

function toggleVulnStack() {
    const stack = document.getElementById('vulnStackWrapper');
    stack.classList.toggle('expanded');
}
