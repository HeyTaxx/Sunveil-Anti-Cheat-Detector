document.addEventListener('DOMContentLoaded', () => {
    // Auth Check
    const token = sessionStorage.getItem('admin_token');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    // Set up Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            sessionStorage.removeItem('admin_token');
            window.location.href = 'login.html';
        });
    }

    // Load initial data
    loadStats();
    loadRecentReports();

    const searchBtn = document.getElementById('searchBtn');
    const searchInput = document.getElementById('searchInput');
    const searchError = document.getElementById('searchError');

    searchBtn.addEventListener('click', handleSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSearch();
    });

    function handleAuthError(res) {
        if (res.status === 401) {
            sessionStorage.removeItem('admin_token');
            window.location.href = 'login.html';
            throw new Error('Session expired or unauthorised access.');
        }
        return res;
    }

    function handleSearch() {
        const id = searchInput.value.trim();
        if (!id) return;
        
        searchError.style.display = 'none';
        
        // Check if report exists before redirecting
        fetch(`/api/reports/${id}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(handleAuthError)
            .then(res => {
                if (!res.ok) throw new Error('Not found');
                window.location.href = `report.html?id=${id}`;
            })
            .catch(() => {
                searchError.style.display = 'block';
            });
    }

    function loadStats() {
        fetch('/api/stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(handleAuthError)
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    renderStats(data.stats);
                }
            })
            .catch(err => console.error('Error loading stats:', err));
    }

    function renderStats(stats) {
        const statsGrid = document.getElementById('statsGrid');
        statsGrid.innerHTML = `
            <div class="stat-card">
                <div class="stat-value" style="background: linear-gradient(135deg, #fff, #9ca3af); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">${stats.totalScans}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--verdict-clean);">${stats.cleanPercent}%</div>
                <div class="stat-label">Clean Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--verdict-flagged);">${stats.flaggedCount}</div>
                <div class="stat-label">Flagged Systems</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent-2);">${stats.last24h}</div>
                <div class="stat-label">Scans (24h)</div>
            </div>
        `;
    }

    function loadRecentReports() {
        fetch('/api/reports?limit=15', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(handleAuthError)
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    renderReports(data.reports);
                }
            })
            .catch(err => {
                console.error('Error loading reports:', err);
                document.getElementById('reportsList').innerHTML = `<tr><td colspan="5" class="empty-state">Error loading reports. Make sure the API is running.</td></tr>`;
            });
    }

    function renderReports(reports) {
        const tbody = document.getElementById('reportsList');
        
        if (!reports || reports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No recent scans found.</td></tr>`;
            return;
        }

        tbody.innerHTML = reports.map(r => {
            const date = new Date(r.created_at).toLocaleString();
            let badgeClass = 'badge-clean';
            if (r.verdict === 'SUSPICIOUS') badgeClass = 'badge-suspicious';
            if (r.verdict === 'FLAGGED') badgeClass = 'badge-flagged';

            const safeId = escapeHtml(r.id);
            const safeVerdict = escapeHtml(r.verdict);

            return `
                <tr onclick="window.location.href='report.html?id=${encodeURIComponent(r.id)}'">
                    <td><strong>${safeId}</strong></td>
                    <td>${escapeHtml(r.username)} <span style="color: var(--text-secondary); font-size: 0.85em;">@${escapeHtml(r.hostname)}</span></td>
                    <td style="color: var(--text-secondary);">${date}</td>
                    <td>
                        <span style="color: var(--severity-high); margin-right: 12px; font-weight: 500;"><i class="fa-solid fa-flag"></i> ${parseInt(r.high_count) || 0}</span>
                        <span style="color: var(--severity-medium); font-weight: 500;"><i class="fa-solid fa-flag"></i> ${parseInt(r.medium_count) || 0}</span>
                    </td>
                    <td><span class="badge ${badgeClass}">${safeVerdict}</span></td>
                </tr>
            `;
        }).join('');
    }

    function escapeHtml(unsafe) {
        return (unsafe || '').toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }
});
