document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadRecentReports();

    const searchBtn = document.getElementById('searchBtn');
    const searchInput = document.getElementById('searchInput');
    const searchError = document.getElementById('searchError');

    searchBtn.addEventListener('click', handleSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSearch();
    });

    function handleSearch() {
        const id = searchInput.value.trim();
        if (!id) return;
        
        searchError.style.display = 'none';
        
        // Check if report exists before redirecting
        fetch(`/api/reports/${id}`)
            .then(res => {
                if (!res.ok) throw new Error('Not found');
                window.location.href = `report.html?id=${id}`;
            })
            .catch(() => {
                searchError.style.display = 'block';
            });
    }

    function loadStats() {
        fetch('/api/stats')
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
                <div class="stat-value">${stats.totalScans}</div>
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
                <div class="stat-value" style="color: var(--primary-color);">${stats.last24h}</div>
                <div class="stat-label">Scans (24h)</div>
            </div>
        `;
    }

    function loadRecentReports() {
        fetch('/api/reports?limit=15')
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

            return `
                <tr onclick="window.location.href='report.html?id=${r.id}'">
                    <td><strong>${r.id}</strong></td>
                    <td>${r.username} <span style="color: var(--text-secondary); font-size: 0.85em;">@${r.hostname}</span></td>
                    <td style="color: var(--text-secondary);">${date}</td>
                    <td>
                        <span style="color: var(--severity-high); margin-right: 8px;"><i class="fa-solid fa-flag"></i> ${r.high_count}</span>
                        <span style="color: var(--severity-medium);"><i class="fa-solid fa-flag"></i> ${r.medium_count}</span>
                    </td>
                    <td><span class="badge ${badgeClass}">${r.verdict}</span></td>
                </tr>
            `;
        }).join('');
    }
});
