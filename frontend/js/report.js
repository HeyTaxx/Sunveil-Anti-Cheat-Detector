document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const reportId = urlParams.get('id');

    if (!reportId) {
        showError();
        return;
    }

    fetchReport(reportId);

    function fetchReport(id) {
        fetch(`/api/reports/${id}`)
            .then(res => {
                if (!res.ok) throw new Error('Report not found');
                return res.json();
            })
            .then(data => {
                if (data.success && data.report) {
                    renderReport(data.report);
                } else {
                    showError();
                }
            })
            .catch(err => {
                console.error(err);
                showError();
            });
    }

    function showError() {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('errorState').style.display = 'block';
    }

    function renderReport(report) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('reportContent').style.display = 'block';

        const sys = report.systemInfo || {};
        const sum = report.summary || {};

        // Header info
        document.getElementById('reportId').textContent = report.reportId;
        document.getElementById('playerName').textContent = sys.username || 'Unknown';
        document.getElementById('scanTime').textContent = new Date(report.timestamp).toLocaleString();
        document.getElementById('scanDuration').textContent = report.scanDuration || 'N/A';
        document.getElementById('scanMode').textContent = (report.scanMode || 'quick').toUpperCase() + ' SCAN';

        // System info
        document.getElementById('hostname').textContent = sys.hostname || 'N/A';
        document.getElementById('username').textContent = sys.username || 'N/A';
        document.getElementById('osVersion').textContent = sys.operatingSystem || sys.os || 'N/A';
        document.getElementById('hwid').textContent = sys.hwid || 'N/A';
        document.getElementById('cpuName').textContent = sys.cpuName || 'N/A';
        document.getElementById('ramTotal').textContent = sys.ramTotalGb ? `${sys.ramTotalGb} GB` : 'N/A';

        // Verdict Badge
        const verdict = sum.verdict || 'UNKNOWN';
        const vBadge = document.getElementById('verdictBadge');
        vBadge.textContent = verdict;
        vBadge.className = 'verdict-large'; // reset
        if (verdict === 'CLEAN') vBadge.classList.add('verdict-clean-bg');
        else if (verdict === 'SUSPICIOUS') vBadge.classList.add('verdict-suspicious-bg');
        else if (verdict === 'FLAGGED') vBadge.classList.add('verdict-flagged-bg');

        // Risk Meter
        const riskFill = document.getElementById('riskFill');
        const riskLabel = document.getElementById('riskLabel');
        let riskPercent = 5;
        let riskClass = 'risk-low';
        let rLabel = 'Low / Clean';

        if (verdict === 'FLAGGED') {
            riskPercent = 95; riskClass = 'risk-high'; rLabel = 'Critical / Flagged';
        } else if (verdict === 'SUSPICIOUS') {
            riskPercent = sum.highCount > 0 ? 75 : 50;
            riskClass = 'risk-medium'; rLabel = 'Elevated / Suspicious';
        } else if (sum.totalFlags > 0) {
            riskPercent = 25; rLabel = 'Low / Notice';
        }
        
        setTimeout(() => {
            riskFill.style.width = `${riskPercent}%`;
            riskFill.className = `risk-meter-fill ${riskClass}`;
            riskLabel.textContent = rLabel;
        }, 100);

        // Flags
        document.getElementById('totalFlagsCount').textContent = `${sum.totalFlags || 0} Flags`;
        
        const flagsList = document.getElementById('flagsList');
        const noFlagsState = document.getElementById('noFlagsState');

        if (!report.flags || report.flags.length === 0) {
            noFlagsState.style.display = 'block';
        } else {
            const sevOrder = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            const sortedFlags = [...report.flags].sort((a, b) =>
                (sevOrder[b.severity?.toUpperCase()] || 0) - (sevOrder[a.severity?.toUpperCase()] || 0)
            );
            const hwid = sys.hwid || null;

            flagsList.innerHTML = sortedFlags.map(f => {
                const sev = f.severity?.toUpperCase() || 'LOW';
                let badgeClass = 'badge-low';
                let iconColor = 'var(--severity-low)';
                let borderColor = 'var(--severity-low)';
                if (sev === 'HIGH')   { badgeClass = 'badge-high';   iconColor = 'var(--severity-high)';   borderColor = 'var(--severity-high)'; }
                if (sev === 'MEDIUM') { badgeClass = 'badge-medium'; iconColor = 'var(--severity-medium)'; borderColor = 'var(--severity-medium)'; }

                return `
                    <div class="flag-item" style="border-left: 3px solid ${borderColor};">
                        <div class="flag-item-header">
                            <i class="fa-solid fa-triangle-exclamation" style="color: ${iconColor};"></i>
                            <h4>${escapeHtml(f.title || 'Suspicious Finding')}</h4>
                            <span class="badge ${badgeClass}">${sev}</span>
                        </div>
                        <p>${escapeHtml(f.description || '')}</p>
                        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
                            <i class="fa-solid fa-cube"></i> Module: ${escapeHtml(f.module || 'Unknown')}
                        </div>
                        ${renderEvidenceBox(f, hwid)}
                    </div>
                `;
            }).join('');
        }
    }

    function renderEvidenceBox(f, hwid) {
        if (!f.evidence && !f.matchedSignature) return '';

        const typeIcons = {
            'JAR_PACKAGE': '<i class="fa-solid fa-box-archive"></i> JAR Package Scan',
            'JAR_ENTRY':   '<i class="fa-solid fa-file-zipper"></i> JAR Entry Match',
            'RAM_STRING':  '<i class="fa-solid fa-memory"></i> RAM String Match',
            'PROCESS_NAME':'<i class="fa-solid fa-gear"></i> Process Detection',
            'FILE_PATH':   '<i class="fa-solid fa-folder-open"></i> File System',
            'REGISTRY':    '<i class="fa-solid fa-key"></i> Registry',
            'PREFETCH':    '<i class="fa-solid fa-clock-rotate-left"></i> Prefetch'
        };
        const typeLabel = f.evidenceType ? (typeIcons[f.evidenceType] || f.evidenceType) : '<i class="fa-solid fa-magnifying-glass"></i> Evidence';

        return `
            <div class="evidence-box">
                <div class="evidence-box-header">
                    <span class="evidence-type-badge">${typeLabel}</span>
                    ${f.matchedSignature ? `<span class="evidence-match-label">Matched: <code class="evidence-match-code">${escapeHtml(f.matchedSignature)}</code></span>` : ''}
                </div>
                ${f.evidence ? `<div class="evidence-detail">${escapeHtml(f.evidence)}</div>` : ''}
                ${hwid ? `<div class="evidence-hwid"><i class="fa-solid fa-fingerprint"></i> HWID Lock: <code>${escapeHtml(hwid)}</code></div>` : ''}
            </div>
        `;
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
