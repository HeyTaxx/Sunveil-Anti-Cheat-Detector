const fs = require('fs');
const path = require('path');

const DB_PATH = process.env.DB_PATH
    ? path.resolve(__dirname, process.env.DB_PATH)
    : path.join(__dirname, 'cheatdetector_db.json');
let reports = [];

function init() {
    if (fs.existsSync(DB_PATH)) {
        try {
            const data = fs.readFileSync(DB_PATH, 'utf8');
            reports = JSON.parse(data);
            console.log(`[DB] Database loaded from ${DB_PATH} (${reports.length} reports)`);
        } catch (err) {
            console.error('[DB] Error reading database file. Starting fresh.', err.message);
            reports = [];
        }
    } else {
        console.log(`[DB] Created new database at ${DB_PATH}`);
        saveDb();
    }
}

function saveDb() {
    fs.writeFileSync(DB_PATH, JSON.stringify(reports, null, 2), 'utf8');
}

function insertReport(report) {
    const sys = report.systemInfo || {};
    const sum = report.summary || {};

    const dbRecord = {
        id: report.reportId,
        created_at: new Date().toISOString(),
        hostname: sys.hostname || 'Unknown',
        username: sys.username || 'Unknown',
        os_version: sys.os || sys.operatingSystem || 'Unknown',
        hwid: sys.hwid || 'Unknown',
        cpu_name: sys.cpuName || 'Unknown',
        ram_total_gb: sys.ramTotalGb || 0,
        scan_mode: report.scanMode || 'quick',
        scan_duration: report.scanDuration || '0s',
        total_flags: sum.totalFlags || 0,
        high_count: sum.highCount || 0,
        medium_count: sum.mediumCount || 0,
        low_count: sum.lowCount || 0,
        verdict: sum.verdict || 'CLEAN',
        parsed: report
    };

    reports.unshift(dbRecord); // Add to beginning (newest first)
    saveDb();
}

function getReport(id) {
    return reports.find(r => r.id === id);
}

function getReports(limit = 50, offset = 0) {
    return reports.slice(offset, offset + limit);
}

function getStats() {
    const total = reports.length;
    const clean = reports.filter(r => r.verdict === 'CLEAN').length;
    const suspicious = reports.filter(r => r.verdict === 'SUSPICIOUS').length;
    const flagged = reports.filter(r => r.verdict === 'FLAGGED').length;
    
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recent = reports.filter(r => new Date(r.created_at) >= oneDayAgo).length;

    return {
        totalScans: total,
        cleanCount: clean,
        suspiciousCount: suspicious,
        flaggedCount: flagged,
        last24h: recent,
        cleanPercent: total > 0 ? Math.round((clean / total) * 100) : 0
    };
}

module.exports = { init, insertReport, getReport, getReports, getStats };
