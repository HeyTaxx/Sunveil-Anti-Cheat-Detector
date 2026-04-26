require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const database = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || '10mb';

// Initialize database
database.init();

// Middleware
app.use(cors());
app.use(express.json({ limit: MAX_BODY_SIZE }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ═══════════════════════════════════════════════
//  API ROUTES
// ═══════════════════════════════════════════════

/**
 * POST /api/reports — Receive a scan report from the client scanner.
 * Returns the generated report URL.
 */
app.post('/api/reports', (req, res) => {
    try {
        const report = req.body;

        if (!report || !report.reportId) {
            return res.status(400).json({
                success: false,
                error: 'Invalid report: missing reportId'
            });
        }

        // Check for duplicate report ID
        const existing = database.getReport(report.reportId);
        if (existing) {
            return res.status(409).json({
                success: false,
                error: 'Report with this ID already exists',
                reportId: report.reportId
            });
        }

        database.insertReport(report);

        const reportUrl = `${req.protocol}://${req.get('host')}/report.html?id=${report.reportId}`;

        console.log(`[API] Report ${report.reportId} saved — Verdict: ${report.summary?.verdict || 'UNKNOWN'}`);

        res.status(201).json({
            success: true,
            reportId: report.reportId,
            reportUrl: reportUrl
        });
    } catch (err) {
        console.error('[API] Error saving report:', err.message);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

/**
 * GET /api/reports/:id — Get a single report by ID.
 */
app.get('/api/reports/:id', (req, res) => {
    try {
        const report = database.getReport(req.params.id);

        if (!report) {
            return res.status(404).json({
                success: false,
                error: 'Report not found'
            });
        }

        res.json({
            success: true,
            report: report.parsed || report
        });
    } catch (err) {
        console.error('[API] Error fetching report:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/**
 * GET /api/reports — List recent reports with pagination.
 * Query params: ?limit=50&offset=0
 */
app.get('/api/reports', (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const offset = parseInt(req.query.offset) || 0;
        const reports = database.getReports(limit, offset);

        res.json({
            success: true,
            count: reports.length,
            reports: reports
        });
    } catch (err) {
        console.error('[API] Error listing reports:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

/**
 * GET /api/stats — Aggregated scan statistics.
 */
app.get('/api/stats', (req, res) => {
    try {
        const stats = database.getStats();
        res.json({ success: true, stats: stats });
    } catch (err) {
        console.error('[API] Error fetching stats:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════

app.listen(PORT, () => {
    console.log(`\n══════════════════════════════════════════════════`);
    console.log(`  CHEAT DETECTOR API SERVER v1.0`);
    console.log(`  Running on http://localhost:${PORT}`);
    console.log(`  Frontend:  http://localhost:${PORT}/index.html`);
    console.log(`══════════════════════════════════════════════════\n`);
});
