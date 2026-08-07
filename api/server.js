require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const database = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || '10mb';
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour session expiry
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minute rate limit window
const MAX_LOGIN_ATTEMPTS = 10; // max attempts per IP in window

// Initialize database
database.init();

// ═══════════════════════════════════════════════
//  SECURITY MIDDLEWARE
// ═══════════════════════════════════════════════

// Security headers (Helmet-equivalent without dependency)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.removeHeader('X-Powered-By');
    next();
});

// CORS — restrict to configured origins (default: same-origin only)
const corsOrigin = process.env.CORS_ORIGIN || '';
if (corsOrigin && corsOrigin !== '*') {
    app.use(cors({ origin: corsOrigin.split(',').map(o => o.trim()), credentials: true }));
} else if (corsOrigin === '*') {
    // Explicitly opted-in to open CORS (development only)
    app.use(cors());
} else {
    // No CORS header = same-origin only (most secure default)
    app.use(cors({ origin: false }));
}

app.use(express.json({ limit: MAX_BODY_SIZE }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ═══════════════════════════════════════════════
//  ADMIN SECURITY
// ═══════════════════════════════════════════════

// Active admin sessions with expiry timestamps
const activeSessions = new Map(); // token -> { createdAt: Date }

// Login rate limiting (in-memory, per IP)
const loginAttempts = new Map(); // ip -> { count, windowStart }

// Periodic session cleanup (every 10 minutes)
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of activeSessions) {
        if (now - session.createdAt > SESSION_TTL_MS) {
            activeSessions.delete(token);
        }
    }
}, 10 * 60 * 1000);

// Admin Authentication Middleware
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token && activeSessions.has(token)) {
        const session = activeSessions.get(token);
        if (Date.now() - session.createdAt > SESSION_TTL_MS) {
            activeSessions.delete(token);
            return res.status(401).json({ success: false, error: 'Session expired' });
        }
        next();
    } else {
        res.status(401).json({
            success: false,
            error: 'Unauthorized'
        });
    }
}

// Rate limiting check for login
function checkLoginRateLimit(ip) {
    const now = Date.now();
    const record = loginAttempts.get(ip);
    if (!record || (now - record.windowStart > LOGIN_WINDOW_MS)) {
        loginAttempts.set(ip, { count: 1, windowStart: now });
        return true;
    }
    record.count++;
    if (record.count > MAX_LOGIN_ATTEMPTS) {
        return false;
    }
    return true;
}

/**
 * POST /api/login — Authenticate admin password.
 * Returns session token.
 */
app.post('/api/login', (req, res) => {
    try {
        // Rate limiting
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
        if (!checkLoginRateLimit(clientIp)) {
            return res.status(429).json({
                success: false,
                error: 'Too many login attempts. Please try again later.'
            });
        }

        const { password } = req.body;
        const adminPassword = process.env.ADMIN_PASSWORD;

        if (!adminPassword) {
            console.error('[API] CRITICAL: ADMIN_PASSWORD environment variable is not set!');
            return res.status(503).json({
                success: false,
                error: 'Server configuration error. Contact administrator.'
            });
        }

        if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
            return res.status(400).json({
                success: false,
                error: 'Invalid password format.'
            });
        }

        // Constant-time comparison to prevent timing attacks
        const pwBuf = Buffer.from(password);
        const adminBuf = Buffer.from(adminPassword);
        if (pwBuf.length === adminBuf.length && crypto.timingSafeEqual(pwBuf, adminBuf)) {
            const token = crypto.randomBytes(32).toString('hex');
            activeSessions.set(token, { createdAt: Date.now() });
            res.json({
                success: true,
                token: token
            });
        } else {
            // Fixed-delay response to mitigate timing attacks
            setTimeout(() => {
                res.status(401).json({
                    success: false,
                    error: 'Invalid administrator password.'
                });
            }, 200 + Math.random() * 300);
        }
    } catch (err) {
        console.error('[API] Login error:', err.message);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════
//  API ROUTES
// ═══════════════════════════════════════════════

/**
 * POST /api/reports — Receive a scan report from the client scanner.
 * Returns the generated report URL. (Keep public for the scanner clients)
 */
app.post('/api/reports', (req, res) => {
    try {
        const report = req.body;

        if (!report || !report.reportId || typeof report.reportId !== 'string') {
            return res.status(400).json({
                success: false,
                error: 'Invalid report: missing or invalid reportId'
            });
        }

        // Validate reportId format (alphanumeric, dashes, max 64 chars)
        if (!/^[A-Za-z0-9\-]{1,64}$/.test(report.reportId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid reportId format'
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

        const reportUrl = `${req.protocol}://${req.get('host')}/report.html?id=${encodeURIComponent(report.reportId)}`;

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
 * GET /api/reports/:id — Get a single report by ID. (Admin only)
 */
app.get('/api/reports/:id', requireAdmin, (req, res) => {
    try {
        // Validate ID format to prevent injection
        const id = req.params.id;
        if (typeof id !== 'string' || !/^[A-Za-z0-9\-]{1,64}$/.test(id)) {
            return res.status(400).json({ success: false, error: 'Invalid report ID format' });
        }

        const report = database.getReport(id);

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
 * GET /api/reports — List recent reports with pagination. (Admin only)
 * Query params: ?limit=50&offset=0
 */
app.get('/api/reports', requireAdmin, (req, res) => {
    try {
        const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 100);
        const offset = Math.max(parseInt(req.query.offset) || 0, 0);
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
 * GET /api/stats — Aggregated scan statistics. (Admin only)
 */
app.get('/api/stats', requireAdmin, (req, res) => {
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
