/**
 * Build script: Copies frontend files into api/public for Railway deployment.
 * In production, Railway sets the root directory to /api,
 * so the ../frontend path doesn't exist. This script copies
 * everything into a local ./public folder during the build step.
 */
const fs = require('fs');
const path = require('path');

const sourceDir = path.resolve(__dirname, '..', '..', 'frontend');
const targetDir = path.resolve(__dirname, '..', 'public');

function copyDirRecursive(src, dest) {
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }

    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);

        if (entry.isDirectory()) {
            copyDirRecursive(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

if (fs.existsSync(sourceDir)) {
    console.log(`[Build] Copying frontend from ${sourceDir} to ${targetDir}...`);
    copyDirRecursive(sourceDir, targetDir);
    console.log('[Build] Frontend copied successfully.');
} else {
    console.log('[Build] No frontend directory found — skipping copy (Railway root might already include it).');
}
