const fs = require('fs');
const crypto = require('crypto');

const clients = [
    "Meteor Client", "Wurst Client", "Aristois", "LiquidBounce", 
    "Vape v4", "Vape Lite", "Impact", "Future", "Inertia", 
    "Kami Blue", "Salhack", "Rusherhack", "Sigma", "Azura", 
    "FDPClient", "Novoline", "Rise", "Moon", "Exhibition", "Drip"
];

const db = {
    "_comment": "SUNVEIL ANTI-CHEAT: CRYPTOGRAPHIC SIGNATURE DATABASE",
    "_instructions": "Add the SHA-256 hash (lowercase, no hyphens) of the target .jar file as the key. THESE ARE MOCK HASHES FOR TESTING SCALABILITY."
};

let count = 0;

// Generate 50 versions for each of the 20 clients = 1000 signatures
for (const client of clients) {
    for (let version = 1; version <= 50; version++) {
        // Create a fake hash by hashing the client name + version + salt
        const hash = crypto.createHash('sha256').update(`${client}-v${version}-saltXYZ`).digest('hex');
        db[hash] = `${client} v1.${version}.0`;
        count++;
    }
}

// Add a few specific known ones
db["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] = "Empty File (Test)";

fs.writeFileSync('signatures.json', JSON.stringify(db, null, 2));
console.log(`Successfully generated signatures.json with ${count} mock signatures.`);
