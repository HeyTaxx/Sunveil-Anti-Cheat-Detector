CREATE TABLE IF NOT EXISTS `reports` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `report_id` VARCHAR(50) NOT NULL UNIQUE,
    `player_name` VARCHAR(100) NOT NULL,
    `hwid` VARCHAR(64) NOT NULL,
    `source` VARCHAR(50) NOT NULL, -- e.g., RAM, Disk, Registry
    `signature_match` VARCHAR(255) NOT NULL,
    `severity` VARCHAR(20) NOT NULL, -- e.g., High, Medium, Low
    `evidence_dump` TEXT NOT NULL,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hwid ON `reports` (`hwid`);
CREATE INDEX idx_severity ON `reports` (`severity`);
