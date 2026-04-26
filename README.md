# Sunveil SMP Anti-Cheat Detector

An advanced, highly-invasive forensic anti-cheat system designed specifically for the Sunveil SMP network. This system goes beyond traditional file scanning by utilizing deep cryptographic signature matching, memory analysis, and registry forensics to catch sophisticated Minecraft cheat clients.

## System Architecture

The project is divided into three core components:

1. **C# Forensic Scanner (`/scanner`)**
   - **Deep Signature Scan:** Matches `.jar` and `.zip` files against a database of 1000+ known cheat hashes (SHA-256).
   - **Full Disk Analysis:** Recursively scans fixed drives, skipping protected Windows directories to maintain performance.
   - **RAM Forensics:** Scans active `javaw.exe` memory for known cheat module strings and class leaks.
   - **Registry Forensics:** Analyzes Windows artifacts (`UserAssist`, `Prefetch`, `AppCompatCache`) to find traces of deleted or archived cheats.
   - **Privacy-Preserving Browser Scan:** Scans browser history files locally for cheat-related domains without extracting personal browsing data or timestamps.
   - **HWID Generation:** Generates a unique, persistent hardware ID (Mainboard UUID + CPU ID) to prevent ban evasion.

2. **PHP Telemetry API (`/api_php`)**
   - Securely receives JSON forensic reports from the C# client.
   - Validates payloads using an `X-API-Key` to prevent unauthorized data injection.
   - Stores telemetry securely in a MySQL database.

3. **Cyber-Blue Web Dashboard (`/frontend`)**
   - A modern, responsive admin dashboard built with Tailwind CSS.
   - Features smooth CSS animations, glassmorphism UI, and real-time auto-refreshing.
   - Displays a detailed "Evidence Box" containing raw forensic dumps for staff review.

## Requirements

- **Scanner:** Windows 10/11, .NET 8.0 SDK
- **Backend:** PHP 8.0+, MySQL/MariaDB
- **Frontend:** Modern web browser

## Building the Scanner

1. Navigate to the scanner directory:
   ```bash
   cd scanner/CheatDetector
   ```
2. Build the executable:
   ```bash
   dotnet build -c Release
   ```
3. The executable will be located in `bin/Release/net8.0-windows/`.

## Running the Scanner

Run the compiled executable. You can pass the API key to automatically upload the report to the dashboard:
```bash
CheatDetector.exe --api-key YOUR_SECRET_API_KEY
```

To run a deep scan (includes memory strings, JVM args, and DLL injections):
```bash
CheatDetector.exe --deep --api-key YOUR_SECRET_API_KEY
```

## Setup Backend & Dashboard

1. Upload the contents of the `/api_php` folder to your web server (e.g., `cheat.sunveil.net`).
2. Rename `db_config.php.template` to `db_config.php` and fill in your database credentials and API key.
3. Import `schema.sql` into your MySQL database to create the required tables.
4. Upload `admin_v2.html` from the `/frontend` directory to your web root.

## License

This software is strictly proprietary and intended for private use by the Sunveil SMP administration only. See the `LICENSE` file for full details.
