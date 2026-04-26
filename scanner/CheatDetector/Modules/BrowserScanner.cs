using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// A privacy-focused browser history scanner.
/// Instead of extracting URLs or reading the SQLite database structure (which could expose private data),
/// this module performs a raw byte-level keyword search on the browser's History files.
/// It only flags the presence of a known cheat domain, NEVER extracting the actual URL, search term, or timestamp.
/// </summary>
public class BrowserScanner
{
    private const string ModuleName = "BrowserScanner (Privacy Mode)";

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Scanning browser traces (Privacy Mode: ON)...");

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Common paths for Chromium and Firefox history files
        string[] browserHistoryPaths = {
            Path.Combine(localAppData, @"Google\Chrome\User Data\Default\History"),
            Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\History"),
            Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data\Default\History"),
            Path.Combine(localAppData, @"Opera Software\Opera Stable\History")
            // Firefox uses places.sqlite in Roaming, which is harder to locate statically without reading profiles.ini
        };

        foreach (string path in browserHistoryPaths)
        {
            if (File.Exists(path))
            {
                ScanHistoryFilePrivately(path, flags);
            }
        }

        return flags;
    }

    private void ScanHistoryFilePrivately(string historyFilePath, List<Flag> flags)
    {
        string browserName = historyFilePath.Contains("Chrome") ? "Chrome" :
                             historyFilePath.Contains("Edge") ? "Edge" :
                             historyFilePath.Contains("Brave") ? "Brave" :
                             historyFilePath.Contains("Opera") ? "Opera" : "Unknown Browser";

        // Since the History file is locked while the browser is open, we must copy it to a temp file
        string tempFile = Path.Combine(Path.GetTempPath(), $"tmp_hist_{Guid.NewGuid():N}.dat");

        try
        {
            File.Copy(historyFilePath, tempFile, true);

            // Read raw bytes and perform a simple ASCII/UTF-8 string search
            // We do NOT parse the SQLite DB to respect privacy and avoid extracting full URLs.
            byte[] fileBytes = File.ReadAllBytes(tempFile);
            string rawContent = System.Text.Encoding.ASCII.GetString(fileBytes).ToLowerInvariant();

            foreach (string domain in CheatSignatures.SuspiciousDomains)
            {
                if (rawContent.Contains(domain.ToLowerInvariant()))
                {
                    flags.Add(new Flag
                    {
                        Module = ModuleName,
                        Severity = Severity.Low,
                        Title = "Cheat Domain Found in Browser Data",
                        Description = $"A trace of '{domain}' was found in {browserName}. (Privacy Note: Exact URLs and timestamps are not extracted or transmitted).",
                        Evidence = $"Domain: {domain} | Browser: {browserName}"
                    });
                }
            }
        }
        catch
        {
            // Ignore access errors
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                try { File.Delete(tempFile); } catch { /* Cleanup best effort */ }
            }
        }
    }
}
