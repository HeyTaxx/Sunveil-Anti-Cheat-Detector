using System.IO;
using Microsoft.Win32;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Forensic module that specifically detects attempts to evade scanning by deleting cheat files,
/// clearing directories, or wiping software right before executing the diagnostic scan.
/// </summary>
public class EvasionDetector
{
    private const string ModuleName = "EvasionDetector";

    public List<Flag> Scan(Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Running Forensic Anti-Evasion & Deletion Analysis...");

        CheckDeletedPrefetchExecutability(flags, onItemScanned);
        CheckUserAssistDeletedFiles(flags, onItemScanned);
        CheckDeletedBrowserDownloads(flags, onItemScanned);

        return flags;
    }

    /// <summary>
    /// Checks Windows Prefetch history for executables matching cheat signatures where the source EXE was removed.
    /// </summary>
    private void CheckDeletedPrefetchExecutability(List<Flag> flags, Action<string>? onItemScanned)
    {
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            var pfFiles = Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
            foreach (var pf in pfFiles)
            {
                onItemScanned?.Invoke($"Checking Prefetch trace: {Path.GetFileName(pf)}");
                string pfName = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();

                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (pfName.Contains(cheat.ToLowerInvariant()))
                    {
                        DateTime lastExec = File.GetLastWriteTimeUtc(pf);
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.High,
                            Title = "Recently Deleted Cheat Found in Execution History",
                            Description = $"Cheat client '{cheat}' was executed on this PC (Prefetch Trace: {Path.GetFileName(pf)} on {lastExec:yyyy-MM-dd HH:mm} UTC). The executable was deleted prior to scanning.",
                            Evidence = $"Prefetch File: {pf} | Last Execution: {lastExec:u} | Match: {cheat}",
                            MatchedSignature = cheat,
                            EvidenceType = "DELETED_PREFETCH_TRACE"
                        });
                    }
                }
            }
        }
        catch { /* Admin permissions check */ }
    }

    /// <summary>
    /// Analyzes UserAssist registry keys for entries referencing cheat paths that no longer exist on disk.
    /// </summary>
    private void CheckUserAssistDeletedFiles(List<Flag> flags, Action<string>? onItemScanned)
    {
        string[] userAssistGuids = {
            "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
        };
        const string basePath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var hkcu = Registry.CurrentUser;
            foreach (string guid in userAssistGuids)
            {
                string keyPath = $@"{basePath}\{guid}\Count";
                using var countKey = hkcu.OpenSubKey(keyPath);
                if (countKey == null) continue;

                foreach (string valName in countKey.GetValueNames())
                {
                    string decoded = DecodeRot13(valName).ToLowerInvariant();
                    onItemScanned?.Invoke($"Checking UserAssist entry: {decoded}");

                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (decoded.Contains(cheat.ToLowerInvariant()))
                        {
                            bool exists = File.Exists(decoded) || Directory.Exists(decoded);
                            if (!exists)
                            {
                                flags.Add(new Flag
                                {
                                    Module = ModuleName,
                                    Severity = Severity.High,
                                    Title = "Cheat Execution in Explorer History (File Removed Prior to Scan)",
                                    Description = $"Explorer execution history proves '{cheat}' was launched ({decoded}). The original file no longer exists at this location (scan evasion attempt).",
                                    Evidence = $"Decoded UserAssist Path: {decoded} | Exists: False | Cheat: {cheat}",
                                    MatchedSignature = cheat,
                                    EvidenceType = "USERASSIST_DELETED_EXE"
                                });
                            }
                        }
                    }
                }
            }
        }
        catch { /* Registry access error handling */ }
    }

    /// <summary>
    /// Checks browser download history traces for downloaded cheat artifacts that have been deleted.
    /// </summary>
    private void CheckDeletedBrowserDownloads(List<Flag> flags, Action<string>? onItemScanned)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");

        string[] browserPaths = {
            Path.Combine(localAppData, @"Google\Chrome\User Data\Default\History"),
            Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\History"),
            Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data\Default\History")
        };

        foreach (string historyDb in browserPaths)
        {
            if (!File.Exists(historyDb)) continue;
            onItemScanned?.Invoke($"Scanning browser history: {Path.GetFileName(Path.GetDirectoryName(historyDb))}");

            try
            {
                using var stream = new FileStream(historyDb, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream);
                string content = reader.ReadToEnd().ToLowerInvariant();

                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (content.Contains(cheat.ToLowerInvariant()))
                    {
                        string expectedFilePath = Path.Combine(downloadsPath, $"{cheat}.jar");
                        string expectedZipPath = Path.Combine(downloadsPath, $"{cheat}.zip");
                        string expectedExePath = Path.Combine(downloadsPath, $"{cheat}.exe");

                        bool filePresent = File.Exists(expectedFilePath) || File.Exists(expectedZipPath) || File.Exists(expectedExePath);

                        if (!filePresent)
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName,
                                Severity = Severity.Medium,
                                Title = "Downloaded & Deleted Cheat Trace in Browser History",
                                Description = $"Browser history contains a download trace for '{cheat}', but the file was removed from the Downloads directory.",
                                Evidence = $"History Database: {historyDb} | Match: {cheat} | File in Downloads: False",
                                MatchedSignature = cheat,
                                EvidenceType = "BROWSER_DOWNLOAD_DELETED"
                            });
                        }
                    }
                }
            }
            catch { /* File lock / access error handling */ }
        }
    }

    private static string DecodeRot13(string input)
    {
        char[] result = new char[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (c >= 'a' && c <= 'z') result[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') result[i] = (char)('A' + (c - 'A' + 13) % 26);
            else result[i] = c;
        }
        return new string(result);
    }
}
