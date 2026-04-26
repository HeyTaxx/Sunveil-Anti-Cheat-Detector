using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Analyzes Windows Prefetch files to detect previously executed cheat clients.
/// Prefetch files are stored in C:\Windows\Prefetch\ and track application execution history.
/// </summary>
public class PrefetchAnalyzer
{
    private const string ModuleName = "PrefetchAnalyzer";
    private static readonly string PrefetchPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    /// <summary>
    /// Scans Prefetch directory for .pf files matching known cheat client names.
    /// </summary>
    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Analyzing Prefetch files...");

        if (!Directory.Exists(PrefetchPath))
        {
            Console.WriteLine("  [!] Prefetch directory not found (may require admin privileges).");
            return flags;
        }

        try
        {
            var prefetchFiles = Directory.GetFiles(PrefetchPath, "*.pf", SearchOption.TopDirectoryOnly);
            Console.WriteLine($"  [*] Found {prefetchFiles.Length} Prefetch files.");

            foreach (var file in prefetchFiles)
            {
                string fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                DateTime lastWriteTime = File.GetLastWriteTimeUtc(file);
                long fileSize = new FileInfo(file).Length;

                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (fileName.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.Medium,
                            Title = "Cheat Client Found in Prefetch History",
                            Description = $"Prefetch file '{Path.GetFileName(file)}' matches known cheat '{cheat}'. " +
                                          $"This indicates the application was executed on this system.",
                            Evidence = $"File: {file}, Last Modified: {lastWriteTime:u}, Size: {fileSize} bytes, Match: '{cheat}'"
                        });
                    }
                }
            }

            // Also check for suspicious Java-related prefetch entries
            // that might indicate cheat client launchers
            foreach (var file in prefetchFiles)
            {
                string fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                // Check for cheat launcher executables
                string[] suspiciousLaunchers = { "cheatengine", "processhacker", "x64dbg", "ollydbg",
                                                  "dnspy", "de4dot", "injector", "dllinjector" };

                foreach (string launcher in suspiciousLaunchers)
                {
                    if (fileName.Contains(launcher))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.Medium,
                            Title = "Suspicious Tool Found in Prefetch",
                            Description = $"Prefetch entry for '{Path.GetFileName(file)}' detected. " +
                                          $"This tool is commonly used for game memory manipulation or reverse engineering.",
                            Evidence = $"File: {file}, Match: '{launcher}'"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("  [!] Access denied to Prefetch directory. Run as Administrator.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Prefetch analysis error: {ex.Message}");
        }

        return flags;
    }
}
