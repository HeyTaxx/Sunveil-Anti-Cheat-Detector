using System.IO;
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

    public List<Flag> Scan(Action<string>? onItemScanned = null)
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
                onItemScanned?.Invoke($"Analyzing Prefetch file: {Path.GetFileName(file)}");
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
                            Title = "Cheat Client Found in Prefetch Execution History",
                            Description = $"Prefetch file '{Path.GetFileName(file)}' matches known cheat client '{cheat}'. " +
                                          $"This confirms the application was previously launched on this machine.",
                            Evidence = $"File: {file}, Last Modified: {lastWriteTime:u}, Size: {fileSize} bytes, Match: '{cheat}'"
                        });
                    }
                }
            }

            foreach (var file in prefetchFiles)
            {
                string fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                string[] suspiciousTools = { "cheatengine", "processhacker", "x64dbg", "ollydbg",
                                                  "dnspy", "de4dot", "injector", "dllinjector" };

                foreach (string tool in suspiciousTools)
                {
                    if (fileName.Contains(tool))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.Medium,
                            Title = "Suspicious Tool Found in Prefetch History",
                            Description = $"Prefetch entry for '{Path.GetFileName(file)}' detected. " +
                                          $"This tool is commonly used for memory editing or process injection.",
                            Evidence = $"File: {file}, Match: '{tool}'"
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
