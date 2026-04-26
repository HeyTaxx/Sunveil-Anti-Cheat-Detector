using System.Management;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Scans running Java processes for suspicious JVM arguments that may indicate
/// code injection, agent loading, or classpath manipulation.
/// Uses WMI (Win32_Process) to read full command lines.
/// </summary>
public class JvmArgumentScanner
{
    private const string ModuleName = "JvmArgumentScanner";

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Scanning JVM arguments via WMI...");
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE Name LIKE 'java%'");
            var results = searcher.Get();
            int count = 0;

            foreach (ManagementObject obj in results)
            {
                count++;
                string? cmdLine = obj["CommandLine"]?.ToString();
                string name = obj["Name"]?.ToString() ?? "unknown";
                string pid = obj["ProcessId"]?.ToString() ?? "?";

                if (string.IsNullOrEmpty(cmdLine)) continue;

                string cmdLower = cmdLine.ToLowerInvariant();

                // Check for suspicious JVM arguments
                foreach (string arg in CheatSignatures.SuspiciousJvmArgs)
                {
                    if (cmdLower.Contains(arg.ToLowerInvariant()))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName, Severity = Severity.High,
                            Title = "Suspicious JVM Argument Detected",
                            Description = $"Java process '{name}' (PID {pid}) uses suspicious argument '{arg}'.",
                            Evidence = $"CommandLine: {TruncateString(cmdLine, 500)}"
                        });
                    }
                }

                // Check for cheat client references in classpath or arguments
                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (cmdLower.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName, Severity = Severity.High,
                            Title = "Cheat Client Reference in JVM Arguments",
                            Description = $"Java process '{name}' (PID {pid}) references '{cheat}' in its command line.",
                            Evidence = $"Match: '{cheat}', CommandLine: {TruncateString(cmdLine, 500)}"
                        });
                    }
                }

                obj.Dispose();
            }

            Console.WriteLine($"  [*] Analyzed {count} Java process(es).");
            if (count == 0)
            {
                flags.Add(new Flag
                {
                    Module = ModuleName, Severity = Severity.Low,
                    Title = "No Java Processes Running",
                    Description = "No Java processes found. Ensure Minecraft is running during the scan.",
                    Evidence = "WMI query returned 0 java processes"
                });
            }
        }
        catch (Exception ex) { Console.WriteLine($"  [!] JVM argument scan error: {ex.Message}"); }
        return flags;
    }

    private static string TruncateString(string s, int maxLen)
        => s.Length <= maxLen ? s : s[..maxLen] + "...";
}
