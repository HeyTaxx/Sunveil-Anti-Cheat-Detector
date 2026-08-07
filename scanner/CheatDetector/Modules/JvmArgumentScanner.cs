using System.IO;
using System.Management;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Scans running Java processes for suspicious JVM arguments that may indicate
/// code injection, agent loading, or classpath manipulation.
/// </summary>
public class JvmArgumentScanner
{
    private const string ModuleName = "JvmArgumentScanner";

    public List<Flag> Scan(Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Scanning JVM arguments via WMI...");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE Name LIKE '%java%'");

            foreach (var obj in searcher.Get())
            {
                string procName = obj["Name"]?.ToString() ?? "java.exe";
                string pid = obj["ProcessId"]?.ToString() ?? "0";
                string commandLine = obj["CommandLine"]?.ToString() ?? "";

                onItemScanned?.Invoke($"Inspecting JVM parameters for PID {pid} ({procName})");

                if (string.IsNullOrEmpty(commandLine)) continue;

                string lowerCmd = commandLine.ToLowerInvariant();

                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (lowerCmd.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.High,
                            Title = "Cheat Client Specified in JVM Arguments",
                            Description = $"JVM command line for PID {pid} contains cheat reference '{cheat}'.",
                            Evidence = $"PID: {pid}, Command Line: {commandLine}"
                        });
                    }
                }

                foreach (string susArg in CheatSignatures.SuspiciousJvmArgs)
                {
                    if (lowerCmd.Contains(susArg.ToLowerInvariant()))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.High,
                            Title = "Suspicious JVM Argument Detected",
                            Description = $"Java process PID {pid} was launched with suspicious parameter '{susArg}'.",
                            Evidence = $"PID: {pid}, Flagged Parameter: {susArg}, Full CMD: {commandLine}"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] JVM Argument scan error: {ex.Message}");
        }

        return flags;
    }
}
