using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Enumerates loaded DLL modules in Java processes and checks for
/// suspicious injected DLLs not on the whitelist.
/// </summary>
public class DllInjectionScanner
{
    private const string ModuleName = "DllInjectionScanner";

    public List<Flag> Scan(Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Scanning for injected DLLs in Java processes...");

        try
        {
            var javaProcesses = Process.GetProcessesByName("java")
                .Concat(Process.GetProcessesByName("javaw"))
                .Concat(Process.GetProcessesByName("minecraft"))
                .ToList();

            foreach (var proc in javaProcesses)
            {
                try
                {
                    onItemScanned?.Invoke($"Scanning loaded DLL modules for PID {proc.Id} ({proc.ProcessName})");
                    ScanProcessModules(proc, flags, onItemScanned);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        return flags;
    }

    private void ScanProcessModules(Process proc, List<Flag> flags, Action<string>? onItemScanned)
    {
        try
        {
            foreach (ProcessModule module in proc.Modules)
            {
                string modName = module.ModuleName?.ToLowerInvariant() ?? "";
                string modPath = module.FileName?.ToLowerInvariant() ?? "";

                onItemScanned?.Invoke($"Loaded DLL: {modName} in PID {proc.Id}");

                bool isWhitelisted = CheatSignatures.JavaWhitelistDlls
                    .Any(w => modName.Contains(w.ToLowerInvariant()) || modPath.Contains(w.ToLowerInvariant()));

                if (isWhitelisted) continue;

                foreach (string pattern in CheatSignatures.SuspiciousDllPatterns)
                {
                    if (modName.Contains(pattern) || modPath.Contains(pattern))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.High,
                            Title = "Suspicious Injected DLL Module Detected",
                            Description = $"Java process PID {proc.Id} has non-standard DLL module '{module.ModuleName}' loaded.",
                            Evidence = $"PID: {proc.Id}, Module: {module.ModuleName}, Path: {module.FileName}, Pattern: '{pattern}'"
                        });
                    }
                }
            }
        }
        catch { }
    }
}
