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

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(
        IntPtr hProcess, IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameExW(
        IntPtr hProcess, IntPtr hModule, char[] lpFilename, int nSize);

    private const uint LIST_MODULES_ALL = 0x03;

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Scanning for injected DLLs in Java processes...");
        try
        {
            var javaProcs = Process.GetProcesses()
                .Where(p => p.ProcessName.Equals("javaw", StringComparison.OrdinalIgnoreCase) ||
                            p.ProcessName.Equals("java", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (javaProcs.Count == 0)
            {
                Console.WriteLine("  [*] No Java processes found for DLL scan.");
                return flags;
            }

            foreach (var proc in javaProcs)
            {
                try
                {
                    Console.WriteLine($"  [*] Checking modules in PID {proc.Id}...");
                    var modules = GetProcessModules(proc);

                    foreach (string modulePath in modules)
                    {
                        string moduleName = Path.GetFileName(modulePath).ToLowerInvariant();

                        // Check if module is whitelisted
                        bool isWhitelisted = CheatSignatures.JavaWhitelistDlls
                            .Any(w => moduleName.Contains(w.ToLowerInvariant()));

                        if (!isWhitelisted)
                        {
                            // Check against suspicious DLL patterns
                            foreach (string pattern in CheatSignatures.SuspiciousDllPatterns)
                            {
                                if (moduleName.Contains(pattern.ToLowerInvariant()))
                                {
                                    flags.Add(new Flag
                                    {
                                        Module = ModuleName, Severity = Severity.High,
                                        Title = "Suspicious DLL Injection Detected",
                                        Description = $"Module '{moduleName}' in Java process (PID {proc.Id}) matches suspicious pattern '{pattern}'.",
                                        Evidence = $"Full Path: {modulePath}"
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) { Console.WriteLine($"  [!] DLL scan for PID {proc.Id}: {ex.Message}"); }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex) { Console.WriteLine($"  [!] DLL injection scan error: {ex.Message}"); }
        return flags;
    }

    private List<string> GetProcessModules(Process proc)
    {
        var modules = new List<string>();
        try
        {
            // Try managed API first
            foreach (ProcessModule mod in proc.Modules)
            {
                if (!string.IsNullOrEmpty(mod.FileName))
                    modules.Add(mod.FileName);
            }
        }
        catch
        {
            // Fallback to P/Invoke for 64-bit processes
            try
            {
                IntPtr handle = proc.Handle;
                IntPtr[] moduleHandles = new IntPtr[1024];
                if (EnumProcessModulesEx(handle, moduleHandles, moduleHandles.Length * IntPtr.Size,
                    out int needed, LIST_MODULES_ALL))
                {
                    int count = needed / IntPtr.Size;
                    char[] nameBuffer = new char[1024];
                    for (int i = 0; i < count; i++)
                    {
                        uint len = GetModuleFileNameExW(handle, moduleHandles[i], nameBuffer, nameBuffer.Length);
                        if (len > 0) modules.Add(new string(nameBuffer, 0, (int)len));
                    }
                }
            }
            catch { /* Cannot access modules */ }
        }
        return modules;
    }
}
