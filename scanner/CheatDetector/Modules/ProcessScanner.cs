using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Scans running processes for known cheat client names and searches
/// process memory (RAM) for cheat-related strings.
/// </summary>
public class ProcessScanner
{
    private const string ModuleName = "ProcessScanner";

    // P/Invoke for reading process memory
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    /// <summary>
    /// Runs the process scan and returns a list of flags.
    /// </summary>
    public List<Flag> Scan(bool deepScan)
    {
        var flags = new List<Flag>();
        ScanProcessNames(flags);
        if (deepScan) ScanProcessMemory(flags);
        return flags;
    }

    /// <summary>
    /// Checks all running process names against the known cheat client list.
    /// </summary>
    private void ScanProcessNames(List<Flag> flags)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    string procName = proc.ProcessName.ToLowerInvariant();
                    string? procPath = null;

                    try { procPath = proc.MainModule?.FileName?.ToLowerInvariant(); }
                    catch { /* Access denied for some system processes */ }

                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (procName.Contains(cheat) ||
                            (procPath != null && procPath.Contains(cheat)))
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName,
                                Severity = Severity.High,
                                Title = "Suspicious Process Detected",
                                Description = $"Running process '{proc.ProcessName}' matches known cheat client signature '{cheat}'.",
                                Evidence = $"PID: {proc.Id}, Path: {procPath ?? "N/A"}, Match: '{cheat}'"
                            });
                        }
                    }
                }
                catch { /* Skip inaccessible processes */ }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Process name scan error: {ex.Message}");
        }
    }

    /// <summary>
    /// Reads memory of Java processes (javaw.exe / java.exe) to find cheat-related strings.
    /// </summary>
    private void ScanProcessMemory(List<Flag> flags)
    {
        try
        {
            var javaProcesses = Process.GetProcesses()
                .Where(p => p.ProcessName.Equals("javaw", StringComparison.OrdinalIgnoreCase) ||
                            p.ProcessName.Equals("java", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (javaProcesses.Count == 0)
            {
                flags.Add(new Flag
                {
                    Module = ModuleName,
                    Severity = Severity.Low,
                    Title = "No Java Process Found",
                    Description = "No running javaw.exe or java.exe process detected. Ensure Minecraft is running during the scan.",
                    Evidence = "Process list did not contain javaw.exe or java.exe"
                });
                return;
            }

            foreach (var proc in javaProcesses)
            {
                try { ScanProcessMemoryRegions(proc, flags); }
                catch (Exception) { /* Ignore access denied */ }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Memory scan error: {ex.Message}");
        }
    }

    /// <summary>
    /// Iterates through committed memory regions of a process looking for cheat signatures.
    /// </summary>
    private void ScanProcessMemoryRegions(Process proc, List<Flag> flags)
    {
        IntPtr handle = proc.Handle;
        IntPtr address = IntPtr.Zero;
        var foundSignatures = new HashSet<string>();
        int regionsScanned = 0;

        while (VirtualQueryEx(handle, address, out MEMORY_BASIC_INFORMATION mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
        {
            // Only scan committed, readable memory regions
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
                 mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
            {
                long regionSize = mbi.RegionSize.ToInt64();
                // Limit individual region reads to 4MB to avoid excessive memory usage
                if (regionSize > 0 && regionSize <= 4 * 1024 * 1024)
                {
                    byte[] buffer = new byte[regionSize];
                    if (ReadProcessMemory(handle, mbi.BaseAddress, buffer, buffer.Length, out int bytesRead) && bytesRead > 0)
                    {
                        // ASCII scan (class file constant pools, log output)
                        string ascii = Encoding.ASCII.GetString(buffer, 0, bytesRead).ToLowerInvariant();
                        // UTF-16 scan (JVM heap String objects — Java stores runtime strings as UTF-16)
                        int utf16Len = bytesRead - (bytesRead % 2);
                        string utf16 = utf16Len >= 2
                            ? Encoding.Unicode.GetString(buffer, 0, utf16Len).ToLowerInvariant()
                            : string.Empty;

                        foreach (string sig in CheatSignatures.MemorySignatures)
                        {
                            if (foundSignatures.Contains(sig)) continue;
                            bool inAscii  = ascii.Contains(sig, StringComparison.Ordinal);
                            bool inUtf16  = !inAscii && utf16.Contains(sig, StringComparison.Ordinal);
                            if (!inAscii && !inUtf16) continue;

                            foundSignatures.Add(sig);
                            string enc = inAscii ? "ASCII" : "UTF-16";
                            flags.Add(new Flag
                            {
                                Module = ModuleName,
                                Severity = Severity.High,
                                Title = "Cheat Signature Found in RAM",
                                Description = $"Memory of '{proc.ProcessName}' (PID {proc.Id}) contains '{sig}'.",
                                Evidence = $"PID: {proc.Id} | Region: 0x{mbi.BaseAddress.ToInt64():X} | Size: {regionSize} bytes | Encoding: {enc}",
                                MatchedSignature = sig,
                                EvidenceType = "RAM_STRING"
                            });
                        }
                    }
                    regionsScanned++;
                }
            }

            // Move to next region
            long nextAddress = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
            if (nextAddress <= address.ToInt64()) break; // Prevent infinite loop
            address = new IntPtr(nextAddress);
        }

        // Silenced region count
    }
}
