using System.IO;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

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

    public List<Flag> Scan(bool deepScan, Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();
        ScanProcessNames(flags, onItemScanned);
        if (deepScan) ScanProcessMemory(flags, onItemScanned);
        return flags;
    }

    private void ScanProcessNames(List<Flag> flags, Action<string>? onItemScanned)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    onItemScanned?.Invoke($"Inspecting active process: {proc.ProcessName} (PID {proc.Id})");
                    string procName = proc.ProcessName.ToLowerInvariant();
                    string? procPath = null;

                    try { procPath = proc.MainModule?.FileName?.ToLowerInvariant(); }
                    catch { }

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
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private void ScanProcessMemory(List<Flag> flags, Action<string>? onItemScanned)
    {
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
                    onItemScanned?.Invoke($"Scanning RAM memory strings of: {proc.ProcessName} (PID {proc.Id})");
                    ScanSingleProcessMemory(proc, flags, onItemScanned);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private void ScanSingleProcessMemory(Process proc, List<Flag> flags, Action<string>? onItemScanned)
    {
        IntPtr hProcess = proc.Handle;
        IntPtr address = IntPtr.Zero;
        var matchedStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (VirtualQueryEx(hProcess, address, out MEMORY_BASIC_INFORMATION memInfo, new UIntPtr((uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>())) != UIntPtr.Zero)
        {
            bool isCommitted = memInfo.State == MEM_COMMIT;
            bool isReadable = memInfo.Protect == PAGE_READWRITE ||
                             memInfo.Protect == PAGE_READONLY ||
                             memInfo.Protect == PAGE_EXECUTE_READ ||
                             memInfo.Protect == PAGE_EXECUTE_READWRITE;

            long regionSize = memInfo.RegionSize.ToInt64();

            if (isCommitted && isReadable && regionSize > 0 && regionSize <= 50 * 1024 * 1024)
            {
                byte[] buffer = new byte[regionSize];
                if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, new IntPtr(buffer.Length), out IntPtr bytesReadPtr) && bytesReadPtr.ToInt64() > 0)
                {
                    int bytesRead = (int)bytesReadPtr.ToInt64();
                    string regionText = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                    foreach (string sig in CheatSignatures.MemorySignatures)
                    {
                        if (!matchedStrings.Contains(sig) && regionText.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchedStrings.Add(sig);
                            onItemScanned?.Invoke($"[RAM MATCH] Found memory string '{sig}' in PID {proc.Id}");
                            flags.Add(new Flag
                            {
                                Module = ModuleName,
                                Severity = Severity.High,
                                Title = "Cheat Signature Found in Process Memory (RAM)",
                                Description = $"Memory string '{sig}' detected in RAM of '{proc.ProcessName}' (PID {proc.Id}).",
                                Evidence = $"PID: {proc.Id}, Process: {proc.ProcessName}, Matched String: '{sig}'"
                            });
                        }
                    }
                }
            }

            address = new IntPtr(memInfo.BaseAddress.ToInt64() + regionSize);
        }
    }
}
