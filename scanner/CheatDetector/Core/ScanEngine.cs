using System.Diagnostics;
using CheatDetector.Models;
using CheatDetector.Modules;

namespace CheatDetector.Core;

/// <summary>
/// Orchestrates all scanner modules and aggregates results into a final ScanResult.
/// </summary>
public class ScanEngine
{
    private readonly bool _deepScan;

    public ScanEngine(bool deepScan)
    {
        _deepScan = deepScan;
    }

    /// <summary>
    /// Executes all scan modules and returns the aggregated result.
    /// </summary>
    public ScanResult Execute()
    {
        var stopwatch = Stopwatch.StartNew();
        var allFlags = new List<Flag>();

        Console.WriteLine("Initializing diagnostic sequence...");
        Console.WriteLine("----------------------------------------------------------------");

        // Module 1: Process Scanner (always runs)
        Console.Write("[1/7] Analyzing active processes... ");
        var processScanner = new ProcessScanner();
        allFlags.AddRange(processScanner.Scan(_deepScan));
        Console.WriteLine($"Done.");

        // Module 2: Prefetch Analyzer
        Console.Write("[2/7] Checking application execution history... ");
        var prefetch = new PrefetchAnalyzer();
        allFlags.AddRange(prefetch.Scan());
        Console.WriteLine($"Done.");

        // Module 3: UserAssist Reader
        Console.Write("[3/7] Verifying registry explorer history... ");
        var userAssist = new UserAssistReader();
        allFlags.AddRange(userAssist.Scan());
        Console.WriteLine($"Done.");

        // Module 4: AppCompatCache Reader
        Console.Write("[4/7] Validating compatibility cache... ");
        var appCompat = new AppCompatCacheReader();
        allFlags.AddRange(appCompat.Scan());
        Console.WriteLine($"Done.");

        // Module 5: File System Scanner
        Console.Write("[5/7] Scanning local application data... ");
        var fileSystem = new FileSystemScanner();
        allFlags.AddRange(fileSystem.Scan());
        Console.WriteLine($"Done.");

        // Module 6: JVM Argument Scanner (deep scan only)
        if (_deepScan)
        {
            Console.Write("[6/7] Inspecting JVM parameters... ");
            var jvmScanner = new JvmArgumentScanner();
            allFlags.AddRange(jvmScanner.Scan());
            Console.WriteLine($"Done.");

            // Module 7: DLL Injection Scanner (deep scan only)
            Console.Write("[7/7] Verifying loaded modules... ");
            var dllScanner = new DllInjectionScanner();
            allFlags.AddRange(dllScanner.Scan());
            Console.WriteLine($"Done.");
        }
        else
        {
            Console.WriteLine("[6/7] Inspecting JVM parameters... Skipped (Standard Mode)");
            Console.WriteLine("[7/7] Verifying loaded modules... Skipped (Standard Mode)");
        }

        stopwatch.Stop();

        // Deduplicate flags by title + evidence
        allFlags = allFlags
            .GroupBy(f => $"{f.Title}|{f.Evidence}")
            .Select(g => g.First())
            .ToList();

        // Build summary
        var summary = new ScanSummary
        {
            TotalFlags = allFlags.Count,
            HighCount = allFlags.Count(f => f.Severity == Severity.High),
            MediumCount = allFlags.Count(f => f.Severity == Severity.Medium),
            LowCount = allFlags.Count(f => f.Severity == Severity.Low),
            Verdict = DetermineVerdict(allFlags)
        };

        // Build result
        var result = new ScanResult
        {
            ReportId = GenerateReportId(),
            Timestamp = DateTime.UtcNow,
            SystemInfo = CollectSystemInfo(),
            ScanDuration = $"{stopwatch.Elapsed.TotalSeconds:F1}s",
            ScanMode = _deepScan ? "deep" : "quick",
            Flags = allFlags,
            Summary = summary
        };

        PrintSummary(result);
        return result;
    }

    private static string DetermineVerdict(List<Flag> flags)
    {
        int high = flags.Count(f => f.Severity == Severity.High);
        int medium = flags.Count(f => f.Severity == Severity.Medium);

        if (high > 0) return Verdict.Flagged;
        if (medium >= 2) return Verdict.Suspicious;
        if (medium > 0 || flags.Count > 3) return Verdict.Suspicious;
        return Verdict.Clean;
    }

    private static string GenerateReportId()
    {
        string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var random = new Random();
        string code = new string(Enumerable.Range(0, 6).Select(_ => chars[random.Next(chars.Length)]).ToArray());
        return $"ACD-{DateTime.UtcNow:yyyy}-{code}";
    }

    private static SystemInfo CollectSystemInfo()
    {
        var info = new SystemInfo
        {
            Hostname = Environment.MachineName,
            Username = Environment.UserName,
            OperatingSystem = Environment.OSVersion.ToString(),
            DotNetVersion = Environment.Version.ToString()
        };

        // Generate HWID from machine name + username hash
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes($"{info.Hostname}|{info.Username}|{Environment.ProcessorCount}");
        info.HardwareId = Convert.ToHexString(sha.ComputeHash(bytes))[..16];

        // Try to get CPU info via WMI
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT Name FROM Win32_Processor");
            foreach (var obj in searcher.Get())
            {
                info.CpuName = obj["Name"]?.ToString() ?? "Unknown";
                obj.Dispose();
                break;
            }
        }
        catch { info.CpuName = "Unknown"; }

        // RAM
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                if (ulong.TryParse(obj["TotalPhysicalMemory"]?.ToString(), out ulong ram))
                    info.RamTotalGb = Math.Round(ram / (1024.0 * 1024 * 1024), 1);
                obj.Dispose();
                break;
            }
        }
        catch { info.RamTotalGb = 0; }

        return info;
    }

    private static void PrintSummary(ScanResult result)
    {
        Console.WriteLine("\n----------------------------------------------------------------");
        Console.WriteLine("DIAGNOSTIC SCAN COMPLETE");
        Console.WriteLine("----------------------------------------------------------------");
        Console.WriteLine($"Reference ID:  {result.ReportId}");
        Console.WriteLine($"Duration:      {result.ScanDuration}");
        Console.WriteLine($"Flags Found:   {result.Summary.TotalFlags}");
        Console.WriteLine("----------------------------------------------------------------");
    }
}
