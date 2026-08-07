using System.Diagnostics;
using CheatDetector.Models;
using CheatDetector.Modules;

namespace CheatDetector.Core;

public record ScanProgressInfo(
    int StepIndex,
    int TotalSteps,
    double Percentage,
    string ModuleName,
    string StatusMessage,
    string CurrentItem
);

/// <summary>
/// Orchestrates all scanner modules and aggregates results into a final ScanResult.
/// Defaults to deep forensic analysis to scan everything.
/// </summary>
public class ScanEngine
{
    private readonly bool _deepScan;

    /// <summary>
    /// Event raised to notify UI or callers about real-time progress.
    /// </summary>
    public event Action<ScanProgressInfo>? OnProgress;

    public ScanEngine(bool deepScan = true)
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
        int totalSteps = 8;

        Console.WriteLine("Initializing forensic diagnostic sequence...");
        Console.WriteLine("----------------------------------------------------------------");

        // Module 1: Process Scanner (weight: 10%)
        ReportProgress(1, totalSteps, 0.0, "Active Processes & Memory", "Scanning active running processes and RAM memory strings...", "Initializing...");
        Console.Write("[1/8] Analyzing active processes... ");
        var processScanner = new ProcessScanner();
        allFlags.AddRange(processScanner.Scan(_deepScan, item => ReportProgress(1, totalSteps, 5.0, "Active Processes & Memory", "Scanning active running processes and RAM...", item)));
        Console.WriteLine("Done.");

        // Module 2: Prefetch Analyzer (weight: 10%)
        ReportProgress(2, totalSteps, 12.5, "Execution History (Prefetch)", "Checking Windows application execution history (Prefetch)...", "Reading Prefetch files...");
        Console.Write("[2/8] Checking application execution history... ");
        var prefetch = new PrefetchAnalyzer();
        allFlags.AddRange(prefetch.Scan(item => ReportProgress(2, totalSteps, 20.0, "Execution History (Prefetch)", "Inspecting Windows Prefetch history...", item)));
        Console.WriteLine("Done.");

        // Module 3: UserAssist Reader (weight: 10%)
        ReportProgress(3, totalSteps, 25.0, "Explorer Registry (UserAssist)", "Reading Windows Explorer UserAssist registry entries...", "Reading UserAssist keys...");
        Console.Write("[3/8] Verifying registry explorer history... ");
        var userAssist = new UserAssistReader();
        allFlags.AddRange(userAssist.Scan(item => ReportProgress(3, totalSteps, 32.5, "Explorer Registry (UserAssist)", "Reading UserAssist registry keys...", item)));
        Console.WriteLine("Done.");

        // Module 4: Evasion & Deletion Forensics (weight: 15%)
        ReportProgress(4, totalSteps, 37.5, "Anti-Evasion & Deletion Forensics", "Checking for recently deleted cheat clients and evasion attempts...", "Checking deletion artifacts...");
        Console.Write("[4/8] Running anti-evasion & deletion forensics... ");
        var evasionScanner = new EvasionDetector();
        allFlags.AddRange(evasionScanner.Scan(item => ReportProgress(4, totalSteps, 45.0, "Anti-Evasion & Deletion Forensics", "Analyzing deleted execution artifacts...", item)));
        Console.WriteLine("Done.");

        // Module 5: AppCompatCache Reader (weight: 10%)
        ReportProgress(5, totalSteps, 50.0, "Compatibility Cache (ShimCache)", "Validating Windows Compatibility ShimCache...", "Parsing ShimCache...");
        Console.Write("[5/8] Validating compatibility cache... ");
        var appCompat = new AppCompatCacheReader();
        allFlags.AddRange(appCompat.Scan(item => ReportProgress(5, totalSteps, 57.5, "Compatibility Cache (ShimCache)", "Parsing Compatibility ShimCache...", item)));
        Console.WriteLine("Done.");

        // Module 6: File System & Drive Scanner (weight: 30%)
        ReportProgress(6, totalSteps, 62.5, "Filesystem & Drive Search", "Scanning Minecraft directories, Temp, Downloads & Drive storage...", "Enumerating drives...");
        Console.Write("[6/8] Scanning local application data & drives... ");
        var fileSystem = new FileSystemScanner();
        allFlags.AddRange(fileSystem.Scan(item => ReportProgress(6, totalSteps, 78.0, "Filesystem & Drive Search", "Scanning local application data & drives...", item)));
        Console.WriteLine("Done.");

        // Module 7: JVM Argument Scanner (weight: 7.5%)
        if (_deepScan)
        {
            ReportProgress(7, totalSteps, 87.5, "Java Runtime Parameters", "Inspecting Java Virtual Machine parameters & agents...", "Checking JVM arguments...");
            Console.Write("[7/8] Inspecting JVM parameters... ");
            var jvmScanner = new JvmArgumentScanner();
            allFlags.AddRange(jvmScanner.Scan(item => ReportProgress(7, totalSteps, 92.5, "Java Runtime Parameters", "Inspecting Java VM parameters...", item)));
            Console.WriteLine("Done.");

            // Module 8: DLL Injection Scanner (weight: 5%)
            ReportProgress(8, totalSteps, 95.0, "Loaded Modules & Injections", "Verifying loaded DLL modules and native injection attempts...", "Checking DLL modules...");
            Console.Write("[8/8] Verifying loaded modules... ");
            var dllScanner = new DllInjectionScanner();
            allFlags.AddRange(dllScanner.Scan(item => ReportProgress(8, totalSteps, 98.0, "Loaded Modules & Injections", "Verifying loaded DLL modules...", item)));
            Console.WriteLine("Done.");
        }
        else
        {
            Console.WriteLine("[7/8] Inspecting JVM parameters... Skipped");
            Console.WriteLine("[8/8] Verifying loaded modules... Skipped");
        }

        ReportProgress(8, totalSteps, 100.0, "Complete", "Diagnostic scan complete. Generating final report...", "Scan Finished.");

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

    private void ReportProgress(int step, int total, double pct, string module, string msg, string currentItem)
    {
        OnProgress?.Invoke(new ScanProgressInfo(step, total, pct, module, msg, currentItem));
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
        var bytes = new byte[6];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        char[] code = new char[6];
        for (int i = 0; i < 6; i++)
        {
            code[i] = chars[bytes[i] % chars.Length];
        }
        return $"ACD-{DateTime.UtcNow:yyyy}-{new string(code)}";
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

        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes($"{info.Hostname}|{info.Username}|{Environment.ProcessorCount}");
        info.HardwareId = Convert.ToHexString(sha.ComputeHash(bytes))[..16];

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
