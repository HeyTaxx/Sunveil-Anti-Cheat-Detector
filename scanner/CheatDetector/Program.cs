using CheatDetector.Core;
using CheatDetector.Network;

namespace CheatDetector;

/// <summary>
/// Entry point for the Minecraft Cheat Detector Scanner.
/// Usage: CheatDetector [--deep] [--api-url http://localhost:3000] [--output report.json] [--dry-run]
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(@"
================================================================
                    SUNVEIL SMP
               System Diagnostic Tool
================================================================
");
        Console.ResetColor();

        Console.WriteLine("This tool will perform a read-only diagnostic scan of your system");
        Console.WriteLine("to verify game integrity. A report will be generated and securely");
        Console.WriteLine("uploaded to the Sunveil SMP servers for review.");
        Console.WriteLine();

        // Parse arguments
        bool deepScan = args.Contains("--deep");
        bool dryRun = args.Contains("--dry-run");
        string apiUrl = GetArgValue(args, "--api-url") ?? "https://cheat.sunveil.net";
        string apiKey = GetArgValue(args, "--api-key") ?? "CHANGE_THIS_TO_A_SECURE_RANDOM_STRING_32_CHARS";
        string outputFile = GetArgValue(args, "--output") ?? $"report_{DateTime.Now:yyyyMMdd_HHmmss}.json";

        if (args.Contains("--help") || args.Contains("-h"))
        {
            PrintHelp();
            return 0;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"[Configuration]");
        Console.WriteLine($"Mode:         {(deepScan ? "Deep Scan (Advanced)" : "Quick Scan (Standard)")}");
        Console.WriteLine($"API Endpoint: {apiUrl}");
        Console.WriteLine($"Local Report: {outputFile}");
        Console.ResetColor();
        Console.WriteLine();

        // Check for admin privileges
        if (!IsRunningAsAdmin())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] Note: Running without Administrator privileges.");
            Console.WriteLine("    Some system directories may not be accessible.");
            Console.ResetColor();
            Console.WriteLine();
        }

        // Execute scan
        var engine = new ScanEngine(deepScan);
        var result = engine.Execute();

        // Save report to file
        await ReportGenerator.SaveToFileAsync(result, outputFile);

        // Upload to API (unless dry run)
        if (!dryRun)
        {
            Console.WriteLine("\n[Network] Uploading diagnostic report...");
            var client = new ApiClient(apiUrl);
            string? reportUrl = await client.UploadReportAsync(result, apiKey);

            if (reportUrl != null)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("================================================================");
                Console.WriteLine("UPLOAD SUCCESSFUL");
                Console.WriteLine("================================================================");
                Console.ResetColor();
                Console.WriteLine("Please provide the following reference URL to the staff team:");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n-> {reportUrl}\n");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[Network] Dry run mode enabled. Report saved locally only.");
            Console.ResetColor();
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey(true);
        return result.Summary.Verdict == "CLEAN" ? 0 : 1;
    }

    private static string? GetArgValue(string[] args, string key)
    {
        int idx = Array.IndexOf(args, key);
        return idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : null;
    }

    private static bool IsRunningAsAdmin()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage: CheatDetector [OPTIONS]\n");
        Console.WriteLine("Options:");
        Console.WriteLine("  --deep           Enable deep scan (RAM strings, JVM args, DLL injection)");
        Console.WriteLine("  --api-url URL    API endpoint for uploading reports (default: http://localhost:3000)");
        Console.WriteLine("  --output FILE    Output file path for JSON report (default: report_<timestamp>.json)");
        Console.WriteLine("  --dry-run        Run scan without uploading to API");
        Console.WriteLine("  --help, -h       Show this help message");
    }
}
