using System.IO;
using System.Runtime.InteropServices;
using CheatDetector.Core;
using CheatDetector.Network;
using CheatDetector.UI;

namespace CheatDetector;

/// <summary>
/// Entry point for the Minecraft Cheat Detector Scanner.
/// Defaults to WPF Client GUI when double-clicked by end-users.
/// Built by Blue Style Development (https://bluestyle.dev) for Sunveil SMP.
/// </summary>
class Program
{
    private static readonly string LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cheatdetector_debug.log");

    [DllImport("kernel32.dll")]
    private static extern bool AllocConsole();

    [STAThread]
    static int Main(string[] args)
    {
        LogToFile("================================================================");
        LogToFile($"[INIT] Sunveil Overwatch Scanner starting at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        LogToFile($"[INIT] Args: {string.Join(" ", args)}");

        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            LogToFile($"[CRITICAL ERROR] UnhandledException: {e.ExceptionObject}");
        };

        TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            LogToFile($"[TASK ERROR] UnobservedTaskException: {e.Exception?.Message}");
            e.SetObserved();
        };

        string apiUrl = GetArgValue(args, "--api-url") ?? "https://anticheat.sunveil.net";
        string apiKey = GetArgValue(args, "--api-key") ?? "CHANGE_THIS_TO_A_SECURE_RANDOM_STRING_32_CHARS";

        bool isCliMode = args.Contains("--cli") || args.Contains("--dry-run") || args.Contains("--help") || args.Contains("-h");

        if (!isCliMode)
        {
            try
            {
                LogToFile("[GUI] Initializing WPF Application...");
                var app = new System.Windows.Application();
                
                // Prevent WPF from shutting down when IntroSplashScreen closes
                app.ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown;

                LogToFile("[GUI] Showing Intro SplashScreen...");
                var splash = new IntroSplashScreen();
                splash.ShowDialog();

                LogToFile("[GUI] Launching MainWindow Diagnostic Console...");
                var window = new MainWindow(apiUrl, apiKey);
                app.MainWindow = window;
                app.ShutdownMode = System.Windows.ShutdownMode.OnMainWindowClose;

                return app.Run(window);
            }
            catch (Exception ex)
            {
                LogToFile($"[GUI ERROR] Exception launching WPF Application: {ex}");
                return 1;
            }
        }

        // Allocate console window for CLI mode if started as WinExe
        AllocConsole();

        // Run CLI workflow synchronously on main thread
        return RunCliAsync(args, apiUrl, apiKey).GetAwaiter().GetResult();
    }

    private static async Task<int> RunCliAsync(string[] args, string apiUrl, string apiKey)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(@"
================================================================
                    SUNVEIL OVERWATCH
             System Diagnostic Console (CLI)
      Powered by Blue Style Development (bluestyle.dev)
================================================================
");
        Console.ResetColor();

        bool deepScan = !args.Contains("--quick");
        bool dryRun = args.Contains("--dry-run");
        string outputFile = GetArgValue(args, "--output") ?? $"report_{DateTime.Now:yyyyMMdd_HHmmss}.json";

        // Prevent path traversal in output file path
        outputFile = Path.GetFullPath(outputFile);
        if (!outputFile.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Output file must have .json extension.");
            Console.ResetColor();
            return 1;
        }

        if (args.Contains("--help") || args.Contains("-h"))
        {
            PrintHelp();
            return 0;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"[Configuration]");
        Console.WriteLine($"Mode:         {(deepScan ? "Full Forensic Scan (Standard)" : "Quick Scan")}");
        Console.WriteLine($"API Endpoint: {apiUrl}");
        Console.WriteLine($"Local Report: {outputFile}");
        Console.ResetColor();
        Console.WriteLine();

        if (!IsRunningAsAdmin())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] Note: Running without Administrator privileges.");
            Console.WriteLine("    Some system directories may have restricted access.");
            Console.ResetColor();
            Console.WriteLine();
        }

        var engine = new ScanEngine(deepScan);
        engine.OnProgress += (info) =>
        {
            string itemStr = string.IsNullOrWhiteSpace(info.CurrentItem) ? "" : $" -> {info.CurrentItem}";
            Console.WriteLine($"[{info.StepIndex}/{info.TotalSteps}] {info.StatusMessage}{itemStr}");
        };

        var result = engine.Execute();

        await ReportGenerator.SaveToFileAsync(result, outputFile);

        if (!dryRun)
        {
            Console.WriteLine("\n[Network] Transmitting telemetry report...");
            var client = new ApiClient(apiUrl);
            string? reportUrl = await client.UploadReportAsync(result, apiKey);

            if (reportUrl != null)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("================================================================");
                Console.WriteLine("TELEMETRY TRANSMISSION SUCCESSFUL");
                Console.WriteLine("================================================================");
                Console.ResetColor();
                Console.WriteLine("Please present this reference URL to server staff in Discord:");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n-> {reportUrl}\n");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[Network] Dry-Run mode active. Report saved locally only.");
            Console.ResetColor();
        }

        if (!Console.IsInputRedirected)
        {
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey(true);
        }
        return result.Summary.Verdict == "CLEAN" ? 0 : 1;
    }

    private static void LogToFile(string message)
    {
        try
        {
            string logLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
            File.AppendAllText(LogFilePath, logLine);
        }
        catch { }
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
        Console.WriteLine("  --cli            Run in console mode (default is Client GUI)");
        Console.WriteLine("  --quick          Run quick scan instead of full deep forensic scan");
        Console.WriteLine("  --api-url URL    API endpoint for uploading reports");
        Console.WriteLine("  --output FILE    Output file path for JSON report");
        Console.WriteLine("  --dry-run        Run scan without uploading to API");
        Console.WriteLine("  --help, -h       Show this help message");
    }
}
