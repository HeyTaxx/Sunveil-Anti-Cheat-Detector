using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Forms;
using System.Windows.Media;
using System.Windows.Threading;
using CheatDetector.Core;
using CheatDetector.Models;
using CheatDetector.Network;
using Application = System.Windows.Application;
using Clipboard = System.Windows.Clipboard;

namespace CheatDetector.UI;

public partial class MainWindow : Window
{
    private readonly string _apiUrl;
    private readonly string _apiKey;
    private ScanResult? _lastResult;
    private string? _uploadedReportUrl;
    private Stopwatch? _scanTimer;
    private DispatcherTimer? _uiTimer;
    private NotifyIcon? _notifyIcon;
    private bool _isScanning = false;

    public MainWindow(string apiUrl = "https://cheat.sunveil.net", string apiKey = "CHANGE_THIS_TO_A_SECURE_RANDOM_STRING_32_CHARS")
    {
        InitializeComponent();
        _apiUrl = apiUrl;
        _apiKey = apiKey;

        CheckAdminRights();
        InitializeSystemTray();

        StateChanged += MainWindow_StateChanged;
        Closing += MainWindow_Closing;
    }

    private void CheckAdminRights()
    {
        bool isAdmin = false;
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { }

        if (isAdmin)
        {
            AdminBadgeText.Text = "🛡️ Administrator";
            AdminBadgeText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#34D399"));
            AdminBadge.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#064E3B"));
        }
        else
        {
            AdminBadgeText.Text = "⚠️ User Mode (Recommended: Run as Admin)";
            AdminBadgeText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F59E0B"));
            AdminBadge.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#451A03"));
        }
    }

    private void InitializeSystemTray()
    {
        try
        {
            _notifyIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "Sunveil Overwatch — Anti-Cheat Scanner",
                Visible = true
            };

            _notifyIcon.DoubleClick += (s, e) => RestoreFromTray();
            _notifyIcon.Click += (s, e) => RestoreFromTray();

            var contextMenu = new ContextMenuStrip();
            contextMenu.Items.Add("Open Sunveil Overwatch", null, (s, e) => RestoreFromTray());
            contextMenu.Items.Add("Exit", null, (s, e) => Close());
            _notifyIcon.ContextMenuStrip = contextMenu;
        }
        catch { }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void MainWindow_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            if (_isScanning)
            {
                _notifyIcon?.ShowBalloonTip(3000, "Sunveil Overwatch Scanner",
                    "Scan is actively running in the background. Double-click tray icon to open.", ToolTipIcon.Info);
            }
        }
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _notifyIcon?.Dispose();
    }

    private void OpenLegalTermsButton_Click(object sender, RoutedEventArgs e)
    {
        LegalTermsModal.Visibility = Visibility.Visible;
    }

    private void CloseTermsModal_Click(object sender, RoutedEventArgs e)
    {
        LegalTermsModal.Visibility = Visibility.Collapsed;
    }

    private void AcceptTermsModal_Click(object sender, RoutedEventArgs e)
    {
        LegalConsentCheckBox.IsChecked = true;
        LegalTermsModal.Visibility = Visibility.Collapsed;
    }

    private async void StartScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (LegalConsentCheckBox.IsChecked != true)
        {
            LegalTermsModal.Visibility = Visibility.Visible;
            return;
        }

        _isScanning = true;

        // Switch to Scanning Panel
        StartPanel.Visibility = Visibility.Collapsed;
        ScanningPanel.Visibility = Visibility.Visible;
        ResultPanel.Visibility = Visibility.Collapsed;

        LogTextBox.Text = "[00:00] Initializing Sunveil Overwatch diagnostic engine...\n";
        _scanTimer = Stopwatch.StartNew();

        _uiTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _uiTimer.Tick += (s, args) =>
        {
            if (_scanTimer != null)
            {
                ElapsedTimeText.Text = $"Elapsed: {_scanTimer.Elapsed:mm\\:ss}";
            }
        };
        _uiTimer.Start();

        var engine = new ScanEngine(deepScan: true);

        engine.OnProgress += (info) =>
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = info.Percentage;
                PercentageText.Text = $"{Math.Min(100, Math.Round(info.Percentage))}%";
                StepNumberText.Text = $"Step {info.StepIndex} of {info.TotalSteps}: ";
                CurrentStepText.Text = info.ModuleName;
                CurrentItemText.Text = string.IsNullOrWhiteSpace(info.CurrentItem) ? info.StatusMessage : info.CurrentItem;

                if (_scanTimer != null && info.Percentage > 2)
                {
                    double elapsedSec = _scanTimer.Elapsed.TotalSeconds;
                    double remainingSec = Math.Max(0, (elapsedSec / info.Percentage) * (100.0 - info.Percentage));
                    TimeRemainingText.Text = $"Est. Remaining: ~{Math.Ceiling(remainingSec)}s";
                }

                string timeCode = _scanTimer != null ? $"[{_scanTimer.Elapsed:mm\\:ss}]" : "[00:00]";
                string logLine = string.IsNullOrWhiteSpace(info.CurrentItem)
                    ? $"{timeCode} [{info.StepIndex}/{info.TotalSteps}] {info.StatusMessage}\n"
                    : $"{timeCode} {info.CurrentItem}\n";

                LogTextBox.Text += logLine;
                LogScrollViewer.ScrollToEnd();
            });
        };

        // Run scan on background thread
        ScanResult result = await Task.Run(() => engine.Execute());
        _lastResult = result;
        _isScanning = false;

        _uiTimer.Stop();
        _scanTimer?.Stop();

        // Save report locally
        string outputFile = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
        await ReportGenerator.SaveToFileAsync(result, outputFile);

        // Upload to server
        LogTextBox.Text += $"[{_scanTimer?.Elapsed:mm\\:ss}] Transmitting telemetry report to Sunveil servers...\n";
        LogScrollViewer.ScrollToEnd();

        try
        {
            var client = new ApiClient(_apiUrl);
            _uploadedReportUrl = await client.UploadReportAsync(result, _apiKey);
        }
        catch (Exception ex)
        {
            LogTextBox.Text += $"[ERROR] Server upload failed: {ex.Message}\n";
        }

        // Notify tray if minimized
        if (WindowState == WindowState.Minimized)
        {
            _notifyIcon?.ShowBalloonTip(5000, "Sunveil Overwatch",
                "Diagnostic scan completed! Click to view your report.", ToolTipIcon.Info);
        }

        // Show Results
        ShowResults(result);
    }

    private void ShowResults(ScanResult result)
    {
        ScanningPanel.Visibility = Visibility.Collapsed;
        ResultPanel.Visibility = Visibility.Visible;

        ReportIdText.Text = result.ReportId;

        if (_uploadedReportUrl != null)
        {
            UploadStatusText.Text = "✓ Telemetry report successfully transmitted to Sunveil servers.";
            UploadStatusText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#34D399"));
        }
        else
        {
            UploadStatusText.Text = "⚠️ Report saved locally (Server upload unavailable or offline mode).";
            UploadStatusText.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F59E0B"));
        }

        if (result.Summary.Verdict == Verdict.Clean)
        {
            VerdictIcon.Text = "✅";
            VerdictTitle.Text = "SYSTEM VERIFIED CLEAN";
            VerdictTitle.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#34D399"));
            VerdictSubtitle.Text = "No cheat client artifacts, memory strings, or evasion traces were detected.";
            VerdictBox.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#064E3B"));
            VerdictBox.BorderBrush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#059669"));
        }
        else if (result.Summary.Verdict == Verdict.Suspicious)
        {
            VerdictIcon.Text = "⚠️";
            VerdictTitle.Text = "SUSPICIOUS ARTIFACTS DETECTED";
            VerdictTitle.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F59E0B"));
            VerdictSubtitle.Text = $"{result.Summary.TotalFlags} suspicious system artifacts or software traces were flagged.";
            VerdictBox.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#451A03"));
            VerdictBox.BorderBrush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#D97706"));
        }
        else
        {
            VerdictIcon.Text = "🚨";
            VerdictTitle.Text = "CHEAT VIOLATION DETECTED";
            VerdictTitle.Foreground = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F87171"));
            VerdictSubtitle.Text = $"System inspection identified {result.Summary.HighCount} critical cheat findings or evasion attempts.";
            VerdictBox.Background = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#451212"));
            VerdictBox.BorderBrush = new SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#DC2626"));
        }
    }

    private void CopyCodeButton_Click(object sender, RoutedEventArgs e)
    {
        string textToCopy = _uploadedReportUrl ?? ReportIdText.Text;
        try
        {
            Clipboard.SetText(textToCopy);
            CopyStatusText.Text = "✓ Reference Code copied to clipboard!";
        }
        catch (Exception ex)
        {
            CopyStatusText.Text = $"Failed to copy: {ex.Message}";
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
