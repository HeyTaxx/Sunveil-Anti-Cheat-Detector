using System.Text.Json.Serialization;

namespace CheatDetector.Models;

/// <summary>
/// The complete scan report containing all findings, system info, and verdict.
/// </summary>
public class ScanResult
{
    [JsonPropertyName("reportId")]
    public string ReportId { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("systemInfo")]
    public SystemInfo SystemInfo { get; set; } = new();

    [JsonPropertyName("scanDuration")]
    public string ScanDuration { get; set; } = string.Empty;

    [JsonPropertyName("scanMode")]
    public string ScanMode { get; set; } = "quick";

    [JsonPropertyName("flags")]
    public List<Flag> Flags { get; set; } = new();

    [JsonPropertyName("summary")]
    public ScanSummary Summary { get; set; } = new();
}

/// <summary>
/// Aggregated summary of all scan flags with a final verdict.
/// </summary>
public class ScanSummary
{
    [JsonPropertyName("totalFlags")]
    public int TotalFlags { get; set; }

    [JsonPropertyName("highCount")]
    public int HighCount { get; set; }

    [JsonPropertyName("mediumCount")]
    public int MediumCount { get; set; }

    [JsonPropertyName("lowCount")]
    public int LowCount { get; set; }

    [JsonPropertyName("verdict")]
    public string Verdict { get; set; } = Models.Verdict.Clean;
}
