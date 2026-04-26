using System.Text.Json.Serialization;

namespace CheatDetector.Models;

/// <summary>
/// Represents a single suspicious finding (flag) detected during a scan.
/// </summary>
public class Flag
{
    [JsonPropertyName("module")]
    public string Module { get; set; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "LOW";

    [JsonPropertyName("title")]
    public string Title { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("evidence")]
    public string Evidence { get; set; } = string.Empty;

    [JsonPropertyName("matchedSignature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MatchedSignature { get; set; }

    [JsonPropertyName("evidenceType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EvidenceType { get; set; }

    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Severity levels for detected flags.
/// </summary>
public static class Severity
{
    public const string Low = "LOW";
    public const string Medium = "MEDIUM";
    public const string High = "HIGH";
}

/// <summary>
/// Verdict levels based on aggregated flags.
/// </summary>
public static class Verdict
{
    public const string Clean = "CLEAN";
    public const string Suspicious = "SUSPICIOUS";
    public const string Flagged = "FLAGGED";
}
