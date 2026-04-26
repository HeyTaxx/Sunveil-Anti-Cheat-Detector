using System.Text.Json.Serialization;

namespace CheatDetector.Models;

/// <summary>
/// System metadata collected during the scan for identification purposes.
/// </summary>
public class SystemInfo
{
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("os")]
    public string OperatingSystem { get; set; } = string.Empty;

    [JsonPropertyName("hwid")]
    public string HardwareId { get; set; } = string.Empty;

    [JsonPropertyName("dotnetVersion")]
    public string DotNetVersion { get; set; } = string.Empty;

    [JsonPropertyName("cpuName")]
    public string CpuName { get; set; } = string.Empty;

    [JsonPropertyName("ramTotalGb")]
    public double RamTotalGb { get; set; }
}
