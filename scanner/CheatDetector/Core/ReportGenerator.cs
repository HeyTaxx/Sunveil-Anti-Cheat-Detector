using System.Text.Json;
using CheatDetector.Models;

namespace CheatDetector.Core;

/// <summary>
/// Serializes ScanResult to JSON for file output and API transmission.
/// </summary>
public static class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// Serializes the scan result to a JSON string.
    /// </summary>
    public static string ToJson(ScanResult result)
    {
        return JsonSerializer.Serialize(result, JsonOptions);
    }

    /// <summary>
    /// Saves the scan result to a JSON file on disk.
    /// </summary>
    public static async Task SaveToFileAsync(ScanResult result, string outputPath)
    {
        string json = ToJson(result);
        string? dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        await File.WriteAllTextAsync(outputPath, json);
        Console.WriteLine($"  [*] Report saved to: {outputPath}");
    /// <summary>
    /// Uploads the scan result to the Sunveil Webhost PHP API.
    /// </summary>
    public static async Task UploadToServerAsync(ScanResult result, string apiUrl, string apiKey)
    {
        Console.WriteLine("  [*] Uploading telemetry to Sunveil servers...");
        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("X-API-Key", apiKey);
            
            // Convert to JSON and send
            string json = ToJson(result);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await client.PostAsync(apiUrl, content);
            
            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("  [+] Telemetry securely transmitted.");
            }
            else
            {
                string errorResponse = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"  [!] API Error ({response.StatusCode}): {errorResponse}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Failed to upload telemetry: {ex.Message}");
        }
    }
}
