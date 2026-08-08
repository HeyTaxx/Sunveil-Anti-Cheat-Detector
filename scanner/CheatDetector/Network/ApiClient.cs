using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CheatDetector.Models;
using CheatDetector.Core;

namespace CheatDetector.Network;

/// <summary>
/// HTTP client for uploading scan reports to the web API.
/// </summary>
public class ApiClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public ApiClient(string baseUrl)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>
    /// Uploads a scan result to the API and returns the report URL.
    /// </summary>
    public async Task<string?> UploadReportAsync(ScanResult result, string apiKey)
    {
        Console.WriteLine($"  [*] Uploading telemetry report to {_baseUrl}...");

        // 1. Try primary Node.js Express API (/api/reports)
        try
        {
            string jsonNode = ReportGenerator.ToJson(result);
            using var contentNode = new StringContent(jsonNode, Encoding.UTF8, "application/json");
            
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/api/reports");
            request.Content = contentNode;

            var responseNode = await _http.SendAsync(request);
            if (responseNode.IsSuccessStatusCode)
            {
                var responseBody = await responseNode.Content.ReadFromJsonAsync<UploadResponse>();
                string reportUrl = responseBody?.ReportUrl ?? $"{_baseUrl}/report.html?id={result.ReportId}";
                Console.WriteLine($"  [+] Upload successful! Telemetry stored securely.");
                return reportUrl;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Express API upload skipped: {ex.Message}. Trying PHP fallback...");
        }

        // 2. Fallback to PHP backend (/upload.php)
        try
        {
            var payload = new
            {
                player_name = result.SystemInfo.Username,
                hwid = result.SystemInfo.HardwareId,
                flags = result.Flags
            };

            string jsonPhp = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            using var contentPhp = new StringContent(jsonPhp, Encoding.UTF8, "application/json");
            using var requestPhp = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/upload.php");
            requestPhp.Headers.Add("X-API-Key", apiKey);
            requestPhp.Content = contentPhp;

            var responsePhp = await _http.SendAsync(requestPhp);

            if (responsePhp.IsSuccessStatusCode)
            {
                var responseBody = await responsePhp.Content.ReadFromJsonAsync<UploadResponse>();
                string reportId = responseBody?.ReportId ?? responseBody?.ReportIdPhp ?? result.ReportId;
                string reportUrl = $"{_baseUrl}/report.html?id={reportId}";
                Console.WriteLine($"  [+] Upload successful via PHP backend!");
                return reportUrl;
            }
            else
            {
                Console.WriteLine($"  [!] Upload failed: HTTP {(int)responsePhp.StatusCode}");
                string body = await responsePhp.Content.ReadAsStringAsync();
                Console.WriteLine($"  [!] Response: {body}");
                return null;
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"  [!] Connection error: {ex.Message}");
            Console.WriteLine($"  [!] Is the webhost accessible at {_baseUrl}?");
            return null;
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("  [!] Upload timed out after 30 seconds.");
            return null;
        }
    }

    private class UploadResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("reportUrl")]
        public string? ReportUrl { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("reportId")]
        public string? ReportId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("report_id")]
        public string? ReportIdPhp { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("success")]
        public bool Success { get; set; }
    }
}
