using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using CheatDetector.Models;

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
        Console.WriteLine($"  [*] Uploading report to {_baseUrl}/upload.php...");
        try
        {
            // Structure payload for PHP backend
            var payload = new
            {
                player_name = result.SystemInfo.Username,
                hwid = result.SystemInfo.HardwareId,
                flags = result.Flags
            };

            string json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            _http.DefaultRequestHeaders.Clear();
            _http.DefaultRequestHeaders.Add("X-API-Key", apiKey);

            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{_baseUrl}/upload.php", content);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadFromJsonAsync<UploadResponse>();
                string reportId = responseBody?.ReportId ?? result.ReportId;
                string reportUrl = $"{_baseUrl}/admin_v2.html"; // The dashboard URL
                Console.WriteLine($"  [+] Upload successful! Telemetry stored securely.");
                return reportUrl;
            }
            else
            {
                Console.WriteLine($"  [!] Upload failed: HTTP {(int)response.StatusCode}");
                string body = await response.Content.ReadAsStringAsync();
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
        public string ReportUrl { get; set; } = "";
        public string ReportId { get; set; } = "";
        public bool Success { get; set; }
    }
}
