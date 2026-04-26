using Microsoft.Win32;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Reads the Windows UserAssist registry entries to detect GUI-launched cheat applications.
/// UserAssist tracks applications launched via Windows Explorer and stores them
/// with ROT13-obfuscated names.
/// </summary>
public class UserAssistReader
{
    private const string ModuleName = "UserAssistReader";
    private static readonly string[] UserAssistGuids = new[]
    {
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
    };
    private const string UserAssistBasePath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Reading UserAssist registry...");
        try
        {
            using var hkcu = Registry.CurrentUser;
            foreach (string guid in UserAssistGuids)
            {
                string keyPath = $@"{UserAssistBasePath}\{guid}\Count";
                using var countKey = hkcu.OpenSubKey(keyPath);
                if (countKey == null) continue;
                string[] valueNames = countKey.GetValueNames();
                Console.WriteLine($"  [*] Found {valueNames.Length} UserAssist entries in {guid[..8]}...");
                foreach (string encodedName in valueNames)
                {
                    string decodedName = DecodeRot13(encodedName).ToLowerInvariant();
                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (decodedName.Contains(cheat))
                        {
                            byte[]? data = countKey.GetValue(encodedName) as byte[];
                            string runInfo = ParseUserAssistData(data);
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.Medium,
                                Title = "Cheat Client in UserAssist History",
                                Description = $"UserAssist entry '{decodedName}' matches cheat '{cheat}'. {runInfo}",
                                Evidence = $"Decoded: {decodedName}, ROT13: {encodedName}, {runInfo}"
                            });
                        }
                    }
                    string[] susTools = { "cheatengine", "processhacker", "x64dbg", "injector", "extremeinjector" };
                    foreach (string tool in susTools)
                    {
                        if (decodedName.Contains(tool))
                        {
                            byte[]? data = countKey.GetValue(encodedName) as byte[];
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.Medium,
                                Title = "Suspicious Tool in UserAssist",
                                Description = $"UserAssist entry for '{tool}' detected. {ParseUserAssistData(data)}",
                                Evidence = $"Decoded: {decodedName}"
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex) { Console.WriteLine($"  [!] UserAssist error: {ex.Message}"); }
        return flags;
    }

    private static string DecodeRot13(string input)
    {
        char[] result = new char[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            if (c >= 'a' && c <= 'z') result[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') result[i] = (char)('A' + (c - 'A' + 13) % 26);
            else result[i] = c;
        }
        return new string(result);
    }

    private static string ParseUserAssistData(byte[]? data)
    {
        if (data == null || data.Length < 72) return "Run data: unavailable";
        try
        {
            uint runCount = BitConverter.ToUInt32(data, 4);
            long fileTime = BitConverter.ToInt64(data, 60);
            DateTime lastRun = fileTime > 0 ? DateTime.FromFileTimeUtc(fileTime) : DateTime.MinValue;
            string lastRunStr = lastRun > DateTime.MinValue ? lastRun.ToString("u") : "unknown";
            return $"Run Count: {runCount}, Last Run: {lastRunStr}";
        }
        catch { return "Run data: parse error"; }
    }
}
