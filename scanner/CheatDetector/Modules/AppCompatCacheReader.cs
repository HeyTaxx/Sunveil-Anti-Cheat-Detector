using Microsoft.Win32;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Reads AppCompatCache (ShimCache) from the SYSTEM registry hive to detect
/// previously executed cheat applications. Entries are written on shutdown.
/// </summary>
public class AppCompatCacheReader
{
    private const string ModuleName = "AppCompatCacheReader";
    private const string CachePath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Reading AppCompatCache (ShimCache)...");
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CachePath);
            if (key == null)
            {
                Console.WriteLine("  [!] AppCompatCache key not found.");
                return flags;
            }
            byte[]? cacheData = key.GetValue("AppCompatCache") as byte[];
            if (cacheData == null || cacheData.Length < 100)
            {
                Console.WriteLine("  [!] AppCompatCache data is empty or too small.");
                return flags;
            }
            // Extract readable strings from the binary cache data
            var paths = ExtractUnicodeStrings(cacheData, minLength: 6);
            Console.WriteLine($"  [*] Extracted {paths.Count} path strings from ShimCache.");
            foreach (string path in paths)
            {
                string lowerPath = path.ToLowerInvariant();
                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (lowerPath.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName, Severity = Severity.Medium,
                            Title = "Cheat Client in AppCompatCache",
                            Description = $"ShimCache entry contains path matching '{cheat}'. This indicates past execution.",
                            Evidence = $"Path: {path}, Match: '{cheat}'"
                        });
                    }
                }
                string[] susTools = { "cheatengine", "processhacker", "x64dbg", "injector" };
                foreach (string tool in susTools)
                {
                    if (lowerPath.Contains(tool))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName, Severity = Severity.Medium,
                            Title = "Suspicious Tool in AppCompatCache",
                            Description = $"ShimCache contains path matching '{tool}'.",
                            Evidence = $"Path: {path}"
                        });
                    }
                }
            }
        }
        catch (Exception ex) { Console.WriteLine($"  [!] AppCompatCache error: {ex.Message}"); }
        return flags;
    }

    /// <summary>
    /// Extracts Unicode strings from binary data (simplified parser for path extraction).
    /// </summary>
    private static List<string> ExtractUnicodeStrings(byte[] data, int minLength)
    {
        var results = new List<string>();
        var current = new List<char>();
        for (int i = 0; i < data.Length - 1; i += 2)
        {
            char c = (char)(data[i] | (data[i + 1] << 8));
            if (c >= 0x20 && c < 0x7F)
            {
                current.Add(c);
            }
            else
            {
                if (current.Count >= minLength)
                {
                    string s = new string(current.ToArray());
                    if (s.Contains('\\') || s.Contains('/')) results.Add(s);
                }
                current.Clear();
            }
        }
        if (current.Count >= minLength)
        {
            string s = new string(current.ToArray());
            if (s.Contains('\\') || s.Contains('/')) results.Add(s);
        }
        return results.Distinct().ToList();
    }
}
