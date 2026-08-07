using System.IO;
using Microsoft.Win32;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Reads AppCompatCache (ShimCache) from the SYSTEM registry hive to detect
/// previously executed cheat applications.
/// </summary>
public class AppCompatCacheReader
{
    private const string ModuleName = "AppCompatCacheReader";

    public List<Flag> Scan(Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();
        Console.WriteLine("  [*] Reading AppCompatCache (ShimCache)...");

        try
        {
            using var hklm = Registry.LocalMachine;
            using var shimKey = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
            if (shimKey == null) return flags;

            byte[]? cacheData = shimKey.GetValue("AppCompatCache") as byte[];
            if (cacheData == null || cacheData.Length == 0) return flags;

            var paths = ExtractUnicodeStrings(cacheData);

            foreach (string rawPath in paths)
            {
                onItemScanned?.Invoke($"ShimCache entry: {rawPath}");
                string lowerPath = rawPath.ToLowerInvariant();
                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (lowerPath.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName,
                            Severity = Severity.Medium,
                            Title = "Cheat Execution Trace in AppCompatCache (ShimCache)",
                            Description = $"ShimCache entry '{rawPath}' matches known cheat client '{cheat}'.",
                            Evidence = $"Path: {rawPath}, Match: '{cheat}'"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] AppCompatCache error: {ex.Message}");
        }

        return flags;
    }

    private static List<string> ExtractUnicodeStrings(byte[] data)
    {
        var strings = new List<string>();
        int minLength = 6;

        for (int i = 0; i < data.Length - 1; i += 2)
        {
            if (data[i] >= 32 && data[i] <= 126 && data[i + 1] == 0)
            {
                int start = i;
                int len = 0;

                while (i < data.Length - 1 && data[i] >= 32 && data[i] <= 126 && data[i + 1] == 0)
                {
                    len++;
                    i += 2;
                }

                if (len >= minLength)
                {
                    char[] chars = new char[len];
                    for (int j = 0; j < len; j++)
                    {
                        chars[j] = (char)data[start + j * 2];
                    }
                    string str = new string(chars);
                    if (str.Contains('\\') || str.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        strings.Add(str);
                    }
                }
            }
        }

        return strings;
    }
}
