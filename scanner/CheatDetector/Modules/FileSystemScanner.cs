using System.IO.Compression;
using CheatDetector.Models;
using CheatDetector.Data;

namespace CheatDetector.Modules;

/// <summary>
/// Scans the file system for traces of cheat clients in key directories:
/// %APPDATA%\.minecraft\, %TEMP%, Recycle Bin ($Recycle.Bin), and %LOCALAPPDATA%.
/// </summary>
public class FileSystemScanner
{
    private const string ModuleName = "FileSystemScanner";

    public List<Flag> Scan()
    {
        var flags = new List<Flag>();

        // Find all possible minecraft instance directories
        var instanceDirs = FindMinecraftInstances();
        foreach (var dir in instanceDirs)
        {
            ScanMinecraftDirectory(dir, flags);
        }

        ScanTempDirectories(flags);
        ScanDownloadsDirectory(flags);
        ScanRecycleBin(flags);
        ScanEntirePC(flags);

        return flags;
    }

    private List<string> FindMinecraftInstances()
    {
        var dirs = new List<string>();
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Vanilla
        string vanilla = Path.Combine(appData, ".minecraft");
        if (Directory.Exists(vanilla)) dirs.Add(vanilla);

        // Alternative Launchers
        string[] altPaths = {
            Path.Combine(appData, "PrismLauncher", "instances"),
            Path.Combine(appData, "ModrinthApp", "profiles"),
            Path.Combine(appData, "gdlauncher_next", "instances"),
            Path.Combine(userProfile, "curseforge", "minecraft", "Instances")
        };

        foreach (string basePath in altPaths)
        {
            if (Directory.Exists(basePath))
            {
                try
                {
                    dirs.AddRange(Directory.GetDirectories(basePath));
                }
                catch { /* Ignore access errors */ }
            }
        }

        return dirs;
    }

    private void ScanMinecraftDirectory(string mcDir, List<Flag> flags)
    {
        if (!Directory.Exists(mcDir)) return;

        Console.WriteLine($"  [*] Scanning {mcDir}...");

        foreach (string relPath in CheatSignatures.SuspiciousMinecraftPaths)
        {
            string fullPath = Path.Combine(mcDir, relPath);
            bool exists = Directory.Exists(fullPath) || File.Exists(fullPath);

            if (exists)
            {
                string cheatMatch = relPath.Split('\\').Last().ToLowerInvariant();
                flags.Add(new Flag
                {
                    Module = ModuleName, Severity = Severity.High,
                    Title = "Cheat Client Files Found",
                    Description = $"Suspicious path '{relPath}' exists in .minecraft directory.",
                    Evidence = $"Full Path: {fullPath}, Exists: true"
                });
            }
        }

        // Scan mods folder for suspicious JAR files
        string modsDir = Path.Combine(mcDir, "mods");
        if (Directory.Exists(modsDir))
        {
            try
            {
                foreach (var jar in Directory.GetFiles(modsDir, "*.jar", SearchOption.TopDirectoryOnly))
                {
                    string jarName = Path.GetFileName(jar).ToLowerInvariant();
                    // 1. Check File Name
                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (jarName.Contains(cheat))
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.High,
                                Title = "Cheat Mod JAR Detected",
                                Description = $"JAR file '{Path.GetFileName(jar)}' matches cheat '{cheat}'.",
                                Evidence = $"File: {jar}"
                            });
                        }
                    }

                    // 2. Deep Package Scan inside JAR — detect cheat classes by Java package path
                    try
                    {
                        using var zip = ZipFile.OpenRead(jar);
                        var matchedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        foreach (var entry in zip.Entries)
                        {
                            string entryLower = entry.FullName.ToLowerInvariant();

                            // Package scan: check .class entry paths against known cheat packages
                            if (entryLower.EndsWith(".class"))
                            {
                                foreach (var sig in CheatSignatures.JarPackageSignatures)
                                {
                                    string pkgPrefix = sig.Package.ToLowerInvariant() + "/";
                                    if (!matchedPackages.Contains(sig.Package) && entryLower.StartsWith(pkgPrefix))
                                    {
                                        matchedPackages.Add(sig.Package);
                                        flags.Add(new Flag
                                        {
                                            Module = ModuleName, Severity = sig.Severity,
                                            Title = $"Cheat Package Detected in JAR: {sig.Label}",
                                            Description = sig.Description,
                                            Evidence = $"File: {jar} | Class: {entry.FullName} | Package: {sig.Package.Replace('/', '.')}",
                                            MatchedSignature = sig.Package,
                                            EvidenceType = "JAR_PACKAGE"
                                        });
                                        break;
                                    }
                                }
                            }

                            // Mixin config scan: cheat clients embed *.mixins.json
                            if (entryLower.EndsWith(".mixins.json"))
                            {
                                string mixinKey = "mixin:" + entryLower;
                                if (!matchedPackages.Contains(mixinKey))
                                {
                                    foreach (string cheat in CheatSignatures.KnownClients)
                                    {
                                        if (entryLower.Contains(cheat))
                                        {
                                            matchedPackages.Add(mixinKey);
                                            flags.Add(new Flag
                                            {
                                                Module = ModuleName, Severity = Severity.High,
                                                Title = $"Cheat Mixin Config Found in JAR",
                                                Description = $"JAR contains a mixin config file from a known cheat client ('{cheat}').",
                                                Evidence = $"File: {jar} | Mixin Config: {entry.FullName}",
                                                MatchedSignature = entry.FullName,
                                                EvidenceType = "JAR_ENTRY"
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { /* Ignore if file is locked or not a valid ZIP */ }
                }
            }
            catch (Exception ex) { Console.WriteLine($"  [!] Mods scan error: {ex.Message}"); }
        }

        // Check resourcepacks folder for X-Ray
        string resourcePacksDir = Path.Combine(mcDir, "resourcepacks");
        if (Directory.Exists(resourcePacksDir))
        {
            try
            {
                var entries = Directory.GetFileSystemEntries(resourcePacksDir, "*", SearchOption.TopDirectoryOnly);
                foreach (var entry in entries)
                {
                    string entryName = Path.GetFileName(entry).ToLowerInvariant();
                    foreach (string xraySig in CheatSignatures.IllegalResourcePacks)
                    {
                        if (entryName.Contains(xraySig))
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.Medium,
                                Title = "Illegal Resource Pack Detected",
                                Description = $"Found potential X-Ray pack: '{Path.GetFileName(entry)}'.",
                                Evidence = $"Path: {entry}"
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"  [!] Resource pack scan error: {ex.Message}"); }
        }

        // Check versions folder for cheat client versions
        string versionsDir = Path.Combine(mcDir, "versions");
        if (Directory.Exists(versionsDir))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(versionsDir))
                {
                    string dirName = Path.GetFileName(dir).ToLowerInvariant();
                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (dirName.Contains(cheat))
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.High,
                                Title = "Cheat Client Version Folder",
                                Description = $"Version folder '{Path.GetFileName(dir)}' matches '{cheat}'.",
                                Evidence = $"Path: {dir}"
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"  [!] Versions scan error: {ex.Message}"); }
        }
    }

    private void ScanTempDirectories(List<Flag> flags)
    {
        string[] tempPaths = {
            Environment.GetEnvironmentVariable("TEMP") ?? "",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        foreach (string tempPath in tempPaths.Where(p => !string.IsNullOrEmpty(p) && Directory.Exists(p)))
        {
            Console.WriteLine($"  [*] Scanning {tempPath}...");
            try
            {
                var entries = Directory.GetFileSystemEntries(tempPath, "*", SearchOption.TopDirectoryOnly);
                foreach (var entry in entries)
                {
                    string name = Path.GetFileName(entry).ToLowerInvariant();
                    foreach (string cheat in CheatSignatures.KnownClients)
                    {
                        if (name.Contains(cheat))
                        {
                            flags.Add(new Flag
                            {
                                Module = ModuleName, Severity = Severity.Low,
                                Title = "Cheat Trace in Temp Directory",
                                Description = $"Temp entry '{Path.GetFileName(entry)}' matches '{cheat}'.",
                                Evidence = $"Path: {entry}"
                            });
                        }
                    }
                }
            }
            catch { /* Access errors in temp are common */ }
        }
    }

    private void ScanDownloadsDirectory(List<Flag> flags)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");

        if (!Directory.Exists(downloadsPath)) return;

        Console.WriteLine($"  [*] Scanning {downloadsPath}...");
        try
        {
            var entries = Directory.GetFileSystemEntries(downloadsPath, "*", SearchOption.TopDirectoryOnly);
            foreach (var entry in entries)
            {
                string name = Path.GetFileName(entry).ToLowerInvariant();
                foreach (string cheat in CheatSignatures.KnownClients)
                {
                    if (name.Contains(cheat))
                    {
                        flags.Add(new Flag
                        {
                            Module = ModuleName, Severity = Severity.Medium,
                            Title = "Cheat Trace in Downloads Directory",
                            Description = $"Download entry '{Path.GetFileName(entry)}' matches '{cheat}'.",
                            Evidence = $"Path: {entry}"
                        });
                        // Don't break here, so we log all matches if multiple keywords match
                    }
                }
            }
        }
        catch { /* Ignore access errors */ }
    }

    private void ScanRecycleBin(List<Flag> flags)
    {
        Console.WriteLine("  [*] Scanning Recycle Bin...");
        try
        {
            string recyclePath = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, "$Recycle.Bin");
            if (!Directory.Exists(recyclePath)) return;

            foreach (var userDir in Directory.GetDirectories(recyclePath))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(userDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        string fileName = Path.GetFileName(file).ToLowerInvariant();
                        foreach (string cheat in CheatSignatures.KnownClients)
                        {
                            if (fileName.Contains(cheat))
                            {
                                flags.Add(new Flag
                                {
                                    Module = ModuleName, Severity = Severity.Medium,
                                    Title = "Deleted Cheat File in Recycle Bin",
                                    Description = $"Recycle Bin file matches '{cheat}'.",
                                    Evidence = $"File: {file}"
                                });
                            }
                        }
                    }
                }
                catch { /* SID directories often deny access */ }
            }
        }
        catch (Exception ex) { Console.WriteLine($"  [!] Recycle Bin scan error: {ex.Message}"); }
    }

    private void ScanEntirePC(List<Flag> flags)
    {
        Console.WriteLine("  [*] Performing Deep Full-PC Scan (This may take a moment)...");
        
        var enumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            ReturnSpecialDirectories = false
        };

        foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
        {
            Console.WriteLine($"      -> Scanning Drive {drive.Name}");
            try
            {
                // We primarily look for .jar and .zip files across the whole PC to save time.
                // Searching EVERY file extension would be extremely slow.
                string[] targetExtensions = { "*.jar", "*.zip", "*.exe" };

                foreach (string ext in targetExtensions)
                {
                    var files = Directory.EnumerateFiles(drive.RootDirectory.Name, ext, enumOptions);
                    foreach (var file in files)
                    {
                        // Skip Windows folder to save time and avoid false positives
                        if (file.StartsWith(Path.Combine(drive.Name, "Windows"), StringComparison.OrdinalIgnoreCase))
                            continue;

                        string fileName = Path.GetFileName(file).ToLowerInvariant();
                        foreach (string cheat in CheatSignatures.KnownClients)
                        {
                            // If a file anywhere on the PC is named something like "meteor-client.jar"
                            if (fileName.Contains(cheat))
                            {
                                flags.Add(new Flag
                                {
                                    Module = ModuleName, Severity = Severity.High,
                                    Title = "Cheat File Found on System",
                                    Description = $"A file matching '{cheat}' was found hidden on the PC.",
                                    Evidence = $"Path: {file}"
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"      [!] Error scanning drive {drive.Name}: {ex.Message}");
            }
        }
    }
}
