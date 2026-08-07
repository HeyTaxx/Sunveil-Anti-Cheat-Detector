using System.IO;
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

    public List<Flag> Scan(Action<string>? onItemScanned = null)
    {
        var flags = new List<Flag>();

        // Find all possible minecraft instance directories
        var instanceDirs = FindMinecraftInstances();
        foreach (var dir in instanceDirs)
        {
            onItemScanned?.Invoke($"Scanning instance: {dir}");
            ScanMinecraftDirectory(dir, flags, onItemScanned);
        }

        ScanTempDirectories(flags, onItemScanned);
        ScanDownloadsDirectory(flags, onItemScanned);
        ScanRecycleBin(flags, onItemScanned);
        ScanEntirePC(flags, onItemScanned);

        return flags;
    }

    private List<string> FindMinecraftInstances()
    {
        var dirs = new List<string>();
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
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

    private void ScanMinecraftDirectory(string mcDir, List<Flag> flags, Action<string>? onItemScanned)
    {
        if (!Directory.Exists(mcDir)) return;

        foreach (string relPath in CheatSignatures.SuspiciousMinecraftPaths)
        {
            string fullPath = Path.Combine(mcDir, relPath);
            onItemScanned?.Invoke($"Inspecting path: {fullPath}");
            bool exists = Directory.Exists(fullPath) || File.Exists(fullPath);

            if (exists)
            {
                flags.Add(new Flag
                {
                    Module = ModuleName, Severity = Severity.High,
                    Title = "Cheat Client Files Found",
                    Description = $"Suspicious path '{relPath}' exists in Minecraft directory.",
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
                    onItemScanned?.Invoke($"Scanning JAR: {Path.GetFileName(jar)}");
                    string jarName = Path.GetFileName(jar).ToLowerInvariant();

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

                    // Deep Package Scan inside JAR
                    try
                    {
                        using var zip = ZipFile.OpenRead(jar);
                        var matchedPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        foreach (var entry in zip.Entries)
                        {
                            string entryLower = entry.FullName.ToLowerInvariant();

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
                    catch { /* Ignore invalid zip */ }
                }
            }
            catch { }
        }

        // Check resourcepacks folder
        string resourcePacksDir = Path.Combine(mcDir, "resourcepacks");
        if (Directory.Exists(resourcePacksDir))
        {
            try
            {
                var entries = Directory.GetFileSystemEntries(resourcePacksDir, "*", SearchOption.TopDirectoryOnly);
                foreach (var entry in entries)
                {
                    onItemScanned?.Invoke($"Scanning Resource Pack: {Path.GetFileName(entry)}");
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
            catch { }
        }

        // Check versions folder
        string versionsDir = Path.Combine(mcDir, "versions");
        if (Directory.Exists(versionsDir))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(versionsDir))
                {
                    onItemScanned?.Invoke($"Scanning Version: {Path.GetFileName(dir)}");
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
            catch { }
        }
    }

    private void ScanTempDirectories(List<Flag> flags, Action<string>? onItemScanned)
    {
        string[] tempPaths = {
            Environment.GetEnvironmentVariable("TEMP") ?? "",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        foreach (string tempPath in tempPaths.Where(p => !string.IsNullOrEmpty(p) && Directory.Exists(p)))
        {
            onItemScanned?.Invoke($"Scanning Temp directory: {tempPath}");
            try
            {
                var entries = Directory.GetFileSystemEntries(tempPath, "*", SearchOption.TopDirectoryOnly);
                foreach (var entry in entries)
                {
                    onItemScanned?.Invoke($"Temp entry: {Path.GetFileName(entry)}");
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
            catch { }
        }
    }

    private void ScanDownloadsDirectory(List<Flag> flags, Action<string>? onItemScanned)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");

        if (!Directory.Exists(downloadsPath)) return;

        onItemScanned?.Invoke($"Scanning Downloads directory: {downloadsPath}");
        try
        {
            var entries = Directory.GetFileSystemEntries(downloadsPath, "*", SearchOption.TopDirectoryOnly);
            foreach (var entry in entries)
            {
                onItemScanned?.Invoke($"Download file: {Path.GetFileName(entry)}");
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
                    }
                }
            }
        }
        catch { }
    }

    private void ScanRecycleBin(List<Flag> flags, Action<string>? onItemScanned)
    {
        onItemScanned?.Invoke("Scanning Recycle Bin ($Recycle.Bin)...");
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
                        onItemScanned?.Invoke($"Recycle Bin entry: {Path.GetFileName(file)}");
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
                catch { }
            }
        }
        catch { }
    }

    private void ScanEntirePC(List<Flag> flags, Action<string>? onItemScanned)
    {
        onItemScanned?.Invoke("Performing Full Drive Forensic Search...");
        
        var enumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            ReturnSpecialDirectories = false
        };

        foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
        {
            onItemScanned?.Invoke($"Scanning Drive {drive.Name}...");
            try
            {
                string[] targetExtensions = { "*.jar", "*.zip", "*.exe" };

                foreach (string ext in targetExtensions)
                {
                    var files = Directory.EnumerateFiles(drive.RootDirectory.Name, ext, enumOptions);
                    foreach (var file in files)
                    {
                        if (file.StartsWith(Path.Combine(drive.Name, "Windows"), StringComparison.OrdinalIgnoreCase))
                            continue;

                        onItemScanned?.Invoke($"Drive file: {file}");
                        string fileName = Path.GetFileName(file).ToLowerInvariant();
                        foreach (string cheat in CheatSignatures.KnownClients)
                        {
                            if (fileName.Contains(cheat))
                            {
                                flags.Add(new Flag
                                {
                                    Module = ModuleName, Severity = Severity.High,
                                    Title = "Cheat File Found on System",
                                    Description = $"A file matching '{cheat}' was found on the system.",
                                    Evidence = $"Path: {file}"
                                });
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}
