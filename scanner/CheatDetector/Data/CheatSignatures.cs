namespace CheatDetector.Data;

public record JarPackageSignature(string Package, string Label, string Severity, string Description);

/// <summary>
/// Static database of known Minecraft cheat client signatures, suspicious JVM arguments,
/// DLL patterns, and file paths used for detection across all scanner modules.
/// </summary>
public static class CheatSignatures
{
    /// <summary>
    /// Known cheat client names used for process, file, and memory scanning.
    /// </summary>
    public static readonly string[] KnownClients = new[]
    {
        // --- Popular Cheat Clients (Refined to prevent false positives) ---
        "wurst-client", "wurstclient", "impact-client", "impactclient", 
        "aristois", "meteor-client", "meteorclient", "sigma-client", "sigmaclient",
        "liquidbounce", "future-client", "futureclient", "rusherhack", "inertia-client",
        "kami-blue", "salhack", "forgehax", "nodus", "huzuni",
        "wolfram", "vape.gg", "drip.gg", "exhibition-client", "rise-client", "riseclient",
        "novoline", "fdpclient", "azura-client", "skilled-client",
        "entropy-client", "remix-client", "moon-client", "moonclient", "pandaware",

        // --- Ghost Clients & Injectors ---
        "vape-v4", "vape-lite", "whiteout-client", "dream-client",
        "antic-client", "crypt-client", "phantom-client",

        // --- Xray / Utility Mods ---
        "xray", "x-ray", "xraymod", "baritone", "freecam",
        "killaura", "nuker", "scaffold", "autofish",

        // --- Injectors & Loaders ---
        "cheatbreaker", "weepcraft", "wizardhax",
        "mchacks", "minecrafthax"
    };

    /// <summary>
    /// Memory strings that indicate cheat client presence in process memory.
    /// </summary>
    public static readonly string[] MemorySignatures = new[]
    {
        // Standard Cheats
        "meteor-client", "impact client", "wurst client",
        "aristois", "liquidbounce", "sigma client",
        "future client", "rusherhack", "salhack",
        "killaura", "scaffold", "fly hack",
        "speed hack", "reach modifier", "auto clicker",
        "aimbot", "triggerbot", "esp module",
        "xray module", "nuker module", "freecam",
        "no fall", "no slow", "anti knockback",
        "chest stealer", "inventory manager hack",
        "timer hack", "blink module", "velocity modifier",

        // Baritone Pathfinder (automated cheating)
        "baritone.api.pathing", "baritone.settings",
        "baritone.process.elytrap", "baritoneapi.getprovider",
        "baritone.cache.worlddata", "ibaritone",
        "pathingbehavior", "baritone.utils.helper",

        // Deep Ghost Client / Legacy Signatures (Silent Scanner)
        "/AVIX-Config", "trumpclientftw_bape", "dg82fo.pw",
        "nG@W", "G0ttaDipMen.java", "Harambe.png", "czaarek99",
        "+(M0G.V", "dinkio", "Sa_Vc", "5d@56", "TCNH$1",
        "onetap.cc", "bspkrs.IlIIIlIlIllIIlllIllIllIII",
        "com/sun/jna/z/Main", "/a.class:::0", "hi.a2",
        "0SO1Lk2KASxzsd", "yCcADi", "74.91.125.194", "kc((k",
        "JNativeHook", "144.217.241.181", "/tcpnodelaymod/COM1"
    };

    /// <summary>
    /// Java package paths (as stored inside JAR/ZIP files) to scan for in deep JAR analysis.
    /// Each package path uses forward-slash notation matching ZIP entry names.
    /// </summary>
    public static readonly JarPackageSignature[] JarPackageSignatures = new[]
    {
        new JarPackageSignature("baritone/api",               "Baritone API",        Models.Severity.High,   "Baritone pathfinding cheat (automated movement/mining)"),
        new JarPackageSignature("baritone/process",           "Baritone Process",    Models.Severity.High,   "Baritone process controller"),
        new JarPackageSignature("baritone/cache",             "Baritone Cache",      Models.Severity.High,   "Baritone world cache — stores exploration data for cheating"),
        new JarPackageSignature("net/ccbluex/liquidbounce",   "LiquidBounce",        Models.Severity.High,   "LiquidBounce open-source cheat client"),
        new JarPackageSignature("net/wurstclient",            "Wurst Client",        Models.Severity.High,   "Wurst cheat client"),
        new JarPackageSignature("meteorclient",               "Meteor Client",       Models.Severity.High,   "Meteor Client — popular Fabric-based cheat"),
        new JarPackageSignature("me/rigamortis/salhack",      "SalHack",             Models.Severity.High,   "SalHack cheat client"),
        new JarPackageSignature("com/lukflug/panelstudio",    "PanelStudio GUI",     Models.Severity.High,   "PanelStudio GUI framework used by Vape and ghost clients"),
        new JarPackageSignature("at/favre/lib/crypto",        "Favre Crypto Lib",    Models.Severity.Medium, "Crypto lib (at.favre.lib.crypto) used by obfuscated cheat clients"),
        new JarPackageSignature("cn/stars",                   "Stars Client (CN)",   Models.Severity.High,   "Chinese-origin ghost client package"),
        new JarPackageSignature("com/georgenadejde/killaura", "KillAura Module",     Models.Severity.High,   "Standalone KillAura cheat module"),
        new JarPackageSignature("net/minecraft/src/hack",     "Legacy Hack Base",    Models.Severity.High,   "Legacy hacked Minecraft client base package"),
        new JarPackageSignature("optifine/shadersmod",        "ShadersMod Spoof",    Models.Severity.Medium, "Cheat client disguised as ShadersMod"),
    };

    /// <summary>
    /// Suspicious JVM arguments that may indicate code injection or agent loading.
    /// </summary>
    public static readonly string[] SuspiciousJvmArgs = new[]
    {
        "-javaagent:",
        "-agentlib:",
        "-agentpath:",
        "-Xbootclasspath",
        "-noverify",
        "-XX:+DisableAttachMechanism",
        "-XX:+AllowUserSignalHandlers",
        "-Djava.system.class.loader",
        "--patch-module",
        "--add-opens java.base"
    };

    /// <summary>
    /// Suspicious DLL file name patterns that may indicate injection.
    /// </summary>
    public static readonly string[] SuspiciousDllPatterns = new[]
    {
        "inject", "hook", "hack", "cheat",
        "d3d9_hook", "d3d11_hook", "opengl32_hook",
        "dinput8", "dxgi_hook",
        "minhook", "detours",
        "imgui"  // Often used in cheat GUIs
    };

    /// <summary>
    /// Known legitimate DLLs loaded by javaw.exe (whitelist for DLL injection check).
    /// </summary>
    public static readonly string[] JavaWhitelistDlls = new[]
    {
        "jvm.dll", "java.dll", "verify.dll", "zip.dll",
        "net.dll", "nio.dll", "management.dll",
        "awt.dll", "fontmanager.dll", "javaaccessbridge.dll",
        "lwjgl", "openal", "glfw", "jinput",
        "ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "shell32.dll", "ole32.dll",
        "msvcrt.dll", "ucrtbase.dll", "vcruntime",
        "msvcp", "combase.dll", "rpcrt4.dll",
        "sechost.dll", "bcrypt.dll", "bcryptprimitives.dll",
        "nsi.dll", "ws2_32.dll", "dnsapi.dll",
        "opengl32.dll", "d3d11.dll", "dxgi.dll",
        "nvidia", "amd", "ati", "intel",
        "igx", "nvoglv", "atig",
        "dbghelp.dll", "version.dll", "winmm.dll",
        "imm32.dll", "setupapi.dll", "cfgmgr32.dll",
        "powrprof.dll", "crypt32.dll", "wintrust.dll"
    };

    /// <summary>
    /// File paths relative to %APPDATA%/.minecraft/ that are suspicious.
    /// </summary>
    public static readonly string[] SuspiciousMinecraftPaths = new[]
    {
        "mods\\wurst",
        "mods\\impact",
        "mods\\meteor-client",
        "mods\\aristois",
        "mods\\liquidbounce",
        "mods\\sigma",
        "mods\\future",
        "mods\\rusherhack",
        "mods\\salhack",
        "mods\\inertia",
        "mods\\kami-blue",
        "mods\\forgehax",
        "versions\\Impact",
        "versions\\Wurst",
        "versions\\Sigma",
        "versions\\LiquidBounce",
        "versions\\Future",
        ".meteor",
        ".wurst",
        ".impact",
        ".aristois",
        ".liquidbounce",
        ".salhack",
        ".rusherhack",
        "baritone\\settings.txt"
    };

    /// <summary>
    /// Directories to scan for deleted/temp cheat traces.
    /// </summary>
    public static readonly string[] TempScanDirectories = new[]
    {
        "%TEMP%",
        "%LOCALAPPDATA%\\Temp",
        "%APPDATA%",
        "%LOCALAPPDATA%"
    };

    /// <summary>
    /// Known cheat domains to search for in a privacy-preserving local browser scan.
    /// </summary>
    public static readonly string[] SuspiciousDomains = new[]
    {
        "vape.gg", "meteorclient.com", "wurstclient.net",
        "aristois.net", "liquidbounce.net", "sigmaclient.info",
        "futureclient.net", "rusherhack.org", "inertia.gg",
        "drip.gg", "novoline.wtf", "riseclient.com",
        "fdpclient.com", "intent.store", "spezz.exchange"
    };

    /// <summary>
    /// Signatures for illegal Resource Packs (like X-Ray).
    /// </summary>
    public static readonly string[] IllegalResourcePacks = new[]
    {
        "xray", "x-ray", "xray_ultimate", "x-ray-ultimate",
        "find-diamonds", "cave-finder", "ore-finder", "ore_esp"
    };
}
