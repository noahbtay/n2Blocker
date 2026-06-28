using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading.Tasks;

class DnsBlocker
{
    const string HostsFile = @"C:\Windows\System32\drivers\etc\hosts";
    const string BlocklistPath = "blocklist.txt";
    const string BlocklistUrl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
    const string Marker = "# --- DNS-ADBLOCKER ---";

    static async Task Main()
    {
        Console.Title = "DNS Ad Blocker";
        Console.WriteLine("╔══════════════════════════════╗");
        Console.WriteLine("║      DNS Ad Blocker          ║");
        Console.WriteLine("╚══════════════════════════════╝");
        Console.WriteLine();

        if (!IsAdmin())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("ERROR: Right-click the exe and choose 'Run as administrator'.");
            Console.ResetColor();
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
            return;
        }

        // Clean up any previous run that didn't restore
        RemoveOurEntries();

        Console.WriteLine("Loading blocklist...");
        var domains = await GetBlocklist();
        Console.WriteLine($"Loaded {domains.Count:N0} domains to block.");

        Console.WriteLine("Writing to hosts file...");
        InjectHosts(domains);
        FlushDns();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n✓ Ad blocking is ACTIVE.\n");
        Console.ResetColor();
        Console.WriteLine("Blocked domains are being redirected to 0.0.0.0.");
        Console.WriteLine("Keep this window open. Press Q to stop and restore.\n");

        // Keep running, show a heartbeat
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Q) break;
        }

        Restore();
    }

    static async Task<List<string>> GetBlocklist()
    {
        if (!File.Exists(BlocklistPath))
        {
            Console.WriteLine("First run: downloading blocklist (~5 MB)...");
            using var http = new HttpClient();
            http.Timeout = TimeSpan.FromSeconds(60);
            var content = await http.GetStringAsync(BlocklistUrl);
            File.WriteAllText(BlocklistPath, content);
            Console.WriteLine("Blocklist saved.");
        }

        var domains = new List<string>();
        foreach (var line in File.ReadLines(BlocklistPath))
        {
            var l = line.Trim();
            if (l.StartsWith('#') || string.IsNullOrWhiteSpace(l)) continue;
            var parts = l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1"))
            {
                var domain = parts[1].ToLowerInvariant();
                if (domain != "localhost" && !domain.StartsWith('#'))
                    domains.Add(domain);
            }
        }
        return domains;
    }

    static void InjectHosts(List<string> domains)
    {
        // Remove any previous entries first
        RemoveOurEntries();

        var lines = new List<string> { "", Marker };
        lines.AddRange(domains.Select(d => $"0.0.0.0 {d}"));
        lines.Add(Marker);

        File.AppendAllLines(HostsFile, lines);
        Console.WriteLine($"Injected {domains.Count:N0} entries into hosts file.");
    }

    static void RemoveOurEntries()
    {
        if (!File.Exists(HostsFile)) return;

        var original = File.ReadAllLines(HostsFile).ToList();
        var cleaned = new List<string>();
        bool inside = false;

        foreach (var line in original)
        {
            if (line.Trim() == Marker)
            {
                inside = !inside;
                continue;
            }
            if (!inside)
                cleaned.Add(line);
        }

        // Trim trailing blank lines we may have added
        while (cleaned.Count > 0 && string.IsNullOrWhiteSpace(cleaned[^1]))
            cleaned.RemoveAt(cleaned.Count - 1);

        File.WriteAllLines(HostsFile, cleaned);
    }

    static void Restore()
    {
        Console.WriteLine("\nRemoving hosts entries...");
        RemoveOurEntries();
        FlushDns();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("✓ Ad blocking stopped. DNS restored.");
        Console.ResetColor();
        Console.WriteLine("\nPress any key to close...");
        Console.ReadKey();
    }

    static void FlushDns()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "ipconfig",
            Arguments = "/flushdns",
            UseShellExecute = false,
            CreateNoWindow = true
        })?.WaitForExit();
    }

    static bool IsAdmin() =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
}