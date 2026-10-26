using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace PacketAnalyzer;

public sealed class RuleManager
{
    private readonly ConcurrentDictionary<string, byte> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<AppType, byte> _blockedApps = new();
    private readonly ConcurrentDictionary<string, byte> _blockedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _domainPatterns = new(StringComparer.OrdinalIgnoreCase);

    public void BlockIP(string ip) { ValidateIp(ip); _blockedIps[ip] = 0; }
    public void UnblockIP(string ip) => _blockedIps.TryRemove(ip, out _);
    public void BlockApp(AppType app) { if (app != AppType.Unknown) _blockedApps[app] = 0; }
    public void UnblockApp(AppType app) => _blockedApps.TryRemove(app, out _);
    public void BlockDomain(string domain)
    {
        string d = NormalizeDomain(domain);
        if (d.Contains('*')) _domainPatterns[d] = 0;
        else _blockedDomains[d] = 0;
    }
    public void UnblockDomain(string domain)
    {
        string d = NormalizeDomain(domain);
        _blockedDomains.TryRemove(d, out _);
        _domainPatterns.TryRemove(d, out _);
    }

    public bool IsBlocked(ParsedPacket p)
    {
        if (_blockedIps.ContainsKey(p.SrcIp) || _blockedIps.ContainsKey(p.DstIp)) return true;
        if (_blockedApps.ContainsKey(p.Application)) return true;
        if (string.IsNullOrWhiteSpace(p.Domain)) return false;

        string domain = NormalizeDomain(p.Domain);
        if (_blockedDomains.ContainsKey(domain)) return true;
        foreach (string pattern in _domainPatterns.Keys)
        {
            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                string suffix = pattern[1..];
                if (domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ||
                    domain.Equals(pattern[2..], StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (domain.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public bool LoadRules(string path)
    {
        if (!File.Exists(path)) return false;
        try
        {
            string text = File.ReadAllText(path);
            if (Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                var rules = JsonSerializer.Deserialize<RuleFile>(text,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (rules == null) return false;
                foreach (var ip in rules.BlockIps ?? []) BlockIP(ip);
                foreach (var app in rules.BlockApps ?? [])
                    if (Enum.TryParse<AppType>(app, true, out var parsed)) BlockApp(parsed);
                foreach (var domain in rules.BlockDomains ?? []) BlockDomain(domain);
                return true;
            }

            foreach (string raw in File.ReadLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                string[] parts = line.Split(new[] { ' ', '=', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2) continue;
                switch (parts[0].ToLowerInvariant())
                {
                    case "ip": case "block-ip": BlockIP(parts[1].Trim()); break;
                    case "app": case "block-app":
                        if (Enum.TryParse<AppType>(parts[1].Trim(), true, out var app)) BlockApp(app);
                        break;
                    case "domain": case "block-domain": BlockDomain(parts[1].Trim()); break;
                }
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Could not load rules: {ex.Message}");
            return false;
        }
    }

    public bool SaveRules(string path)
    {
        try
        {
            var rules = new RuleFile
            {
                BlockIps = _blockedIps.Keys.Order().ToList(),
                BlockApps = _blockedApps.Keys.Select(x => x.ToString()).Order().ToList(),
                BlockDomains = _blockedDomains.Keys.Concat(_domainPatterns.Keys).Order().ToList()
            };
            File.WriteAllText(path, JsonSerializer.Serialize(rules,
                new JsonSerializerOptions { WriteIndented = true }));
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Could not save rules: {ex.Message}");
            return false;
        }
    }

    public object GetStats() => new
    {
        BlockedIps = _blockedIps.Count,
        BlockedApps = _blockedApps.Count,
        BlockedDomains = _blockedDomains.Count + _domainPatterns.Count
    };

    public IReadOnlyList<string> BlockedAppNames() =>
        _blockedApps.Keys.OrderBy(app => app.ToString()).Select(app => app.ToString()).ToArray();

    private static string NormalizeDomain(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();
    private static void ValidateIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out _)) throw new ArgumentException($"Invalid IP address: {ip}");
    }

    private sealed class RuleFile
    {
        public List<string>? BlockIps { get; set; }
        public List<string>? BlockApps { get; set; }
        public List<string>? BlockDomains { get; set; }
    }
}
