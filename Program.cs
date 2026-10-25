using PacketAnalyzer;

static void Usage()
{
    Console.WriteLine("""
    DPI Engine (.NET 8) - PCAP packet inspection and filtering

    Usage:
      dotnet run -- <input.pcap> <output.pcap> [options]

    Options:
      --block-ip <ip>       Block packets involving this IPv4 address (source or destination)
      --block-app <app>     Block an application, e.g. YouTube, Facebook, GitHub
      --block-domain <host> Block a domain; wildcard supported: *.example.com
      --rules <file>        Load rules from JSON or text file
      --save-rules <file>   Save active rules as JSON
      --lbs <n>             Number of load-balancer partitions (default: 2)
      --fps <n>             Workers per partition (default: 2)
      --queue-size <n>      Capacity of each bounded queue (default: 10000)
      --verbose             Log each dropped packet
      --help                Show this help

    Examples:
      dotnet run -- test_dpi.pcap filtered.pcap
      dotnet run -- test_dpi.pcap filtered.pcap --block-app YouTube
      dotnet run -- test_dpi.pcap filtered.pcap --block-domain *.tiktok.com
      dotnet run -- test_dpi.pcap filtered.pcap --rules rules.json
    """);
}

if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
{
    Usage();
    return args.Length == 0 ? 1 : 0;
}

if (args.Length < 2)
{
    Usage();
    return 1;
}

string input = args[0];
string output = args[1];
var config = new EngineConfig();
var blockIps = new List<string>();
var blockApps = new List<string>();
var blockDomains = new List<string>();
string? saveRules = null;

for (int i = 2; i < args.Length; i++)
{
    string NextValue()
    {
        if (i + 1 >= args.Length) throw new ArgumentException($"Missing value after {args[i]}");
        return args[++i];
    }

    switch (args[i])
    {
        case "--block-ip": blockIps.Add(NextValue()); break;
        case "--block-app": blockApps.Add(NextValue()); break;
        case "--block-domain": blockDomains.Add(NextValue()); break;
        case "--rules": config.RulesFile = NextValue(); break;
        case "--save-rules": saveRules = NextValue(); break;
        case "--lbs": config.LoadBalancers = int.Parse(NextValue()); break;
        case "--fps": config.WorkersPerBalancer = int.Parse(NextValue()); break;
        case "--queue-size": config.QueueCapacity = int.Parse(NextValue()); break;
        case "--verbose": config.Verbose = true; break;
        default: throw new ArgumentException($"Unknown option: {args[i]}");
    }
}

try
{
    using var engine = new DPIEngine(config);
    engine.Initialize();

    foreach (string ip in blockIps) engine.BlockIP(ip);
    foreach (string app in blockApps) engine.BlockApp(app);
    foreach (string domain in blockDomains) engine.BlockDomain(domain);

    if (!engine.ProcessFile(input, output)) return 1;
    if (saveRules != null && !engine.SaveRules(saveRules))
        Console.Error.WriteLine($"Warning: failed to save rules to {saveRules}");

    Console.WriteLine($"Processing complete. Output written to: {output}");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}
