using System.Collections.Concurrent;
using System.Threading.Channels;

namespace PacketAnalyzer;

public sealed class DPIEngine : IDisposable
{
    private readonly EngineConfig _config;
    private readonly RuleManager _rules = new();
    private readonly DPIStats _stats = new();
    private readonly ConnectionTracker _connections = new();
    private readonly ConcurrentDictionary<AppType, long> _classifications = new();
    private bool _initialized;
    private bool _disposed;

    public DPIEngine(EngineConfig config) => _config = config ?? throw new ArgumentNullException(nameof(config));
    public RuleManager Rules => _rules;
    public bool IsRunning { get; private set; }
    public DPIStats Stats => _stats;

    public IReadOnlyDictionary<string, long> ClassificationSnapshot() =>
        _classifications.ToDictionary(pair => pair.Key.ToString(), pair => pair.Value);

    public IReadOnlyList<FlowSnapshot> FlowSnapshot() => _connections.Snapshot()
        .OrderByDescending(flow => flow.Bytes)
        .Take(100)
        .Select(flow => new FlowSnapshot(
            flow.Tuple.SrcIp,
            flow.Tuple.DstIp,
            flow.Tuple.SrcPort,
            flow.Tuple.DstPort,
            flow.Tuple.Protocol,
            flow.Packets,
            flow.Bytes,
            flow.LastTimestampMicroseconds,
            flow.Domain,
            flow.Application.ToString(),
            flow.Action.ToString()))
        .ToArray();

    public bool Initialize()
    {
        if (_config.LoadBalancers < 1 || _config.WorkersPerBalancer < 1 || _config.QueueCapacity < 1)
            throw new ArgumentOutOfRangeException(nameof(_config), "LB count, worker count and queue capacity must be positive.");
        if (!string.IsNullOrWhiteSpace(_config.RulesFile) && !_rules.LoadRules(_config.RulesFile))
            Console.Error.WriteLine($"Warning: rules file was not loaded: {_config.RulesFile}");
        _initialized = true;
        Console.WriteLine($"[DPI] Initialized: {_config.LoadBalancers} load balancers × {_config.WorkersPerBalancer} workers");
        return true;
    }

    public bool ProcessFile(string inputPath, string outputPath)
    {
        if (!_initialized) Initialize();
        if (!File.Exists(inputPath))
        {
            Console.Error.WriteLine($"Input PCAP does not exist: {inputPath}");
            return false;
        }

        int workerCount = checked(_config.LoadBalancers * _config.WorkersPerBalancer);
        var workerChannels = Enumerable.Range(0, workerCount)
            .Select(_ => Channel.CreateBounded<(RawPacket Raw, ParsedPacket Parsed, uint Id)>(
                new BoundedChannelOptions(_config.QueueCapacity)
                {
                    FullMode = BoundedChannelFullMode.Wait,
                    SingleReader = true,
                    SingleWriter = false
                })).ToArray();

        var output = Channel.CreateBounded<RawPacket>(new BoundedChannelOptions(_config.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

        IsRunning = true;
        try
        {
            using var reader = new PcapReader(inputPath);
            using var writer = new PcapWriter(outputPath, reader.GlobalHeader);

            Task outputTask = Task.Run(async () =>
            {
                await foreach (RawPacket packet in output.Reader.ReadAllAsync())
                    writer.Write(packet);
                writer.Flush();
            });

            Task[] workerTasks = workerChannels.Select(channel => Task.Run(async () =>
            {
                var fastPath = new FastPathProcessor(_rules);
                await foreach (var item in channel.Reader.ReadAllAsync())
                {
                    PacketAction action = fastPath.Process(item.Parsed);
                    _connections.Observe(
                        new FiveTuple(item.Parsed.SrcIp, item.Parsed.DstIp,
                            item.Parsed.SrcPort, item.Parsed.DstPort, item.Parsed.Protocol),
                        item.Raw.Data.Length, item.Raw.Header.TsSec, item.Raw.Header.TsUsec,
                        item.Parsed.Domain, item.Parsed.Application, action);
                    Interlocked.Increment(ref _stats.TotalPackets);
                    Interlocked.Add(ref _stats.TotalBytes, item.Raw.Data.Length);
                    if (item.Parsed.HasTcp) Interlocked.Increment(ref _stats.TcpPackets);
                    if (item.Parsed.HasUdp) Interlocked.Increment(ref _stats.UdpPackets);
                    if (item.Parsed.Application != AppType.Unknown)
                    {
                        Interlocked.Increment(ref _stats.ClassifiedPackets);
                        _classifications.AddOrUpdate(item.Parsed.Application, 1, (_, old) => old + 1);
                    }

                    if (action == PacketAction.Drop)
                    {
                        Interlocked.Increment(ref _stats.DroppedPackets);
                        if (_config.Verbose)
                            Console.WriteLine($"DROP {item.Parsed.SrcIp}:{item.Parsed.SrcPort} -> {item.Parsed.DstIp}:{item.Parsed.DstPort} domain={item.Parsed.Domain ?? "-"} app={item.Parsed.Application}");
                    }
                    else
                    {
                        Interlocked.Increment(ref _stats.ForwardedPackets);
                        await output.Writer.WriteAsync(item.Raw);
                    }
                }
            })).ToArray();

            uint packetId = 0;
            Exception? pipelineError = null;
            try
            {
                while (reader.TryRead(out RawPacket? raw))
                {
                    if (raw == null) continue;
                    if (!PacketParser.TryParse(raw, out ParsedPacket parsed))
                    {
                        Interlocked.Increment(ref _stats.ParseErrors);
                        continue;
                    }

                    var tuple = new FiveTuple(parsed.SrcIp, parsed.DstIp, parsed.SrcPort, parsed.DstPort, parsed.Protocol);
                    int index = LoadBalancerRouter.SelectWorker(tuple, workerCount);
                    workerChannels[index].Writer.WriteAsync((raw, parsed, packetId++)).AsTask().GetAwaiter().GetResult();
                }
            }
            catch (Exception ex)
            {
                pipelineError = ex;
            }
            finally
            {
                foreach (var channel in workerChannels) channel.Writer.TryComplete(pipelineError);
            }

            try { Task.WhenAll(workerTasks).GetAwaiter().GetResult(); }
            catch (Exception ex) { pipelineError ??= ex; }

            output.Writer.TryComplete(pipelineError);
            try { outputTask.GetAwaiter().GetResult(); }
            catch (Exception ex) { pipelineError ??= ex; }

            if (pipelineError != null) throw new InvalidOperationException("Packet pipeline failed.", pipelineError);

            Console.WriteLine(GenerateReport());
            Console.WriteLine(GenerateClassificationReport());
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[DPI] Processing failed: {ex.Message}");
            return false;
        }
        finally
        {
            IsRunning = false;
        }
    }

    public void BlockIP(string ip) => _rules.BlockIP(ip);
    public void UnblockIP(string ip) => _rules.UnblockIP(ip);
    public void BlockApp(AppType app) => _rules.BlockApp(app);
    public void BlockApp(string app)
    {
        if (Enum.TryParse(app.Replace("/", ""), true, out AppType parsed) && parsed != AppType.Unknown)
            _rules.BlockApp(parsed);
        else
            Console.Error.WriteLine($"Unknown app name: {app}");
    }
    public void UnblockApp(AppType app) => _rules.UnblockApp(app);
    public void BlockDomain(string domain) => _rules.BlockDomain(domain);
    public void UnblockDomain(string domain) => _rules.UnblockDomain(domain);
    public bool LoadRules(string path) => _rules.LoadRules(path);
    public bool SaveRules(string path) => _rules.SaveRules(path);

    public string GenerateReport()
    {
        long total = Interlocked.Read(ref _stats.TotalPackets);
        long dropped = Interlocked.Read(ref _stats.DroppedPackets);
        double rate = total == 0 ? 0 : dropped * 100.0 / total;
        return $"""

        ================= DPI ENGINE REPORT =================
        Packets processed : {total}
        Bytes processed   : {Interlocked.Read(ref _stats.TotalBytes)}
        TCP packets       : {Interlocked.Read(ref _stats.TcpPackets)}
        UDP packets       : {Interlocked.Read(ref _stats.UdpPackets)}
        Classified        : {Interlocked.Read(ref _stats.ClassifiedPackets)}
        Forwarded         : {Interlocked.Read(ref _stats.ForwardedPackets)}
        Dropped            : {dropped}
        Parse errors      : {Interlocked.Read(ref _stats.ParseErrors)}
        Active flows      : {_connections.FlowCount}
        Drop rate         : {rate:F2}%
        ======================================================
        """;
    }

    public string GenerateClassificationReport()
    {
        var lines = _classifications.OrderByDescending(x => x.Value)
            .Select(x => $"  {x.Key,-12} {x.Value,8}");
        return "Application classification:\n" +
               (string.Join(Environment.NewLine, lines) is { Length: > 0 } s ? s : "  No applications classified.");
    }

    public void PrintStatus() => Console.WriteLine(GenerateReport());

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }
}
