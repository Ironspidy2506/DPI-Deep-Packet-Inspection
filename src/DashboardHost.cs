using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace PacketAnalyzer;

public static class DashboardHost
{
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: dotnet run -- --dashboard <input.pcap> <output.pcap> [port]");
            return 1;
        }

        string inputPath = args[0];
        string outputPath = args[1];
        int port = args.Length > 2 && int.TryParse(args[2], out int parsedPort) ? parsedPort : 5180;
        var runState = new DashboardRunState();
        runState.Initialize();

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        builder.Services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase);
        var app = builder.Build();

        app.MapGet("/api/status", () => DashboardSnapshot.From(runState.Engine));
        app.MapGet("/api/flows", (HttpResponse response) =>
        {
            response.Headers.CacheControl = "no-store";
            return Results.Json(runState.Engine.FlowSnapshot());
        });
        app.MapGet("/api/classifications", () => runState.Engine.ClassificationSnapshot());
        app.MapPost("/api/runs", (RunRequest request) =>
        {
            if (string.IsNullOrWhiteSpace(request.InputPath) || string.IsNullOrWhiteSpace(request.OutputPath))
                return Results.BadRequest(new { error = "InputPath and OutputPath are required." });
            if (!File.Exists(request.InputPath))
                return Results.BadRequest(new { error = $"Input PCAP was not found: {request.InputPath}" });
            string[] blockApps = request.BlockApps.Where(app => !string.IsNullOrWhiteSpace(app)).ToArray();
            if (blockApps.Length == 0 && !string.IsNullOrWhiteSpace(request.BlockApp))
                blockApps = [request.BlockApp];
            if (!runState.Start(request.InputPath, request.OutputPath, blockApps))
                return Results.Conflict(new { error = "A capture is already running." });
            return Results.Accepted("/api/status", new { message = "Capture started.", blockedApps = blockApps });
        });
        app.MapGet("/api/stream", async (HttpResponse response, CancellationToken cancellationToken) =>
        {
            response.Headers.ContentType = "text/event-stream";
            response.Headers.CacheControl = "no-cache";
            while (!cancellationToken.IsCancellationRequested)
            {
                string payload = JsonSerializer.Serialize(
                    DashboardSnapshot.From(runState.Engine),
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
                await response.WriteAsync($"event: snapshot\ndata: {payload}\n\n", cancellationToken);
                await response.Body.FlushAsync(cancellationToken);
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            }
        });

        Console.WriteLine($"[Dashboard] http://127.0.0.1:{port}");
        await app.RunAsync();
        return 0;
    }
}

public sealed record DashboardSnapshot(
    bool IsRunning,
    long TotalPackets,
    long TotalBytes,
    long TcpPackets,
    long UdpPackets,
    long ForwardedPackets,
    long DroppedPackets,
    long ParseErrors,
    long ClassifiedPackets,
    int ActiveFlows,
    IReadOnlyDictionary<string, long> Classifications,
    IReadOnlyList<string> BlockedApps,
    IReadOnlyList<FlowSnapshot> Flows)
{
    public static DashboardSnapshot From(DPIEngine engine) => new(
        engine.IsRunning,
        Interlocked.Read(ref engine.Stats.TotalPackets),
        Interlocked.Read(ref engine.Stats.TotalBytes),
        Interlocked.Read(ref engine.Stats.TcpPackets),
        Interlocked.Read(ref engine.Stats.UdpPackets),
        Interlocked.Read(ref engine.Stats.ForwardedPackets),
        Interlocked.Read(ref engine.Stats.DroppedPackets),
        Interlocked.Read(ref engine.Stats.ParseErrors),
        Interlocked.Read(ref engine.Stats.ClassifiedPackets),
        engine.FlowSnapshot().Count,
        engine.ClassificationSnapshot(),
        engine.Rules.BlockedAppNames(),
        engine.FlowSnapshot());
}

public sealed class RunRequest
{
    public string InputPath { get; set; } = "";
    public string OutputPath { get; set; } = "";
    public string[] BlockApps { get; set; } = [];
    public string? BlockApp { get; set; }
}

public sealed class DashboardRunState
{
    private readonly object _gate = new();
    private DPIEngine? _engine;

    public DPIEngine Engine => _engine ?? throw new InvalidOperationException("No capture has been started.");

    public void Initialize()
    {
        lock (_gate)
        {
            _engine ??= CreateEngine([]);
        }
    }

    public bool Start(string inputPath, string outputPath, IEnumerable<string> blockApps)
    {
        lock (_gate)
        {
            if (_engine?.IsRunning == true) return false;

            var engine = CreateEngine(blockApps);
            _engine = engine;
            _ = Task.Run(() => engine.ProcessFile(inputPath, outputPath));
            return true;
        }
    }

    private static DPIEngine CreateEngine(IEnumerable<string> blockApps)
    {
        var engine = new DPIEngine(new EngineConfig());
        engine.Initialize();
        foreach (string blockApp in blockApps) engine.BlockApp(blockApp);
        return engine;
    }
}