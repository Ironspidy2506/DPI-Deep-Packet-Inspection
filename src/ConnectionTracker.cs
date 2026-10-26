using System.Collections.Concurrent;

namespace PacketAnalyzer;

/// <summary>Thread-safe per-five-tuple counters for flows observed in a PCAP.</summary>
public sealed class ConnectionTracker
{
    private sealed class FlowState
    {
        public long Packets;
        public long Bytes;
        public long LastTimestampMicroseconds;
        public string Domain = "";
        public AppType Application = AppType.Unknown;
        public PacketAction Action = PacketAction.Forward;
    }

    private readonly ConcurrentDictionary<FiveTuple, FlowState> _flows = new();

    public void Observe(FiveTuple tuple, int byteCount, uint seconds, uint microseconds,
        string? domain, AppType application, PacketAction action)
    {
        var state = _flows.GetOrAdd(tuple, _ => new FlowState());
        Interlocked.Increment(ref state.Packets);
        Interlocked.Add(ref state.Bytes, byteCount);
        Interlocked.Exchange(ref state.LastTimestampMicroseconds,
            (long)seconds * 1_000_000L + microseconds);
        if (!string.IsNullOrWhiteSpace(domain)) state.Domain = domain;
        if (application != AppType.Unknown) state.Application = application;
        if (action == PacketAction.Drop || state.Action == PacketAction.Drop)
            state.Action = PacketAction.Drop;
    }

    public int FlowCount => _flows.Count;

    public IEnumerable<(FiveTuple Tuple, long Packets, long Bytes, long LastTimestampMicroseconds, string Domain, AppType Application, PacketAction Action)> Snapshot() =>
        _flows.Select(pair => (
            pair.Key,
            Interlocked.Read(ref pair.Value.Packets),
            Interlocked.Read(ref pair.Value.Bytes),
            Interlocked.Read(ref pair.Value.LastTimestampMicroseconds),
            pair.Value.Domain,
            pair.Value.Application,
            pair.Value.Action));
}
